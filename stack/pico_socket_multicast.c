#include "pico_config.h"
#include "pico_stack.h"
#include "pico_socket.h"
#include "pico_socket_multicast.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_udp.h"
#include "pico_dns_client.h"

#ifdef PICO_SUPPORT_MCAST
# define so_mcast_dbg(...) do {} while(0) /* ip_mcast_dbg in pico_ipv4.c */
/* #define so_mcast_dbg dbg */

/*                       socket
 *                         |
 *                    MCASTListen
 *                    |    |     |
 *         ------------    |     ------------
 *         |               |                |
 *   MCASTSources    MCASTSources     MCASTSources
 *   |  |  |  |      |  |  |  |       |  |  |  |
 *   S  S  S  S      S  S  S  S       S  S  S  S
 *
 *   MCASTListen: RBTree(mcast_link, mcast_group)
 *   MCASTSources: RBTree(source)
 */
struct pico_mcast_listen
{
    uint8_t filter_mode;
    union pico_address mcast_link;
    union pico_address mcast_group;
    struct pico_tree MCASTSources;
    uint16_t proto;
};
union mcast_link_u {
    struct pico_ipv4_link *ipv4;
    struct pico_ipv6_link *ipv6;
};
static int mcast_listen_link_cmp(struct pico_mcast_listen *a, struct pico_mcast_listen *b)
{

    if (a->proto < b->proto)
        return -1;

    if (a->proto > b->proto)
        return 1;

    return pico_address_compare(&a->mcast_link, &b->mcast_link, a->proto);
}

static int mcast_listen_grp_cmp(struct pico_mcast_listen *a, struct pico_mcast_listen *b)
{
    if (a->mcast_group.ip4.addr < b->mcast_group.ip4.addr)
        return -1;

    if (a->mcast_group.ip4.addr > b->mcast_group.ip4.addr)
        return 1;

    return mcast_listen_link_cmp(a, b);
}

static int mcast_listen_cmp(void *ka, void *kb)
{
    struct pico_mcast_listen *a = ka, *b = kb;
    if (a->proto < b->proto)
        return -1;

    if (a->proto > b->proto)
        return 1;

    return mcast_listen_grp_cmp(a, b);
}

static int mcast_sources_cmp(void *ka, void *kb)
{
    struct pico_address_t *a = ka, *b = kb;
    switch(a->type) {
    case PICO_PROTO_IPV4:
        if (a->addr.ip4.addr < b->addr.ip4.addr)
            return -1;

        if (a->addr.ip4.addr > b->addr.ip4.addr)
            return 1;
        break;
    case PICO_PROTO_IPV6:
        return pico_ipv6_compare(a->addr.ip6.addr, b->addr.ip6.addr);
    }
    return 0;
}

static int mcast_socket_cmp(void *ka, void *kb)
{
    struct pico_socket *a = ka, *b = kb;
    if (a < b)
        return -1;

    if (a > b)
        return 1;

    return 0;
}

/* gather all multicast sockets to hasten filter aggregation */
PICO_TREE_DECLARE(MCASTSockets, mcast_socket_cmp);

static int mcast_filter_cmp(void *ka, void *kb)
{
    struct pico_address_t *a = ka, *b = kb;
    switch(a->type) {
    case PICO_PROTO_IPV4:
        if (a->addr.ip4.addr < b->addr.ip4.addr)
            return -1;

        if (a->addr.ip4.addr > b->addr.ip4.addr)
            return 1;
        break;
    case PICO_PROTO_IPV6:
        return pico_ipv6_compare(a->addr.ip6.addr, b->addr.ip6.addr);
    }
    return 0;
}
/* gather sources to be filtered */
PICO_TREE_DECLARE(MCASTFilter, mcast_filter_cmp);

static struct pico_mcast_listen *listen_find(struct pico_socket *s, union pico_address *lnk, union pico_address *grp)
{
    struct pico_mcast_listen ltest = {
        0
    };
    memcpy(&ltest.mcast_link, lnk, sizeof(union pico_address));
    memcpy(&ltest.mcast_group, grp, sizeof(union pico_address));
    return pico_tree_findKey(s->MCASTListen, &ltest);
}

static uint8_t pico_mcast_filter_excl_excl(struct pico_mcast_listen *listen)
{
    /* filter = intersection of EXCLUDEs */
    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */
    /* remove from the interface EXCLUDE filter any source not in the socket EXCLUDE filter */
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    union pico_address *source = NULL;
    pico_tree_foreach_safe(index, &MCASTFilter, _tmp)
    {
        source = pico_tree_findKey(&listen->MCASTSources, index->keyValue);
        if (!source)
            pico_tree_delete(&MCASTFilter, index->keyValue);
    }
    return PICO_IP_MULTICAST_EXCLUDE;
}

static uint8_t pico_mcast_filter_excl_incl(struct pico_mcast_listen *listen)
{
    /* filter = EXCLUDE - INCLUDE */
    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */
    /* remove from the interface EXCLUDE filter any source in the socket INCLUDE filter */
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    union pico_address *source = NULL;
    pico_tree_foreach_safe(index, &listen->MCASTSources, _tmp)
    {
        source = pico_tree_findKey(&MCASTFilter, index->keyValue);
        if (source)
            pico_tree_delete(&MCASTFilter, source);
    }
    return PICO_IP_MULTICAST_EXCLUDE;
}

static uint8_t pico_mcast_filter_incl_excl(struct pico_mcast_listen *listen)
{
    /* filter = EXCLUDE - INCLUDE */
    /* delete from the interface INCLUDE filter any source NOT in the socket EXCLUDE filter */
    struct pico_tree_node *index = NULL, *_tmp = NULL, *index2 = NULL, *_tmp2 = NULL;
    union pico_address *source = NULL;
    pico_tree_foreach_safe(index2, &MCASTFilter, _tmp2)
    {
        source = pico_tree_findKey(&listen->MCASTSources, index2->keyValue);
        if (!source)
            pico_tree_delete(&MCASTFilter, index2->keyValue);
    }
    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */

    /* add to the interface EXCLUDE filter any socket source NOT in the former interface INCLUDE filter */
    pico_tree_foreach_safe(index, &listen->MCASTSources, _tmp)
    {
        source = pico_tree_insert(&MCASTFilter, index->keyValue);
        if (source)
            pico_tree_delete(&MCASTFilter, source);
    }
    return PICO_IP_MULTICAST_EXCLUDE;
}

static uint8_t pico_mcast_filter_incl_incl(struct pico_mcast_listen *listen)
{
    /* filter = summation of INCLUDEs */
    /* mode stays INCLUDE, add all sources to filter */
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    union pico_address *source = NULL;
    pico_tree_foreach_safe(index, &listen->MCASTSources, _tmp)
    {
        source = index->keyValue;
        pico_tree_insert(&MCASTFilter, source);
    }
    return PICO_IP_MULTICAST_INCLUDE;
}

struct pico_mcast_filter_aggregation
{
    uint8_t (*call)(struct pico_mcast_listen *);
};

static const struct pico_mcast_filter_aggregation mcast_filter_aggr_call[2][2] =
{
    {
        /* EXCL + EXCL */ {.call = pico_mcast_filter_excl_excl},
        /* EXCL + INCL */ {.call = pico_mcast_filter_excl_incl}
    },

    {
        /* INCL + EXCL */ {.call = pico_mcast_filter_incl_excl},
        /* INCL + INCL */ {.call = pico_mcast_filter_incl_incl}
    }
};

static int mcast_aggr_validate(uint8_t fm, struct pico_mcast_listen *l)
{
    if (!l)
        return -1;

    if (fm > 1)
        return -1;

    if (l->filter_mode > 1)
        return -1;

    return 0;
}


/* MCASTFilter will be empty if no socket is listening on mcast_group on mcast_link anymore */
static int pico_socket_aggregate_mcastfilters(union pico_address *mcast_link, union pico_address *mcast_group)
{
    uint8_t filter_mode = PICO_IP_MULTICAST_INCLUDE;
    struct pico_mcast_listen *listen = NULL;
    struct pico_socket *mcast_sock = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;


    /* cleanup old filter */
    pico_tree_foreach_safe(index, &MCASTFilter, _tmp)
    {
        pico_tree_delete(&MCASTFilter, index->keyValue);
    }

    /* construct new filter */
    pico_tree_foreach_safe(index, &MCASTSockets, _tmp)
    {
        mcast_sock = index->keyValue;
        listen = listen_find(mcast_sock, mcast_link, mcast_group);
        if (listen) {
            if (mcast_aggr_validate(filter_mode, listen) < 0) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }

            if (mcast_filter_aggr_call[filter_mode][listen->filter_mode].call) {
                filter_mode = mcast_filter_aggr_call[filter_mode][listen->filter_mode].call(listen);
                if (filter_mode > 1)
                    return -1;
            }
        }
    }
    return filter_mode;
}

static int pico_socket_mcast_filter_include(struct pico_mcast_listen *listen, struct pico_address_t *src)
{
    struct pico_tree_node *index = NULL;
    char *addr = NULL;
    pico_tree_foreach(index, &listen->MCASTSources)
    {
        switch(src->type) {
        case PICO_PROTO_IPV4: {
            if(!addr) {
                addr = PICO_ZALLOC(PICO_DNS_IPV4_ADDR_LEN);
                pico_ipv4_to_string(addr , src->addr.ip4.addr);
            }
            if (src->addr.ip4.addr == ((union pico_address *)index->keyValue)->ip4.addr) {
                so_mcast_dbg("MCAST: IP %s in included socket source list\n", addr);
                PICO_FREE(addr);
                return 0;
             } 
            break;
        }       
        case PICO_PROTO_IPV6: {
            if(!addr) {
                addr = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN);
                pico_ipv6_to_string(addr , src->addr.ip6.addr);
            }
            if (pico_ipv6_compare(src->addr.ip6.addr, ((union pico_address *)index->keyValue)->ip6.addr)) {
                so_mcast_dbg("MCAST: IP %s in included socket source list\n", addr);
                PICO_FREE(addr);
                return 0;
             }  
            break;
        }
        } /*switch*/
    }
    so_mcast_dbg("MCAST: IP %s NOT in included socket source list\n", addr);
    PICO_FREE(addr);
    return -1;

}

static int pico_socket_mcast_filter_exclude(struct pico_mcast_listen *listen, struct pico_address_t *src)
{
    struct pico_tree_node *index = NULL;
    char *addr = NULL;
    pico_tree_foreach(index, &listen->MCASTSources)
    {
        switch(src->type) {
        case PICO_PROTO_IPV4: {
            if(!addr) {
                addr = PICO_ZALLOC(PICO_DNS_IPV4_ADDR_LEN);
                pico_ipv4_to_string(addr , src->addr.ip4.addr);
            }
            if (src->addr.ip4.addr == ((union pico_address *)index->keyValue)->ip4.addr) {
                so_mcast_dbg("MCAST: IP %s in excluded socket source list\n", addr);
                PICO_FREE(addr);
                return 0;
             } 
            break;
        }       
        case PICO_PROTO_IPV6: {
            if(!addr) {
                addr = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN);
                pico_ipv6_to_string(addr , src->addr.ip6.addr);
            }
            if (pico_ipv6_compare(src->addr.ip6.addr, ((union pico_address *)index->keyValue)->ip6.addr)) {
                so_mcast_dbg("MCAST: IP %s in excluded socket source list\n", addr);
                PICO_FREE(addr);
                return 0;
             }  
            break;
        }
        } /*switch*/
    }
    so_mcast_dbg("MCAST: IP %s NOT in excluded socket source list\n", addr);
    PICO_FREE(addr);
    return 0;
}

static int pico_socket_mcast_source_filtering(struct pico_mcast_listen *listen, struct pico_address_t *src)
{
    /* perform source filtering */
    if (listen->filter_mode == PICO_IP_MULTICAST_INCLUDE)
        return pico_socket_mcast_filter_include(listen, src);

    if (listen->filter_mode == PICO_IP_MULTICAST_EXCLUDE)
        return pico_socket_mcast_filter_exclude(listen, src);

    return -1;
}

static void *pico_socket_mcast_filter_link_get(struct pico_socket *s)
{
    /* check if no multicast enabled on socket */
    if (!s->MCASTListen)
        return NULL;
    switch(s->local_addr.type) {
    case PICO_PROTO_IPV4: {
        if (!s->local_addr.addr.ip4.addr)
            return pico_ipv4_get_default_mcastlink();
        return pico_ipv4_link_get(&s->local_addr.addr.ip4);
    }
    break;
    case PICO_PROTO_IPV6: {
        /* if (!s->local_addr.addr.ip6.addr)
            return pico_ipv6_get_default_mcastlink();*/
        return pico_ipv6_link_get(&s->local_addr.addr.ip6);
    }
    break;
    } /*switch*/
    return NULL;
}

int pico_socket_mcast_filter(struct pico_socket *s, union pico_address *mcast_group, union pico_address *src)
{
    struct pico_ipv4_link *mcast_link = NULL;
    struct pico_ipv6_link *mcast_link_ipv6 = NULL;
    struct pico_mcast_listen *listen = NULL;
    union pico_address *p;

    switch(s->local_addr.type) {
    case PICO_PROTO_IPV4: {
        mcast_link = pico_socket_mcast_filter_link_get(s);
        if (!mcast_link)
            return -1;
        p = &mcast_link->address;
    }
    case PICO_PROTO_IPV6: {
        mcast_link_ipv6 = pico_socket_mcast_filter_link_get(s);
        if (!mcast_link_ipv6)
            return -1;
        p = &mcast_link_ipv6->address;
    }
    }

    listen = listen_find(s, p , mcast_group);
    if (!listen)
        return -1;

    return pico_socket_mcast_source_filtering(listen, src);
}

static void *get_mcast_link(struct pico_address_t *a)
{

    switch(a->type) {
    case PICO_PROTO_IPV4: {
        if (!a->addr.ip4.addr)
           return pico_ipv4_get_default_mcastlink();
        return pico_ipv4_link_get(&a->addr.ip4);
    }
    break;
    case PICO_PROTO_IPV6: {
        /*if (!a->addr.ip6.addr)
           return pico_ipv6_get_default_mcastlink();
        */
        return pico_ipv6_link_get(&a->addr.ip6);
    }
    break;
    } /*switch*/
    return NULL;
}

static int pico_socket_setoption_pre_validation(struct pico_ip_mreq *mreq)
{
    if (!mreq)
        return -1;

    if (!mreq->mcast_group_addr.addr)
        return -1;

    return 0;
}

static void *pico_socket_setoption_validate_mreq(struct pico_mreq_t *mreq)
{
    
    if (pico_socket_setoption_pre_validation(mreq) < 0)
        return NULL;
    switch(mreq->type) {
    case PICO_PROTO_IPV4: {
        if (pico_ipv4_is_unicast(mreq->mreq.ipv4.mcast_group_addr.addr))
            return NULL;
        return get_mcast_link((union pico_address *)&mreq->mreq.ipv4.mcast_link_addr);
    }
    case PICO_PROTO_IPV6: {
        if (pico_ipv6_is_unicast(mreq->mreq.ipv6.mcast_group_addr.addr))
            return NULL;
        return get_mcast_link((union pico_address *)&mreq->mreq.ipv6.mcast_link_addr);
    }
    } /*switch*/
    return NULL;
}

static int pico_socket_setoption_pre_validation_s(struct pico_mreq_source_t *mreq)
{
    if (!mreq)
        return -1;
    switch(mreq->type) {
    case PICO_PROTO_IPV4: {
        if (!mreq->mreq_source.ipv4.mcast_group_addr.addr)
            return -1;
    }
    break;
    case PICO_PROTO_IPV6: {
        if (!mreq->mreq_source.ipv6.mcast_group_addr.addr)
            return -1;
    }
    break;
    }/*switch*/

    return 0;
}

static void *pico_socket_setoption_validate_s_mreq(struct pico_mreq_source_t *mreq)
{
    if (pico_socket_setoption_pre_validation_s(mreq) < 0)
        return NULL;
    switch(mreq->type) {
    case PICO_PROTO_IPV4: {
        if (pico_ipv4_is_unicast(mreq->mreq_source.ipv4.mcast_group_addr.addr))
            return NULL;

        if (!pico_ipv4_is_unicast(mreq->mreq_source.ipv4.mcast_source_addr.addr))
            return NULL;
        return get_mcast_link((union pico_address *)&mreq->mreq_source.ipv4.mcast_link_addr);
    }
    break;
    case PICO_PROTO_IPV6: {
        if (pico_ipv6_is_unicast(mreq->mreq_source.ipv6.mcast_group_addr.addr))
            return NULL;

        if (!pico_ipv6_is_unicast(mreq->mreq_source.ipv6.mcast_source_addr.addr))
            return NULL;
        return get_mcast_link((union pico_address *)&mreq->mreq_source.ipv6.mcast_link_addr);
    }
    break;
    }/*switch*/   
    return NULL;
}


static void *setop_multicast_link_search(void *value, int bysource)
{

    struct pico_mreq_t *mreq = NULL;

    union mcast_link_u *mcast_link = NULL;
    struct pico_ip_mreq_source *mreq_src;
    
    if (!bysource) {
        mreq = (struct pico_mreq_t *) value;
        mcast_link = pico_socket_setoption_validate_mreq(mreq);
        if (!mcast_link)
            return NULL;

    } else {
        mreq_src = (struct pico_mreq_source_t *) value;
        if (!mreq_src)
            return NULL;

        mcast_link = pico_socket_setoption_validate_s_mreq(mreq_src);
        if (!mcast_link)
            return NULL;
    }
    if (mreq->type == PICO_PROTO_IPV4 && !mreq->mreq.ipv4.mcast_link_addr.addr)
        mreq->mreq.ipv4.mcast_link_addr.addr = mcast_link->ipv4->address.addr;
    if (mreq->type == PICO_PROTO_IPV6 && !mreq->mreq.ipv6.mcast_link_addr.addr)
        memcpy(mreq->mreq.ipv6.mcast_link_addr.addr,mcast_link->ipv6->address.addr, sizeof(union pico_address));;

    return mcast_link;
}

static int setop_verify_listen_tree(struct pico_socket *s, int alloc)
{
    if(!alloc)
        return -1;

    s->MCASTListen = PICO_ZALLOC(sizeof(struct pico_tree));
    if (!s->MCASTListen) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    s->MCASTListen->root = &LEAF;
    s->MCASTListen->compare = mcast_listen_cmp;
    return 0;
}


static void *setopt_multicast_check(struct pico_socket *s, void *value, int alloc, int bysource)
{
    union mcast_link_u *mcast_link = NULL;

    if (!value) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    mcast_link = (union mcast_link_u *) setop_multicast_link_search(value, bysource);

    if (!mcast_link) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (!s->MCASTListen) { /* No RBTree allocated yet */
        if (setop_verify_listen_tree(s, alloc) < 0)
            return NULL;
    }

    return mcast_link;
}


void pico_multicast_delete(struct pico_socket *s)
{
    int filter_mode;
    struct pico_tree_node *index = NULL, *_tmp = NULL, *index2 = NULL, *_tmp2 = NULL;
    struct pico_mcast_listen *listen = NULL;
    union pico_address *source = NULL;
    if (s->MCASTListen) {
        pico_tree_delete(&MCASTSockets, s);
        pico_tree_foreach_safe(index, s->MCASTListen, _tmp)
        {
            listen = index->keyValue;
            pico_tree_foreach_safe(index2, &listen->MCASTSources, _tmp2)
            {
                source = index->keyValue;
                pico_tree_delete(&listen->MCASTSources, source);
                PICO_FREE(source);
            }
            filter_mode = pico_socket_aggregate_mcastfilters((union pico_address *)&listen->mcast_link, (union pico_address *)&listen->mcast_group);
            if (filter_mode >= 0)
                pico_ipv4_mcast_leave(&listen->mcast_link.ip4, &listen->mcast_group.ip4, 1, (uint8_t)filter_mode, &MCASTFilter);

            pico_tree_delete(s->MCASTListen, listen);
            PICO_FREE(listen);
        }
        PICO_FREE(s->MCASTListen);
    }
}


int pico_getsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    switch(option) {
    case PICO_IP_MULTICAST_IF:
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;

    case PICO_IP_MULTICAST_TTL:
        if (s->proto->proto_number == PICO_PROTO_UDP) {
            pico_udp_get_mc_ttl(s, (uint8_t *) value);
        } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        break;

    case PICO_IP_MULTICAST_LOOP:
        if (s->proto->proto_number == PICO_PROTO_UDP) {
            *(uint8_t *)value = (uint8_t)PICO_SOCKET_GETOPT(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}

static int mcast_so_loop(struct pico_socket *s, void *value)
{
    uint8_t val = (*(uint8_t *)value);
    if (val == 0u) {
        PICO_SOCKET_SETOPT_DIS(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        return 0;
    } else if (val == 1u) {
        PICO_SOCKET_SETOPT_EN(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}

static int mcast_so_addm(struct pico_socket *s, void *value)
{
    int filter_mode;
    struct pico_mcast_listen *listen;
    struct pico_mreq_t *mreq = (struct pico_ip_mreq *)value;
    union pico_address *mcast_link_addr, *mcast_group_addr;
    union mcast_link_u *mcast_link = setopt_multicast_check(s, value, 1, 0);
    if (!mcast_link)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }

    listen = listen_find(s, mcast_link_addr, mcast_group_addr);
    if (listen) {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        } else {
            so_mcast_dbg("pico_socket_setoption: ERROR duplicate PICO_IP_ADD_MEMBERSHIP\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    } else {
        listen = PICO_ZALLOC(sizeof(struct pico_mcast_listen));
        if (!listen) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        listen->filter_mode = PICO_IP_MULTICAST_EXCLUDE;
        if(mreq->type == PICO_PROTO_IPV4) {
            listen->mcast_link.ip4 = mreq->mreq.ipv4.mcast_link_addr;
            listen->mcast_group.ip4 = mreq->mreq.ipv4.mcast_group_addr;        
        } else {
            memcpy(&listen->mcast_link.ip6, &mreq->mreq.ipv6.mcast_link_addr, sizeof(struct pico_ip6));
            memcpy(&listen->mcast_group.ip6, &mreq->mreq.ipv6.mcast_group_addr, sizeof(struct pico_ip6));
        }
        listen->MCASTSources.root = &LEAF;
        listen->MCASTSources.compare = mcast_sources_cmp;
        listen->proto = s->net->proto_number;
        pico_tree_insert(s->MCASTListen, listen);
    }

    pico_tree_insert(&MCASTSockets, s);

    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 

    filter_mode = pico_socket_aggregate_mcastfilters( mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    so_mcast_dbg("PICO_IP_ADD_MEMBERSHIP - success, added %p\n", s);
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq.ipv4.mcast_link_addr, &mreq->mreq.ipv4.mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq.ipv6.mcast_link_addr, &mreq->mreq.ipv6.mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;
}

static int mcast_so_dropm(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_mcast_listen *listen;
    struct pico_mreq_t *mreq = (union pico_mreq *)value;
    union pico_address *source = NULL, *mcast_link_addr, *mcast_group_addr;
    struct pico_tree_node *index, *_tmp;
    union mcast_link_u *mcast_link = setopt_multicast_check(s, value, 0, 0);
    if (!mcast_link)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }


    listen = listen_find(s, mcast_link_addr, mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_DROP_MEMBERSHIP before PICO_IP_ADD_MEMBERSHIP/SOURCE_MEMBERSHIP\n");
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    } else {
        pico_tree_foreach_safe(index, &listen->MCASTSources, _tmp)
        {
            source = index->keyValue;
            pico_tree_delete(&listen->MCASTSources, source);
            PICO_FREE(source);
        }
        pico_tree_delete(s->MCASTListen, listen);
        PICO_FREE(listen);
        if (pico_tree_empty(s->MCASTListen)) {
            PICO_FREE(s->MCASTListen);
            s->MCASTListen = NULL;
            pico_tree_delete(&MCASTSockets, s);
        }
    }
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 

    filter_mode = pico_socket_aggregate_mcastfilters( mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq.ipv4.mcast_link_addr, &mreq->mreq.ipv4.mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq.ipv6.mcast_link_addr, &mreq->mreq.ipv6.mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;

}

static int mcast_so_unblock_src(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_mreq_source_t *mreq = (struct pico_ip_mreq_source_t *)value;
    struct pico_mcast_listen *listen = NULL;
    union pico_address *source = NULL, stest, *mcast_link_addr,*mcast_group_addr;
    union mcast_link_u *mcast_link = setopt_multicast_check(s, value, 0, 1);

    memset(&stest, 0, sizeof(union pico_address));
    if (!mcast_link)
        return -1;
     if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq_source.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq_source.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }

    listen = listen_find(s, (union pico_address *) mcast_link_addr, (union pico_address *) mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_UNBLOCK_SOURCE before PICO_IP_ADD_MEMBERSHIP\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        if(mreq->type == PICO_PROTO_IPV4)
            stest.ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
        else
            memcpy(stest.ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (!source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to unblock not in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            pico_tree_delete(&listen->MCASTSources, source);
            PICO_FREE(source);
        }
    }
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 
    filter_mode = pico_socket_aggregate_mcastfilters(mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq_source.ipv4.mcast_link_addr, &mreq->mreq_source.ipv4.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq_source.ipv6.mcast_link_addr, &mreq->mreq_source.ipv6.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;
}


static int mcast_so_block_src(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_mreq_source_t *mreq = (struct pico_mreq_source_t *)value;
    struct pico_mcast_listen *listen;
    union pico_address *source, stest, *mcast_link_addr, *mcast_group_addr;
    union mcast_link_u *mcast_link = setopt_multicast_check(s, value, 0, 1);
    if (!mcast_link)
        return -1;

    memset(&stest, 0, sizeof(union pico_address));
     if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq_source.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq_source.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }

    listen = listen_find(s, mcast_link_addr, mcast_group_addr);
    if (!listen) {
        dbg("pico_socket_setoption: ERROR PICO_IP_BLOCK_SOURCE before PICO_IP_ADD_MEMBERSHIP\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        if(mreq->type == PICO_PROTO_IPV4)
            stest.ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
        else
            memcpy(stest.ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));

        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to block already in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            source = PICO_ZALLOC(sizeof(union pico_address));
            if (!source) {
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }
             if(mreq->type == PICO_PROTO_IPV4)
                source->ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
            else
                memcpy(source->ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));

            pico_tree_insert(&listen->MCASTSources, source);
        }
    }

    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 
    filter_mode = pico_socket_aggregate_mcastfilters(mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq_source.ipv4.mcast_link_addr, &mreq->mreq_source.ipv4.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq_source.ipv6.mcast_link_addr, &mreq->mreq_source.ipv6.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;
}
static int mcast_so_addsrcm(struct pico_socket *s, void *value)
{
    int filter_mode = 0, reference_count = 0;
    struct pico_mreq_source_t *mreq = (struct pico_mreq_source_t *)value;
    struct pico_mcast_listen *listen = NULL;
    union pico_address *source = NULL, stest, *mcast_link_addr, *mcast_group_addr;
    union mcast_link_u * mcast_link = setopt_multicast_check(s, value, 1, 1);
    if (!mcast_link)
        return -1;

    memset(&stest, 0, sizeof(union pico_address));
     if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq_source.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq_source.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }

    listen = listen_find(s, mcast_link_addr, mcast_group_addr);
    if (listen) {
        if (listen->filter_mode != PICO_IP_MULTICAST_INCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR source-specific multicast (include) on any-source multicast (exclude)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        if(mreq->type == PICO_PROTO_IPV4)
            stest.ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
        else
            memcpy(stest.ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (source) {
            so_mcast_dbg("pico_socket_setoption: ERROR source address to allow already in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            source = PICO_ZALLOC(sizeof(union pico_address));
            if (!source) {
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }

            if(mreq->type == PICO_PROTO_IPV4)
                source->ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
            else
                memcpy(source->ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));

            pico_tree_insert(&listen->MCASTSources, source);
        }
    } else {
        listen = PICO_ZALLOC(sizeof(struct pico_mcast_listen));
        if (!listen) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        listen->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        if(mreq->type == PICO_PROTO_IPV4) {
            listen->mcast_link.ip4 = mreq->mreq_source.ipv4.mcast_link_addr;
            listen->mcast_group.ip4 = mreq->mreq_source.ipv4.mcast_group_addr;        
        } else {
            memcpy(&listen->mcast_link.ip6, &mreq->mreq_source.ipv6.mcast_link_addr, sizeof(struct pico_ip6));
            memcpy(&listen->mcast_group.ip6, &mreq->mreq_source.ipv6.mcast_group_addr, sizeof(struct pico_ip6));
        }
        listen->MCASTSources.root = &LEAF;
        listen->MCASTSources.compare = mcast_sources_cmp;
        source = PICO_ZALLOC(sizeof(union pico_address));
        if (!source) {
            PICO_FREE(listen);
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if(mreq->type == PICO_PROTO_IPV4)
            source->ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
        else
            memcpy(source->ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));


        pico_tree_insert(&listen->MCASTSources, source);
        pico_tree_insert(s->MCASTListen, listen);
        reference_count = 1;
    }

    pico_tree_insert(&MCASTSockets, s);
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 
    filter_mode = pico_socket_aggregate_mcastfilters(mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq_source.ipv4.mcast_link_addr, &mreq->mreq_source.ipv4.mcast_group_addr, (uint8_t) reference_count, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq_source.ipv6.mcast_link_addr, &mreq->mreq_source.ipv6.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;
}
static int mcast_so_dropsrcm(struct pico_socket *s, void *value)
{
    int filter_mode = 0, reference_count = 0;
    struct pico_mreq_source_t *mreq = (struct pico_mreq_source_t *)value;
    struct pico_mcast_listen *listen;
    union pico_address *source, stest, *mcast_link_addr, *mcast_group_addr;
    union mcast_link_u *mcast_link = setopt_multicast_check(s, value, 0, 1);
    if (!mcast_link)
        return -1;

    memset(&stest, 0, sizeof(union pico_address));
    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mreq->mreq_source.ipv4.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv4.mcast_group_addr;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mreq->mreq_source.ipv6.mcast_link_addr;
        mcast_group_addr = &mreq->mreq_source.ipv6.mcast_group_addr;
    } 
    else {
        return -1;
    }

    listen = listen_find(s, mcast_link_addr, mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_DROP_SOURCE_MEMBERSHIP before PICO_IP_ADD_SOURCE_MEMBERSHIP\n");
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_INCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR source-specific multicast (include) on any-source multicast (exclude)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        if(mreq->type == PICO_PROTO_IPV4)
            stest.ip4.addr = mreq->mreq_source.ipv4.mcast_source_addr.addr;
        else
            memcpy(stest.ip6.addr, mreq->mreq_source.ipv6.mcast_source_addr.addr, sizeof(struct pico_ip6));
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (!source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to drop not in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            pico_tree_delete(&listen->MCASTSources, source);
            PICO_FREE(source);
            if (pico_tree_empty(&listen->MCASTSources)) { /* 1 if empty, 0 otherwise */
                reference_count = 1;
                pico_tree_delete(s->MCASTListen, listen);
                PICO_FREE(listen);
                if (pico_tree_empty(s->MCASTListen)) {
                    PICO_FREE(s->MCASTListen);
                    s->MCASTListen = NULL;
                    pico_tree_delete(&MCASTSockets, s);
                }
            }
        }
    }

    if(mreq->type == PICO_PROTO_IPV4) {
        mcast_link_addr = &mcast_link->ipv4->address;
    }   
    else if(mreq->type == PICO_PROTO_IPV6) {
        mcast_link_addr = &mcast_link->ipv6->address;
    } 
    filter_mode = pico_socket_aggregate_mcastfilters(mcast_link_addr, mcast_group_addr);
    if (filter_mode < 0)
        return -1;
    if(mreq->type == PICO_PROTO_IPV4) {
        return pico_ipv4_mcast_leave(&mreq->mreq_source.ipv4.mcast_link_addr, &mreq->mreq_source.ipv4.mcast_group_addr, (uint8_t) reference_count, (uint8_t)filter_mode, &MCASTFilter);
    }

    else if(mreq->type == PICO_PROTO_IPV6) {
        return pico_ipv6_mcast_leave(&mreq->mreq_source.ipv6.mcast_link_addr, &mreq->mreq_source.ipv6.mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
    }
    return -1;
}
struct pico_setsockopt_mcast_call
{
    int option;
    int (*call)(struct pico_socket *, void *);
};

static const struct pico_setsockopt_mcast_call mcast_so_calls[1 + PICO_IP_DROP_SOURCE_MEMBERSHIP - PICO_IP_MULTICAST_IF] =
{
    { PICO_IP_MULTICAST_IF,             NULL },
    { PICO_IP_MULTICAST_TTL,            pico_udp_set_mc_ttl },
    { PICO_IP_MULTICAST_LOOP,           mcast_so_loop },
    { PICO_IP_ADD_MEMBERSHIP,           mcast_so_addm },
    { PICO_IP_DROP_MEMBERSHIP,          mcast_so_dropm },
    { PICO_IP_UNBLOCK_SOURCE,           mcast_so_unblock_src },
    { PICO_IP_BLOCK_SOURCE,             mcast_so_block_src },
    { PICO_IP_ADD_SOURCE_MEMBERSHIP,    mcast_so_addsrcm },
    { PICO_IP_DROP_SOURCE_MEMBERSHIP,   mcast_so_dropsrcm }
};


static int mcast_so_check_socket(struct pico_socket *s)
{
    pico_err = PICO_ERR_EINVAL;
    if (!s)
        return -1;

    if (!s->proto)
        return -1;

    if (s->proto->proto_number != PICO_PROTO_UDP)
        return -1;

    pico_err = PICO_ERR_NOERR;
    return 0;
}

int pico_setsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    int arrayn = option - PICO_IP_MULTICAST_IF;
    if (option < PICO_IP_MULTICAST_IF || option > PICO_IP_DROP_SOURCE_MEMBERSHIP) {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;
    }

    if (mcast_so_check_socket(s) < 0)
        return -1;

    if (!mcast_so_calls[arrayn].call) {
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;
    }

    return (mcast_so_calls[arrayn].call(s, value));
}

int pico_udp_set_mc_ttl(struct pico_socket *s, void  *_ttl)
{
    struct pico_socket_udp *u;
    uint8_t ttl = *(uint8_t *)_ttl;
    if(!s) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    u = (struct pico_socket_udp *) s;
    u->mc_ttl = ttl;
    return 0;
}

int pico_udp_get_mc_ttl(struct pico_socket *s, uint8_t *ttl)
{
    struct pico_socket_udp *u;
    if(!s)
        return -1;

    u = (struct pico_socket_udp *) s;
    *ttl = u->mc_ttl;
    return 0;
}
#else
int pico_udp_set_mc_ttl(struct pico_socket *s, void  *_ttl)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_udp_get_mc_ttl(struct pico_socket *s, uint8_t *ttl)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_socket_mcast_filter(struct pico_socket *s, union pico_address *mcast_group, union pico_address *src)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

void pico_multicast_delete(struct pico_socket *s)
{
    (void)s;
}

int pico_getsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_setsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;

}
#endif /* PICO_SUPPORT_MCAST */

