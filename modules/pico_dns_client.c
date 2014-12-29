/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Kristof Roelants
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_dns_common.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_DNS_CLIENT

/* #define dns_dbg(...) do {} while(0) */
#define dns_dbg dbg

/* DNS response length */
#define PICO_DNS_MAX_QUERY_LEN 255
#define PICO_DNS_MAX_QUERY_LABEL_LEN 63

/* DNS client retransmission time (msec) + frequency */
#define PICO_DNS_CLIENT_RETRANS 4000
#define PICO_DNS_CLIENT_MAX_RETRANS 3

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s);
static void pico_dns_client_retransmission(pico_time now, void *arg);
static int pico_dns_client_getaddr_generic(const char *url, uint16_t proto, void (*callback)(char *, void *), void *arg);

struct pico_dns_ns
{
    struct pico_ip4 ns4; /* nameserver */
};

static int dns_ns_cmp(void *ka, void *kb)
{
    struct pico_dns_ns *a = ka, *b = kb;
    return pico_ipv4_compare(&a->ns4, &b->ns4);
}
PICO_TREE_DECLARE(NSTable, dns_ns_cmp);

struct pico_dns_client_cookie
{
    struct pico_dns_header *hdr;
    struct pico_dns_query *q;
    uint8_t retrans;
    struct pico_dns_ns ns;
    struct pico_socket *sock;
    void (*callback)(char *, void *);
    void *arg;
};

static int dns_client_cmp(void *ka, void *kb)
{
    struct pico_dns_client_cookie *a = ka, *b = kb;
    if(a->hdr == NULL || b->hdr == NULL)
        return 0;

    if (a->hdr->id == b->hdr->id)
        return 0;

    return (a->hdr->id < b->hdr->id) ? (-1) : (1);
}
PICO_TREE_DECLARE(DNSTable, dns_client_cmp);

static int pico_dns_client_del_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns test = {{0}}, *found = NULL;

    test.ns4 = *ns_addr;
    found = pico_tree_findKey(&NSTable, &test);
    if (!found)
        return -1;

    pico_tree_delete(&NSTable, found);
    PICO_FREE(found);

    /* no NS left, add default NS */
    if (pico_tree_empty(&NSTable))
        pico_dns_client_init();

    return 0;
}

static struct pico_dns_ns *pico_dns_client_add_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns *dns = NULL, *found = NULL, test = {{0}};

    dns = PICO_ZALLOC(sizeof(struct pico_dns_ns));
    if (!dns) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    dns->ns4 = *ns_addr;

    found = pico_tree_insert(&NSTable, dns);
    if (found) { /* nameserver already present */
        PICO_FREE(dns);
        return found;
    }

    /* default NS found, remove it */
    pico_string_to_ipv4(PICO_DNS_NS_DEFAULT, (uint32_t *)&test.ns4.addr);
    found = pico_tree_findKey(&NSTable, &test);
    if (found && (found->ns4.addr != ns_addr->addr))
        pico_dns_client_del_ns(&found->ns4);

    return dns;
}

static struct pico_dns_ns pico_dns_client_next_ns(struct pico_ip4 *ns_addr)
{
    struct pico_dns_ns dns = {{0}}, *nxtdns = NULL;
    struct pico_tree_node *node = NULL, *nxtnode = NULL;

    dns.ns4 = *ns_addr;
    node = pico_tree_findNode(&NSTable, &dns);
    if (!node)
        return dns; /* keep using current NS */

    nxtnode = pico_tree_next(node);
    nxtdns = nxtnode->keyValue;
    if (!nxtdns)
        nxtdns = (struct pico_dns_ns *)pico_tree_first(&NSTable);

    return *nxtdns;
}

static struct pico_dns_client_cookie *pico_dns_client_add_cookie(struct pico_dns_header *hdr, struct pico_dns_query *q, void (*callback)(char *, void *), void *arg)
{
    struct pico_dns_client_cookie *ck = NULL, *found = NULL;

    ck = PICO_ZALLOC(sizeof(struct pico_dns_client_cookie));
    if (!ck)
        return NULL;

    ck->hdr = hdr;
    ck->q = q;
    ck->retrans = 1;
    ck->ns = *((struct pico_dns_ns *)pico_tree_first(&NSTable));
    ck->callback = callback;
    ck->arg = arg;
    ck->sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dns_client_callback);
    if (!ck->sock) {
        PICO_FREE(ck);
        return NULL;
    }

    found = pico_tree_insert(&DNSTable, ck);
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        pico_socket_close(ck->sock);
        PICO_FREE(ck->hdr);
        PICO_FREE(ck->q);
        PICO_FREE(ck);
        return NULL;
    }

    dns_dbg("Cookie ID#%d '%s' added to table\n", (int)ck->hdr->id, ck->q->qname);

    return ck;
}

static int pico_dns_client_del_cookie(uint16_t tst_id)
{
    struct pico_dns_client_cookie test = {
        0
    }, *found = NULL;

    struct pico_dns_header tst_hdr = {
        .id = tst_id
    };

    test.hdr = &tst_hdr;
    found = pico_tree_findKey(&DNSTable, &test);
    if (!found)
        return -1;

    PICO_FREE(found->hdr);
    PICO_FREE(found->q);
    pico_socket_close(found->sock);
    pico_tree_delete(&DNSTable, found);
    PICO_FREE(found);
    return 0;
}

static struct pico_dns_client_cookie *pico_dns_client_find_cookie(uint16_t tst_id)
{
    struct pico_dns_client_cookie test = {
        0
    }, *found = NULL;

    struct pico_dns_header tst_hdr = {
        .id = tst_id
    };

    test.hdr = &tst_hdr;
    found = pico_tree_findKey(&DNSTable, &test);
    if (found)
        return found;
    else
        return NULL;
}

/* seek end of string */
static char *pico_dns_client_seek(char *ptr)
{
    if (!ptr)
        return NULL;

    while (*ptr != 0)
        ptr++;
    return ptr + 1;
}

static uint16_t pico_dns_client_generate_id()
{
    uint16_t id = 0;
    uint8_t retry = 32;

    do {
        id = (uint16_t)(pico_rand() & 0xFFFFU);
        dns_dbg("DNS: generated id %u\n", id);
    } 
    while (id != 0 && retry-- && (pico_dns_client_find_cookie(id) != NULL));

    if (!retry)
        return 0;

    return id;
}

static int pico_dns_client_check_header(struct pico_dns_header *pre)
{
    if (pre->qr != PICO_DNS_QR_RESPONSE || pre->opcode != PICO_DNS_OPCODE_QUERY || pre->rcode != PICO_DNS_RCODE_NO_ERROR) {
        dns_dbg("DNS ERROR: OPCODE %d | TC %d | RCODE %d\n", pre->opcode, pre->tc, pre->rcode);
        return -1;
    }

    if (short_be(pre->ancount) < 1) {
        dns_dbg("DNS ERROR: ancount < 1\n");
        return -1;
    }

    return 0;
}

static int pico_dns_client_check_qsuffix(struct pico_dns_query *q, struct pico_dns_client_cookie *ck)
{
    if (!q)
        return -1;

    if (short_be(q->qtype) != ck->q->qtype || short_be(q->qclass) != ck->q->qclass) {
        dns_dbg("DNS ERROR: received qtype (%u) or qclass (%u) incorrect\n", short_be(q->qtype), short_be(q->qclass));
        return -1;
    }

    return 0;
}

static int pico_dns_client_check_asuffix(struct pico_dns_answer *a, struct pico_dns_client_cookie *ck)
{
    if (!a) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (short_be(a->atype) != ck->q->qtype || short_be(a->aclass) != ck->q->qclass) {
        dns_dbg("DNS WARNING: received atype (%u) or aclass (%u) incorrect\n", short_be(a->atype), short_be(a->aclass));
        return -1;
    }

    if (long_be(a->ttl) > PICO_DNS_MAX_TTL) {
        dns_dbg("DNS WARNING: received TTL (%u) > MAX (%u)\n", long_be(a->ttl), PICO_DNS_MAX_TTL);
        return -1;
    }

    return 0;
}

static char *pico_dns_client_seek_suffix(char *suf, struct pico_dns_header *hdr, struct pico_dns_client_cookie *ck)
{
    struct pico_dns_answer *ans = NULL;
    uint16_t comp = 0, compression = 0;
    uint16_t i = 0;

    if (!suf)
        return NULL;

    while (i++ < short_be(hdr->ancount)) {
        comp = short_from(suf);
        compression = short_be(comp);
        switch (compression >> 14)
        {
        case PICO_DNS_POINTER:
            while (compression >> 14 == PICO_DNS_POINTER) {
                dns_dbg("DNS: pointer\n");
                suf += sizeof(uint16_t);
                comp = short_from(suf);
                compression = short_be(comp);
            }
            break;

        case PICO_DNS_LABEL:
            dns_dbg("DNS: label\n");
            suf = pico_dns_client_seek(suf);
            break;

        default:
            dns_dbg("DNS ERROR: incorrect compression (%u) value\n", compression);
            return NULL;
        }

        ans = (struct pico_dns_answer *)suf;
        if (!ans)
            break;

        if (pico_dns_client_check_asuffix(ans, ck) < 0) {
            suf += (sizeof(struct pico_dns_answer) + short_be(ans->rdlen));
            continue;
        }

        return suf;
    }
    return NULL;
}

static int pico_dns_client_send(struct pico_dns_client_cookie *ck)
{
    char *dns_packet = NULL;
    uint32_t plen = 0;
    uint16_t *paramID = PICO_ZALLOC(sizeof(uint16_t));
    if (!paramID) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    dns_dbg("DNS: sending query to %08X\n", ck->ns.ns4.addr);
    if (!ck->sock)
        goto failure;

    if (pico_socket_connect(ck->sock, &ck->ns.ns4, short_be(PICO_DNS_NS_PORT)) < 0)
        goto failure;

    dns_packet = pico_dns_create_packet(&plen, ck->hdr, ck->q, NULL);

    pico_socket_send(ck->sock, dns_packet, (int)plen);
    *paramID = ck->hdr->id;
    pico_timer_add(PICO_DNS_CLIENT_RETRANS, pico_dns_client_retransmission, paramID);

    return 0;

failure:
    PICO_FREE(paramID);
    return -1;
}

static void pico_dns_client_retransmission(pico_time now, void *arg)
{
    struct pico_dns_client_cookie *ck = NULL;
    struct pico_dns_client_cookie dummy;
    struct pico_dns_header dummy_hdr;
    IGNORE_PARAMETER(now);

    if(!arg)
        return;

    dummy.hdr = &dummy_hdr;

    /* search for the dns query and free used space */
    dummy.hdr->id = *(uint16_t *)arg;
    ck = (struct pico_dns_client_cookie *)pico_tree_findKey(&DNSTable, &dummy);
    PICO_FREE(arg);

    /* dns query successful? */
    if (!ck) {
        return;
    }

    ck->retrans++;
    if (ck->retrans <= PICO_DNS_CLIENT_MAX_RETRANS) {
        ck->ns = pico_dns_client_next_ns(&ck->ns.ns4);
        pico_dns_client_send(ck);
    } else {
        pico_err = PICO_ERR_EIO;
        ck->callback(NULL, ck->arg);
        pico_dns_client_del_cookie(ck->hdr->id);
    }
}

static int pico_dns_client_user_callback(struct pico_dns_answer *a, struct pico_dns_client_cookie *ck)
{
    uint32_t ip = 0;
    char *str = NULL;

    switch (ck->q->qtype)
    {
    case PICO_DNS_TYPE_A:
        ip = long_from(a->rdata);
        str = PICO_ZALLOC(PICO_DNS_IPV4_ADDR_LEN);
        pico_ipv4_to_string(str, ip);
        break;
#ifdef PICO_SUPPORT_IPV6
    case PICO_DNS_TYPE_AAAA:
    {
        struct pico_ip6 ip6;
        memcpy(&ip6.addr, a->rdata, sizeof(struct pico_ip6));
        str = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN);
        pico_ipv6_to_string(str, ip6.addr);
        break;
    }
#endif
    case PICO_DNS_TYPE_PTR:
        pico_dns_notation_to_name(a->rdata);
        str = PICO_ZALLOC((size_t)(a->rdlen - PICO_DNS_LABEL_INITIAL));
        if (!str) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        memcpy(str, a->rdata + PICO_DNS_LABEL_INITIAL, short_be(a->rdlen) - PICO_DNS_LABEL_INITIAL);
        break;

    default:
        dns_dbg("DNS ERROR: incorrect qtype (%u)\n", ck->q->qtype);
        break;
    }

    if (ck->retrans) {
        ck->callback(str, ck->arg);
        ck->retrans = 0;
        pico_dns_client_del_cookie(ck->hdr->id);
    }

    if (str)
        PICO_FREE(str);

    return 0;
}

static char dns_response[PICO_IP_MTU] = {
     0
};

static void pico_dns_try_fallback_cname(struct pico_dns_client_cookie *ck, struct pico_dns_header *h, struct pico_dns_query *q)
{
    uint16_t type = ck->q->qtype;
    uint16_t proto = PICO_PROTO_IPV4;
    struct pico_dns_answer_suffix *asuffix = NULL;
    char *p_asuffix = NULL;
    char *cname = NULL;

    /* Try to use CNAME only if A or AAAA query is ongoing */
    if (type != PICO_DNS_TYPE_A && type != PICO_DNS_TYPE_AAAA)
        return;

    if (type == PICO_DNS_TYPE_AAAA)
        proto = PICO_PROTO_IPV6;

    ck->q->qtype = PICO_DNS_TYPE_CNAME;
    p_asuffix = (char *)q + sizeof(struct pico_dns_query_suffix);
    p_asuffix = pico_dns_client_seek_suffix(p_asuffix, h, ck);
    if (!p_asuffix) {
        return;
    }
    /* Found CNAME response. Re-initiating query. */
    asuffix = (struct pico_dns_answer_suffix *)p_asuffix;
    cname = (char *) asuffix + sizeof(struct pico_dns_answer_suffix);
    pico_dns_notation_to_name(cname);
    if (cname[0] == '.')
       cname++; 
    dns_dbg("Restarting query for name '%s'\n", cname);
    pico_dns_client_getaddr_generic(cname, proto, ck->callback, ck->arg);
    pico_dns_client_del_cookie(ck->hdr->id);
}
    
static void pico_dns_client_callback(uint16_t ev, struct pico_socket *sock)
{
    struct pico_dns_header *header = NULL;
    char *answer_rr = NULL;
    struct pico_dns_query *q = NULL;
    struct pico_dns_answer *a = NULL;
    struct pico_dns_client_cookie *ck = NULL;
    char *p_asuffix = NULL;

    if (ev == PICO_SOCK_EV_ERR) {
        dns_dbg("DNS: socket error received\n");
        return;
    }

    if (ev & PICO_SOCK_EV_RD) {
        if (pico_socket_read(sock, dns_response, PICO_IP_MTU) < 0)
            return;
    }

    /* DNS Response structure
     *  +--------------------+
     *  | HEADER | ANSWER RR |
     *  +--------------------+
     */

    header = (struct pico_dns_header *)dns_response;
    answer_rr = (char *)header + sizeof(struct pico_dns_header);
    q = (struct pico_dns_query *)pico_dns_client_seek(answer_rr);

    //TODO
    /* valid asuffix is determined dynamically later on */

    if (pico_dns_client_check_header(header) < 0)
        return;

    ck = pico_dns_client_find_cookie(short_be(header->id));
    if (!ck)
        return;

    if (pico_dns_client_check_qsuffix(q, ck) < 0)
        return;

    //p_asuffix = (char *)q + sizeof(struct pico_dns_query_suffix);
    //p_asuffix = pico_dns_client_seek_suffix(p_asuffix, header, ck);
    if (!p_asuffix) {
        pico_dns_try_fallback_cname(ck, header, q);
        return;
    }

    a = (struct pico_dns_answer *)p_asuffix;
    pico_dns_client_user_callback(a, ck);

    return;
}

static int pico_dns_client_addr_label_check_len(const char *url)
{
    const char *p, *label;
    int count;
    label = url;
    p = label;

    while(*p != (char) 0) {
        count = 0;
        while((*p != (char)0)) {
            if (*p == '.'){
                label = ++p;
                break;
            }
            count++;
            p++;
            if (count > PICO_DNS_MAX_QUERY_LABEL_LEN)
                return -1;
        }
    }
    return 0;
}

static int pico_dns_client_getaddr_check(const char *url, void (*callback)(char *, void *))
{
    if (!url || !callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (strlen(url) > PICO_DNS_MAX_QUERY_LEN) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (pico_dns_client_addr_label_check_len(url) < 0) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}

static int pico_dns_client_getaddr_generic(const char *url, uint16_t proto, void (*callback)(char *, void *), void *arg)
{
    struct pico_dns_header *header = NULL;
    struct pico_dns_query *query = NULL;
    struct pico_dns_client_cookie *ck = NULL;
    char *dns_url = NULL;
    uint16_t packet_id = 0;
    (void)proto;

    if (pico_dns_client_getaddr_check(url, callback) < 0)
        return -1;

    dns_url = pico_dns_name_to_dns_notation(url);

    packet_id = pico_dns_client_generate_id();
    if(packet_id == 0)
      return -1;
    header = pico_dns_create_header(packet_id, 1, 0); /* 1 question, 0 answers */

#ifdef PICO_SUPPORT_IPV6
    if(proto == PICO_PROTO_IPV6)
        query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_AAAA, PICO_DNS_CLASS_IN);
    else
#endif
        query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);

    ck = pico_dns_client_add_cookie(header, query, callback, arg);
    if (!ck) {
        PICO_FREE(header);
        return -1;
    }

    if (pico_dns_client_send(ck) < 0) {
        pico_dns_client_del_cookie(ck->hdr->id); /* frees msg */
        return -1;
    }

    return 0;
}

int pico_dns_client_getaddr(const char *url, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_client_getaddr_generic(url, PICO_PROTO_IPV4, callback, arg);
}

int pico_dns_client_getaddr6(const char *url, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_client_getaddr_generic(url, PICO_PROTO_IPV6, callback, arg);
}

static int pico_dns_getname_generic(const char *ip, void (*callback)(char *, void *), void *arg, uint16_t proto)
{
    struct pico_dns_client_cookie *ck = NULL;
    uint16_t packet_id = 0;
    struct pico_dns_header *hdr = NULL;
    struct pico_dns_query *query = NULL;
    char *dns_url = NULL;
    char *inaddr = NULL;

    if (!ip || !callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    inaddr = pico_dns_addr_to_inaddr(ip, proto);
    dns_url = pico_dns_name_to_dns_notation(inaddr);
    PICO_FREE(inaddr);

    packet_id = pico_dns_client_generate_id();
    if(packet_id == 0)
      return -1;
    hdr = pico_dns_create_header(packet_id, 1, 0); /* 1 question, 0 answers */
    query = pico_dns_create_query(dns_url, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN);
    PICO_FREE(dns_url);

    ck = pico_dns_client_add_cookie(hdr, query, callback, arg);
    if(!ck)
        return -1;

    if (pico_dns_client_send(ck) < 0) {
        pico_dns_client_del_cookie(ck->hdr->id);
        return -1;
    }

    return 0;
}

int pico_dns_client_getname(const char *ip, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_getname_generic(ip, callback, arg, PICO_PROTO_IPV4);
}
#ifdef PICO_SUPPORT_IPV6
int pico_dns_client_getname6(const char *ip, void (*callback)(char *, void *), void *arg)
{
    return pico_dns_getname_generic(ip, callback, arg, PICO_PROTO_IPV6);
}
#endif
int pico_dns_client_nameserver(struct pico_ip4 *ns, uint8_t flag)
{
    dns_dbg("nameserver call\n");

    if (!ns) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch (flag)
    {
    case PICO_DNS_NS_ADD:
        if (!pico_dns_client_add_ns(ns))
            return -1;

        break;

    case PICO_DNS_NS_DEL:
        if (pico_dns_client_del_ns(ns) < 0) {
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

int pico_dns_client_init(void)
{
    struct pico_ip4 default_ns = {
        0
    };

    if (pico_string_to_ipv4(PICO_DNS_NS_DEFAULT, (uint32_t *)&default_ns.addr) < 0)
        return -1;

    return pico_dns_client_nameserver(&default_ns, PICO_DNS_NS_ADD);
}


#endif /* PICO_SUPPORT_DNS_CLIENT */
