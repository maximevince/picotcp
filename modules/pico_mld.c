/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   RFC 2710 3019 3590 3810 4604 6636 

   Authors: Roel Postelmans
 *********************************************************************/

#include "pico_stack.h"
#include "pico_ipv6.h"
#include "pico_igmp.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#define mld_dbg printf
//#define igmp_dbg dbg
#define PICO_MLD_LISTENER_QUERY          130
#define PICO_MLD_LISTENER_REPORT         131
#define PICO_MLD_LISTENER_REDUCTION      132

PACKED_STRUCT_DEF pico_mld_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t crc;
	uint16_t mrd;
	uint16_t reserved;
	uint32_t multicast;
};

typedef int (*callback) (struct mld_parameters *);
static int pico_mld_process_event(struct mld_parameters *p); 
static struct mld_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group);

/* queues */
static struct pico_queue mld_in = {
    0
};
static struct pico_queue mld_out = {
    0
};
static void pico_mld_report_expired(struct mld_timer *t)
{
    struct mld_parameters *p = NULL;

    p = pico_mld_find_parameter(&t->mcast_link, &t->mcast_group);
    if (!p)
        return;

    p->event = MLD_EVENT_TIMER_EXPIRED;
    pico_mld_process_event(p);
}
static int pico_mld_send_report(struct mld_parameters *p, struct pico_frame *f)
{
    char * ipv6 = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN); 
    pico_ipv6_to_string(ipv6,p->mcast_group.addr);
    char * ipv6_dst = PICO_ZALLOC(PICO_DNS_IPV6_ADDR_LEN);
    pico_ipv6_to_string(ipv6_dst, p->mcast_group.addr);
    printf("MLD: send membership report on group %s to %s\n", ipv6, ipv6_dst);
    pico_ipv6_frame_push(f, &p->mcast_group, PICO_PROTO_ICMP6);
    return 0;
}


static int8_t pico_mld_generate_report(struct mld_parameters *p)
{
    struct pico_ipv6_link *link = NULL;
    int i = 0;

    link = pico_ipv6_link_get(&p->mcast_link);
    if (!link) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if( !pico_ipv6_is_multicast(p->mcast_group.addr) ) {
        return -1;
    }
    switch (link->mcast_compatibility) {

    case PICO_MLDV1:
    {
        struct pico_icmp6_hdr *report = NULL; 
        uint8_t report_type = PICO_MLD_REPORT;

        p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, IP_OPTION_ROUTER_ALERT_LEN + sizeof(struct pico_icmp6_hdr));
        p->f->net_len = (uint16_t)(p->f->net_len + IP_OPTION_ROUTER_ALERT_LEN);
        p->f->transport_hdr += IP_OPTION_ROUTER_ALERT_LEN;
        p->f->transport_len = (uint16_t)(p->f->transport_len - IP_OPTION_ROUTER_ALERT_LEN);
        p->f->dev = pico_ipv6_link_find(&p->mcast_link);
        /* p->f->len is correctly set by alloc */

        report = (struct pico_icmpv6_hdr*)p->f->transport_hdr;
        report->type = report_type;
        for(i = 0; i< sizeof(struct pico_ip6); i++) 
            report->msg.info.mld_report.record->multicast.addr[i] = p->mcast_group.addr[i];
        report->code = 0;
        report->crc = 0;
        report->crc = short_be(pico_icmp6_checksum(p->f));
        break;
    }

#if 0
    case PICO_MLDV2:
    {
        struct igmpv3_report *report = NULL;
        struct igmpv3_group_record *record = NULL;
        struct pico_mcast_group *g = NULL, test = {
            0
        };
        struct pico_tree_node *index = NULL, *_tmp = NULL;
        struct pico_tree *IGMPFilter = NULL;
        struct pico_ip4 *source = NULL;
        uint8_t record_type = 0;
        uint8_t sources = 0;
        uint16_t len = 0;

        test.mcast_addr = p->mcast_group;
        g = pico_tree_findKey(link->MCASTGroups, &test);
        if (!g) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        if (p->event == IGMP_EVENT_DELETE_GROUP) { /* "non-existent" state of filter mode INCLUDE and empty source list */
            p->filter_mode = PICO_IP_MULTICAST_INCLUDE;
            p->MCASTFilter = NULL;
        }

        if (p->event == IGMP_EVENT_QUERY_RECV) {
            goto igmp3_report;
        }


        /* cleanup filters */
        pico_tree_foreach_safe(index, &IGMPAllow, _tmp)
        {
            pico_tree_delete(&IGMPAllow, index->keyValue);
        }
        pico_tree_foreach_safe(index, &IGMPBlock, _tmp)
        {
            pico_tree_delete(&IGMPBlock, index->keyValue);
        }

        switch (g->filter_mode) {

        case PICO_IP_MULTICAST_INCLUDE:
            switch (p->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
                if (p->event == IGMP_EVENT_DELETE_GROUP) { /* all ADD_SOURCE_MEMBERSHIP had an equivalent DROP_SOURCE_MEMBERSHIP */
                    /* TO_IN (B) */
                    record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                    IGMPFilter = &IGMPAllow;
                    if (p->MCASTFilter) {
                        pico_tree_foreach(index, p->MCASTFilter) /* B */
                        {
                            pico_tree_insert(&IGMPAllow, index->keyValue);
                            sources++;
                        }
                    } /* else { IGMPAllow stays empty } */

                    break;
                }

                /* ALLOW (B-A) */
                /* if event is CREATE A will be empty, thus only ALLOW (B-A) has sense */
                if (p->event == IGMP_EVENT_CREATE_GROUP) /* first ADD_SOURCE_MEMBERSHIP */
                    record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                else
                    record_type = IGMP_ALLOW_NEW_SOURCES;

                IGMPFilter = &IGMPAllow;
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    pico_tree_insert(&IGMPAllow, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    source = pico_tree_findKey(&IGMPAllow, index->keyValue);
                    if (source) {
                        pico_tree_delete(&IGMPAllow, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPAllow)) /* record type is ALLOW */
                    break;

                /* BLOCK (A-B) */
                record_type = IGMP_BLOCK_OLD_SOURCES;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    source = pico_tree_findKey(&IGMPBlock, index->keyValue);
                    if (source) {
                        pico_tree_delete(&IGMPBlock, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPBlock)) /* record type is BLOCK */
                    break;

                /* ALLOW (B-A) and BLOCK (A-B) are empty: do not send report (RFC 3376 $5.1) */
                p->f = NULL;
                return 0;

            case PICO_IP_MULTICAST_EXCLUDE:
                /* TO_EX (B) */
                record_type = IGMP_CHANGE_TO_EXCLUDE_MODE;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                break;

            default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;

        case PICO_IP_MULTICAST_EXCLUDE:
            switch (p->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
                /* TO_IN (B) */
                record_type = IGMP_CHANGE_TO_INCLUDE_MODE;
                IGMPFilter = &IGMPAllow;
                if (p->MCASTFilter) {
                    pico_tree_foreach(index, p->MCASTFilter) /* B */
                    {
                        pico_tree_insert(&IGMPAllow, index->keyValue);
                        sources++;
                    }
                } /* else { IGMPAllow stays empty } */

                break;

            case PICO_IP_MULTICAST_EXCLUDE:
                /* BLOCK (B-A) */
                record_type = IGMP_BLOCK_OLD_SOURCES;
                IGMPFilter = &IGMPBlock;
                pico_tree_foreach(index, p->MCASTFilter)
                {
                    pico_tree_insert(&IGMPBlock, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    source = pico_tree_findKey(&IGMPBlock, index->keyValue); /* B */
                    if (source) {
                        pico_tree_delete(&IGMPBlock, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPBlock)) /* record type is BLOCK */
                    break;

                /* ALLOW (A-B) */
                record_type = IGMP_ALLOW_NEW_SOURCES;
                IGMPFilter = &IGMPAllow;
                pico_tree_foreach(index, &g->MCASTSources)
                {
                    pico_tree_insert(&IGMPAllow, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    source = pico_tree_findKey(&IGMPAllow, index->keyValue); /* A */
                    if (source) {
                        pico_tree_delete(&IGMPAllow, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&IGMPAllow)) /* record type is ALLOW */
                    break;

                /* BLOCK (B-A) and ALLOW (A-B) are empty: do not send report (RFC 3376 $5.1) */
                p->f = NULL;
                return 0;

            default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;

        default:
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
#endif
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    return 0;
}
/* stop timer, send leave if flag set */
static int stsdifs(struct igmp_parameters *p)
{
    printf("MLD: event = leave group | action = stop timer, send done if flag set\n");

    return 0;
}
/* send report, set flag, start timer */
static int srsfst(struct mld_parameters *p)
{

    struct mld_timer t = {
        0
    };
    struct pico_frame *copy_frame = NULL;
    uint8_t i;
    printf("MLD: event = start listening | action = send report, set flag, start timer\n");

    p->last_host = MLD_HOST_LAST;

    if (pico_MLD_generate_report(p) < 0)
        return -1;

    if (!p->f)
        return 0;

    copy_frame = pico_frame_copy(p->f);
    if (!copy_frame) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if (pico_mld_send_report(p, copy_frame) < 0)
        return -1;

    t.type = MLD_TIMER_V1_REPORT;
    for(i=0; i<sizeof(struct pico_ip6); i++) {
        t.mcast_link.addr[i] = p->mcast_link.addr[i];
        t.mcast_group.addr[i] = p->mcast_group.addr[i];
    }
    t.delay = (pico_rand() % (MLD_UNSOLICITED_REPORT_INTERVAL * 10000));
    t.f = p->f;
    t.callback = pico_mld_report_expired;
    //pico_mld_timer_start(&t);

    p->state = MLD_STATE_DELAYING_LISTENER;
    printf("MLD: new state = delaying listener\n");
    return 0;
}
/* merge report, send report, reset timer (IGMPv3 only) */
static int mrsrrt(struct mld_parameters *p)
{

    printf("MLD: event = update group | action = merge report, send report, reset timer (IGMPv3 only)\n");
    return 0;
}
/* send report, start timer (IGMPv3 only) */
static int srst(struct mld_parameters *p)
{
  
    printf("MLD: event = update group | action = send report, start timer (MLDv2 only)\n");
    return 0;
}
/* send done if flag set */
static int sdifs(struct mld_parameters *p)
{
    printf("MLD: event = leave group | action = send done  if flag set\n");
    return 0;
}

/* start timer */
static int st(struct mld_parameters *p)
{
    printf("MLD: event = query received | action = start timer\n");
}
/* stop timer, clear flag */
static int stcl(struct mld_parameters *p)
{
    printf("MLD: event = report received | action = stop timer, clear flag\n");
}
/* send report, set flag */
static int srsf(struct mld_parameters *p)
{
    printf("MLD: event = timer expired | action = send report, set flag\n");
    return 0;
}
/* reset timer if max response time < current timer */
static int rtimrtct(struct igmp_parameters *p) {
    printf("MLD: event = query received | action = reset timer if max response time < current timer\n");


    return 0;
}
static int discard(struct mld_parameters *p)
{
    printf("MLD: ignore and discard frame\n");
    pico_frame_discard(p->f);
    return 0;
}


/* finite state machine table */
static const callback host_membership_diagram_table[3][6] =
{ /* event                    |Query received  |Done reveive |Report receive |Timer expired  | Stop Listening  | Start listening */
/* state Non-Member      */
/* none listener*/          { discard ,         discard,       discard,        discard,         discard,          discard },
/* idle listener */         { discard ,         discard,       discard,        discard,         stsdifs,          discard    },
/* delaying listener     */ { rtimrtct,         discard,          stcl,           srsf,           sdifs,            srsfst }
};
static inline int mldparm_group_compare(struct mld_parameters *a,  struct mld_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_group, &b->mcast_group);
}

static inline int mldparm_link_compare(struct mld_parameters *a,  struct mld_parameters *b)
{
    return pico_ipv6_compare(&a->mcast_link, &b->mcast_link);
}


static int mld_parameters_cmp(void *ka, void *kb)
{
    struct mld_parameters *a = ka, *b = kb;
    int cmp = mldparm_group_compare(a, b);
    if (cmp)
        return cmp;

    return mldparm_link_compare(a, b);
}
PICO_TREE_DECLARE(MLDParameters, mld_parameters_cmp);

static struct mld_parameters *pico_mld_find_parameter(struct pico_ip6 *mcast_link, struct pico_ip6 *mcast_group)
{
    struct mld_parameters test = {
        0
    };
    if (!mcast_link || !mcast_group)
        return NULL;
    uint8_t i;
    for(i = 0; i< sizeof(struct pico_ip6); i++) {
        test.mcast_link.addr[i] = mcast_link->addr[i];
        test.mcast_group.addr[i] = mcast_group->addr[i];
    }
    return pico_tree_findKey(&MLDParameters, &test);
}	
static int pico_mld_is_checksum_valid(struct pico_frame *f) {
    if( pico_icmp6_checksum(f) == 0)
        return 1;
    printf("ICMP6 (MLD) : invalid checksum\n");
    return 0;
}
/* RFC 3810 $8 */
static int pico_mld_compatibility_mode(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = NULL;
    struct pico_ipv6_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hbhoption * hbh = NULL; 
    /*struct mld_timer t = {
        0
    };*/
    uint16_t len, datalen; 
   link = pico_ipv6_link_by_dev(f->dev);
    if (!link)
        return -1;
    ipv6_hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    icmp6_hdr = (struct pico_icmp6_hdr *) f->transport_hdr;
    
    len = (uint16_t) (short_be(ipv6_hdr->len) +f->transport_len);
    datalen = (uint16_t)(f->buffer_len - PICO_SIZE_IP6HDR);
    if (f->dev->eth) {
        datalen = (uint16_t)(datalen - PICO_SIZE_ETHHDR);
    } 
    datalen -= IP_OPTION_ROUTER_ALERT_LEN ; 
    printf("MLD: LEN = %u, OCTETS = %u\n", short_be(ipv6_hdr->len), datalen);
    if( datalen >= 28) {
        /* MLDv2 */
        //link->mcast_compatibility = PICO_MLDV2;
        printf("MLD Compatibility: v2\n");
    } else if( datalen == 24) {
        /* MLDv1 */
        //link->mcast_compatibility = PICO_MLDV1;
        printf("MLD Compatibility: v1\n");
    } else {
        /* invalid query, silently ignored */
        return -1;
    }
    return 0;
}


/* finite state machine caller */
static int pico_mld_process_event(struct mld_parameters *p);

static struct mld_parameters *pico_mld_analyse_packet(struct pico_frame *f)
{
    struct pico_icmp6_hdr *hdr = (struct pico_icmp6_hdr *) f->transport_hdr;
    struct pico_ipv6_hdr *ipv6_hdr = (struct pico_ipv6_hdr *) f->net_hdr;
    struct pico_ipv6_link *link = NULL;
    struct mld_parameters *p = NULL;
    uint8_t general_query = 1;
    struct pico_ip6 mcast_group = {
        0
    };
    struct mld_multicast_address_record  * mld_report = (hdr->msg.info.mld_report.record);
    
    link = pico_ipv6_link_by_dev(f->dev);
    if(!link) 
        return NULL;

    uint32_t i;
    for(i = 0; i < sizeof(struct pico_ip6); i++) {
        mcast_group.addr[i] = mld_report->multicast.addr[i];
        if(mcast_group.addr[i] != 0)
            general_query = 0;
    }

    /* Package check */
    if(ipv6_hdr->hop != MLD_HOP_LIMIT) {
        printf("MLD: Hop limit > 1, ignoring frame\n");
        return NULL;
    }
    struct pico_ipv6_exthdr *hbh = ipv6_hdr+ipv6_hdr->nxthdr;
    if(hbh->ext.routing.routtype != 0) {
        printf("MLD: Router Alert option is not set\n");
        return NULL;
    }
    if(!pico_ipv6_is_linklocal(ipv6_hdr->src.addr) || pico_ipv6_is_unspecified(ipv6_hdr->src.addr) ) {
        printf("MLD Source is invalid link-local address\n");
        return NULL;
    }
    /* end package check */

    p = pico_mld_find_parameter(&link->address, &mcast_group); 
   
    if(!p) {
        printf("Alloc-ing MLD parameters\n");
        p = PICO_ZALLOC(sizeof(struct mld_parameters));
        if(!p)
            return NULL;
        p->state = MLD_STATE_NON_LISTENER;
        for(i = 0; i< sizeof(struct pico_ip6); i++) 
            p->mcast_link.addr[i] = link->address.addr[i];
        pico_tree_insert(&MLDParameters,p);
    } 
    printf("Analyse package, type = %d\n", hdr->type);
    switch(hdr->type) {
    case PICO_MLD_QUERY:
        p->max_resp_time = hdr->msg.info.mld.max_response_time;
        p->event = MLD_EVENT_QUERY_RECV;
        break;
    case PICO_MLD_REPORT:
        p->event = MLD_EVENT_REPORT_RECV;
        break;
    case PICO_MLD_DONE:
        p->event = MLD_EVENT_DONE_RECV;
        break;
    case PICO_MLD_REPORTV2:
        p->event = MLD_EVENT_REPORT_RECV;
        break;
    }
    p->f = f; 
    p->general_query = general_query;
    return p;
}
static int pico_mld_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    struct mld_parameters *p = NULL;
    IGNORE_PARAMETER(self);
   
    printf("CHECKSUM 0x%X\n" , pico_icmp6_checksum(f) );
    if (!pico_mld_is_checksum_valid(f))
        goto out;
    if (pico_mld_compatibility_mode(f) < 0)
        goto out;
    p = pico_mld_analyse_packet(f);
    if (!p)
        goto out;
    return pico_mld_process_event(p);

out:
    printf("FRAME DISCARD\n");
    pico_frame_discard(f);
    return 0;
}

static int pico_mld_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    /* packets are directly transferred to the IP layer by calling pico_ipv4_frame_push */
    IGNORE_PARAMETER(self);
    IGNORE_PARAMETER(f);
    return 0;
}

/* Interface: protocol definition */
struct pico_protocol pico_proto_mld = {
    .name = "mld",
    .proto_number = PICO_PROTO_ICMP6, // MLD is embedded in the ICMP6 protocol
    .layer = PICO_LAYER_TRANSPORT,
    .process_in = pico_mld_process_in,
    .process_out = pico_mld_process_out,
    .q_in = &mld_in,
    .q_out = &mld_out,
};

static int pico_mld_process_event(struct mld_parameters *p) {
    struct pico_tree_node *index= NULL;
    struct mld_parameters *_p;
   
    char ipv6[40];
    pico_ipv6_to_string(ipv6, p->mcast_group.addr);
    printf("MLD: process event on group address %s\n", ipv6);
    if (p->event == MLD_EVENT_QUERY_RECV && p->general_query) { /* general query */
        pico_tree_foreach(index, &MLDParameters) {
            _p = index->keyValue;
            _p->max_resp_time = p->max_resp_time;
            _p->event = MLD_EVENT_QUERY_RECV;
            pico_ipv6_to_string(ipv6, _p->mcast_group.addr);
            printf("MLD: for each mcast_group = %08X | state = %u\n", ipv6, _p->state);
            host_membership_diagram_table[_p->state][_p->event](_p);
        }
    } else {
        printf("MLD: state = %u (0: non-listener - 1: delaying listener - 2: idle listener)\n", p->state);
        host_membership_diagram_table[p->state][p->event](p);
    }
    return 0;
}
