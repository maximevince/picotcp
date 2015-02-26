/*********************************************************************
 PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 See LICENSE and COPYING for usage.
 .
 Author: Toon Stegen
 *********************************************************************/

/* picoTCP */
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_mdns.h"
#include "pico_dns_common.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

//#define mdns_dbg(...) do {} while(0)
#define mdns_dbg dbg

#define PICO_MDNS_QUERY_TIMEOUT (10000) /* Ten seconds */
#define PICO_MDNS_RR_TTL_TICK (1000)    /* One second */

#define PICO_MDNS_CACHE_FLUSH_BIT 0x8000u
#define PICO_MDNS_NO_CACHE_FLUSH_BIT 0x0000u
#define PICO_MDNS_UNICAST_RESPONSE_BIT 0x8000u
#define PICO_MDNS_NO_UNICAST_RESPONSE_BIT 0x0000u

#define PICO_MDNS_FLAG_PROBE 0x01u
#define PICO_MDNS_FLAG_NO_PROBE 0x00u
#define PICO_MDNS_FLAG_UNICAST_RES 0x02u
#define PICO_MDNS_FLAG_MULTICAST_RES 0x00u
#define PICO_MDNS_FLAG_CACHE_FLUSH 0x04u
#define PICO_MDNS_FLAG_NO_CACHE_FLUSH 0x00u

#define PICO_ARPA_IPV4_SUFFIX ".in-addr.arpa"
#define PICO_ARPA_IPV6_SUFFIX ".IP6.ARPA"

#define IS_PROBE_FLAG_SET(x) (((x) & PICO_MDNS_FLAG_UNICAST_RES) > 0 ?  PICO_MDNS_FLAG_PROBE : PICO_MDNS_FLAG_NO_PROBE)
#define IS_UNICAST_FLAG_SET(x) (((x) & PICO_MDNS_FLAG_PROBE) > 0 ? PICO_MDNS_UNICAST_RESPONSE_BIT : PICO_MDNS_NO_UNICAST_RESPONSE_BIT)
#define IS_CACHE_FLUSH_FLAG_SET(x) (((x) & PICO_MDNS_FLAG_CACHE_FLUSH) > 0 ? PICO_MDNS_CACHE_FLUSH_BIT : PICO_MDNS_NO_CACHE_FLUSH_BIT)

static struct pico_ip4 inaddr_any = { 0 };

/* struct containing status of a query */
struct pico_mdns_cookie {
    struct pico_dns_header *header;     /* Pointer to DNS packet */
    char *qname;                        /* Hostname being queried */
    uint16_t qtype;                     /* qtype */
    uint16_t qclass;                    /* qclass */
    uint8_t count;                      /* Number of packets to send */
    uint8_t flags;                      /* Flags: | uni/multi ‡| probe | */
    uint16_t len;                       /* Length of packet */
    struct pico_timer *timer;           /* For Timer events */
    void (*callback)(char *, void *);   /* MARK: Callback? */
    void *arg;                          /* Argument to pass to callback */
};

/* struct containing the information about a cache record */
struct pico_mdns_cache_rr {
    char *url;                          /* Hostname */
    struct pico_dns_answer_suffix *suf; /* Type, Class, TTL and rdata length */
    char *rdata;                        /* Resource Record Data */
    struct pico_timer *timer;           /* For Timer events */
};

/* Global socket and port for all mdns communication */
static struct pico_socket *mdns_sock = NULL;
static uint16_t mdns_port = 5353u;

/* only one hostname can be claimed at the time */
static char *mdns_global_host;

/* ------------ FUNCTION PROTOTYPES ----------- */
// MARK: PROTOS COOKIE UTILITIES
static int pico_mdns_qname_to_url( const char *qname, char **url_addr );
static int pico_mdns_url_to_qname( const char *url, char **qname_addr );
static int pico_mdns_del_cookie( char *url, uint16_t qtype );
static struct pico_mdns_cookie *pico_mdns_find_cookie( const char *url, uint16_t qtype );
static struct pico_mdns_cookie *pico_mdns_add_cookie( struct pico_dns_header *dns_packet, uint16_t len, uint8_t flags, uint8_t count, void (*callback)(char *str, void *arg), void *arg );
// MARK: PROTOS MDNS QUERY UTILITIES
static struct pico_dns_header *pico_mdns_dns_fill_query( struct pico_dns_question *question_list, uint16_t *len );
// MARK: PROTOS MDNS ANSWER UTILITIES
static uint16_t mdns_get_len(uint16_t qtype, char *rdata);
static struct pico_dns_header *pico_mdns_create_answer(char *url, unsigned int *len, uint16_t qtype, void *_rdata);
// MARK: PROTOS ASYNCHRONOUS MDNS RECEPTION
static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer, char *name);
static int pico_check_query_name(char *url);
static int pico_mdns_handle_query(char *name, struct pico_dns_query_suffix *suf, struct pico_ip4 peer);
static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer);
static void pico_mdns_wakeup(uint16_t ev, struct pico_socket *s);
static struct pico_dns_header *pico_mdns_create_answer(char *url, unsigned int *len, uint16_t qtype, void *_rdata);
/* -------------------------------------------- */

/* **************************************************************************
 * Compare-function for two cache entries to give to the tree
 * **************************************************************************/
static int mdns_cache_cmp(void *ka, void *kb)
{
    struct pico_mdns_cache_rr *a = ka, *b = kb;
    uint32_t ha = 0, hb = 0;
    
    /* Cache is sorted by qtype, name */
    if(a->suf->qtype < b->suf->qtype)
        return -1;
    if(b->suf->qtype < a->suf->qtype)
        return 1;
    
    /* Hash strings to compare */
    ha = pico_hash(a->url, (uint32_t)strlen(a->url));
    hb = pico_hash(b->url, (uint32_t)strlen(b->url));
    
    if(ha < hb)
        return -1;
    if(hb < ha)
        return 1;
    
    return 0;
}

/* **************************************************************************
 * Compare-function for two query-cookies to give to the tree
 * **************************************************************************/
static int mdns_cmp(void *ka, void *kb)
{
    struct pico_mdns_cookie *a = ka, *b = kb;
    uint32_t ha = 0, hb = 0;
    
    /* Cookie is sorted by qtype, name */
    if(a->qtype < b->qtype)
        return -1;
    if(b->qtype < a->qtype)
        return 1;
    
    /* Hash strings to compare */
    ha = pico_hash(a->qname, (uint32_t)strlen(a->qname));
    hb = pico_hash(b->qname, (uint32_t)strlen(b->qname));
    
    if(ha < hb)
        return -1;
    if(hb < ha)
        return 1;
    
    return 0;
}

/* Cache records for the mDNS hosts in the network */
PICO_TREE_DECLARE(CacheTable, mdns_cache_cmp);

/* Tree containing query-cookies */
PICO_TREE_DECLARE(QTable, mdns_cmp);

// MARK: MDNS PACKET UTILITIES

/* Just prints a DNS packet with given length in [len] */
static void pico_mdns_print_dns_packet(struct pico_dns_header *packet, uint16_t len)
{
    int i, j, k; /* Iterators */
    int lines_8_wide;
    int leftover;
    unsigned char *buf = (unsigned char *)packet;
    
    lines_8_wide = len / 8;
    leftover = len % 8;
    mdns_dbg("______________________________\n");
    mdns_dbg("DNS PACKET (RAW) size '%d': \n", len);
    for (j = 0; j < lines_8_wide; j++) {
        for (i = 0; i < 8; i++) {
            k = (8 * j) + i;
            mdns_dbg("%02X ", (unsigned char)buf[k]);
            if (i == 3) mdns_dbg(" ");
        }
        mdns_dbg("\n");
    }
    for (i = 0; i < leftover; i++) {
        k = (8 * j) + i;
        mdns_dbg("%02X ", (unsigned char)buf[k]);
        if (i == 3) mdns_dbg(" ");
    }
    mdns_dbg("\n______________________________\n");
}

/* Sends an mdns packet on the global socket*/
static int pico_mdns_send_packet(struct pico_dns_header *hdr, unsigned int len)
{
    struct pico_ip4 dst;
    pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &dst.addr);
    return pico_socket_sendto(mdns_sock, hdr, (int)len, &dst, short_be(mdns_port));
}

/* Fill in the DNS header following the mDNS header format */
static void pico_mdns_fill_packet_header(struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount, uint16_t authcount, uint16_t addcount)
{
    hdr->id = short_be(0);
    pico_dns_fill_header(hdr, qdcount, ancount, authcount, addcount);
}

/* Returns the compressed length of the compressed name without NULL terminator */
static unsigned int pico_mdns_namelen_comp(char *name)
{
    unsigned int len;
    char *ptr;
    
    ptr = name;
    
    /* Just count until the zero-byte */
    while (*ptr != '\0' && !(*ptr & 0x80)) {
        ptr += (uint8_t) *ptr + 1;
    }
    len = (unsigned int) (ptr - name);
    if(*ptr != '\0') {
        len++;
    }
    
    return len;
}

/* returns the uncompressed length of the compressed name  without NULL terminator */
static unsigned int pico_mdns_namelen_uncomp(char *name, char *buf)
{
    unsigned int len = 0;   // Temporary storage of length
    char *begin_comp = name;// Temporary pointer to beginning of name in data field
    char *ptr = begin_comp; // Temporary pointer
    
    /* While we are not at the end of the name */
    while (*ptr != '\0') {
        /* Check if the first bit of the data is set '|1|1|POINTER...|' */
        if(*ptr & 0x80) {
            len += (unsigned int) (ptr - begin_comp);
            begin_comp = buf + *(ptr + 1);  /* set at beginning of compstring*/
            ptr = begin_comp;
        }
        
        /* Move 'ptr' to the next length label */
        ptr += (uint8_t)*ptr + 1;
    }
    
    len += (unsigned int) (ptr - begin_comp);
    return len;
}

/* Replaces the label length in the domain name by '.'
 * f.e. 3www6google2be0 => .www.google.be
 * AND expand compressed names */
static char *pico_mdns_expand_name_comp(char *url, char *buf)
{
    unsigned int len;   // To store the complete length of the name
    char *ptr;          // Temporary pointer
    char *begin_comp;   // Temporary pointer to beginning of ?
    char *str = NULL;   // Temporary storage of name
    char *sp;           // SP?
    
    /* Determine the length of the uncompressed name */
    len = pico_mdns_namelen_uncomp(url, buf);
    mdns_dbg("Uncomp len:%u, comp len:%u.\n", len, pico_mdns_namelen_comp(url));
    
    /* Determine the length of a compressed name */
    if(len < pico_mdns_namelen_comp(url)) {
        mdns_dbg("BOOM compressed longer than uncompressed!\n");
        return NULL;
    }
    
    /* Provide storage for the name */
    str = PICO_ZALLOC(len + 1); /* + 1 for null terminator */
    if(!str) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Convert compressed 3www6google2be0 => .www.google.be */
    begin_comp = url;
    ptr = begin_comp;
    sp = str;
    *sp = '.';
    sp++;
    while(*ptr != '\0') {
        memcpy(sp, ptr + 1, *(uint8_t*)ptr);
        sp += (uint8_t)*ptr;
        *sp = '.';
        sp++;
        ptr += (uint8_t)*ptr + 1; /* jump to next occurring dot */
        if(*ptr & 0x80) {
            len += (unsigned int) (ptr - begin_comp) + 1;   /* +1 for the dot at the end of the label */
            begin_comp = buf + *(ptr + 1);  /* set at beginning of compstring*/
            ptr = begin_comp;
        }
    }
    sp--;
    *sp = '\0';
    
    return str;
}

// MARK: QUESTION UTILITIES

/* **************************************************************************
 *
 * Fills in the question suffix following the mDNS-question suffix format,
 * with MSB (unicast response bit) of the qclass-field set accordingly.
 *
 * **************************************************************************/
static void pico_mdns_fill_question_suffix(struct pico_dns_query_suffix *qsuffix, uint16_t qtype, uint16_t qclass, uint16_t qclass_MSB)
{
    /* Cast the class to a 16-bit unsigned integer otherwise the MSB will be casted to a 8-bit unsigned integer when OR-ing */
    qclass_MSB = (uint16_t) qclass_MSB;
    qclass = (uint16_t) qclass;
    qclass |= qclass_MSB;
    
    pico_dns_fill_query_suffix(qsuffix, qtype, qclass);
}

/* **************************************************************************
 *
 * Fills the qname-field [qname] of the question with [url] in DNS-format,
 * f.e.: www.google.com => 3www6google3com0
 * If [inverse] is set, an arpa-suffix will be added to the qname depending
 * on [proto], whether this param is PICO_PROTO_IPV4 or PICO_PROTO_IPV6.
 *
 * **************************************************************************/
static void pico_mdns_fill_qname( char *qname, const char *url, uint16_t qtype, uint16_t proto )
{
    /* If reverse IPv4 address resolving is requested, convert to IPv4 arpa-format */
    if(qtype == PICO_DNS_TYPE_PTR && proto == PICO_PROTO_IPV4) {
        memcpy(qname + 1u, url, strlen(url));
        pico_dns_mirror_addr(qname + 1u);
        memcpy(qname + (uint16_t)(pico_dns_client_strlen(url) + 2u) - 1, PICO_ARPA_IPV4_SUFFIX, strlen(PICO_ARPA_IPV4_SUFFIX));
    }
    /* If reverse IPv6 address resolving is requested, convert to IPv6 arpa-format */
#ifdef PICO_SUPPORT_IPV6
    else if (qtype == PICO_DNS_TYPE_PTR && proto == PICO_PROTO_IPV6) {
        pico_dns_ipv6_set_ptr(url, qname + 1u);
        memcpy(qname + 1u + STRLEN_PTR_IP6, PICO_ARPA_IPV6_SUFFIX, strlen(PICO_ARPA_IPV6_SUFFIX));
    }
#endif
    /* If NO reverse address resolving is requested, copy url in the qname field */
    else
        memcpy(qname + 1u, url, strlen(url));
    
    /* change www.google.com to 3www6google3com0 */
    pico_dns_name_to_dns_notation(qname);
}

/* **************************************************************************
 *
 * Gets the length of a given 'url' as if it where a qname for given qtype and
 * protocol. Fills arpalen with the length of the arpa-suffix when qtype is 
 * PICO_DNS_TYPE_PTR, depending on [proto].
 *
 * **************************************************************************/
static uint16_t pico_mdns_get_qname_len( const char *url, uint16_t *arpalen, uint16_t qtype, uint16_t proto )
{
    uint16_t slen;
    
    /* Check if pointers given are not NULL */
    if (!url && !arpalen) {
        pico_err = PICO_ERR_EINVAL;
        return 0;
    }
    
    /* Get length + 2 for .-prefix en trailing zero-byte by default */
    slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    *arpalen = 0;
    
    /* Get the length of arpa-suffix if needed */
    if (proto == PICO_PROTO_IPV4 && qtype == PICO_DNS_TYPE_PTR)
        *arpalen = (uint16_t) strlen(PICO_ARPA_IPV4_SUFFIX);
#ifdef PICO_SUPPORT_IPV6
    else if (proto == PICO_PROTO_IPV6 && qtype == PICO_DNS_TYPE_PTR) {
        *arpalen = (uint16_t) strlen(PICO_ARPA_IPV6_SUFFIX);
        slen = STRLEN_PTR_IP6 + 2u;
    }
#endif
    
    return slen;
}

/* **************************************************************************
 *
 * Creates a standalone DNS question for given 'url'. Fills the 'len'-argument
 * with the total length of the question.
 *
 * **************************************************************************/
static struct pico_dns_question *pico_mdns_dns_create_question( const char *url, uint16_t *len, uint8_t proto, uint16_t qtype, uint8_t flags )
{
    struct pico_dns_question *question = NULL;  /* Question pointer to return */
    uint16_t slen, arpalen;                     /* Some lenghts */
    
    /* Check if valid arguments are provided */
    if (!url || !len) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    if (proto != PICO_PROTO_IPV6 && proto != PICO_PROTO_IPV4) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Determine the length of the URL as if it where a qname */
    slen = pico_mdns_get_qname_len(url, &arpalen, qtype, proto);
    
    /* Allocate space for the question and the subfields */
    question = PICO_ZALLOC(sizeof(struct pico_dns_question));
    question->qname = PICO_ZALLOC(slen + arpalen);
    question->qsuffix = PICO_ZALLOC(sizeof(struct pico_dns_query_suffix));
    if (!question || !(question->qname) || !(question->qsuffix)) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Determine the entire length of the question */
    *len = slen + arpalen + (uint16_t) sizeof(struct pico_dns_query_suffix);
    
    /* Set the length of the question */
    question->qname_length = slen + arpalen;
    
    /* Initialise next-pointer */
    question->next = NULL;
    
    /* Fill in the qname field */
    pico_mdns_fill_qname(question->qname, url, qtype, proto);
    
    /* Fill in the question suffix */
    if (IS_PROBE_FLAG_SET(flags))
    /* RFC:
     *  All probe queries SHOULD be done using the desired resource
     *  record name and class (usually class 1, "Internet"), and
     *  query type "ANY" (255), to elicit answers for all
     *  types of records with that name.
     */
        pico_mdns_fill_question_suffix(question->qsuffix, PICO_DNS_TYPE_ANY, PICO_DNS_CLASS_IN, IS_UNICAST_FLAG_SET(flags));
    else if (qtype == PICO_DNS_TYPE_PTR)
        pico_mdns_fill_question_suffix(question->qsuffix, PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN, IS_UNICAST_FLAG_SET(flags));
    else {
        pico_mdns_fill_question_suffix(question->qsuffix, qtype, PICO_DNS_CLASS_IN, IS_UNICAST_FLAG_SET(flags));
    }
    
    return question;
}

/* **************************************************************************
 *
 * Creates a standalone DNS question for given 'url'. Fills the 'len'-argument
 * with the total length of the question.
 *
 * **************************************************************************/
static int pico_mdns_dns_fill_question_section( struct pico_dns_header *packet, struct pico_dns_question *question_list)
{
    struct pico_dns_question *iterator = question_list;         /* Put iterator at the beginning of list */
    struct pico_dns_question *previous = iterator;              /* Pointer to previous question in list when iterating */
    char *destination_qname = NULL;                             /* Destination pointer to copy the iterator->qname to */
    struct pico_dns_query_suffix *destination_qsuffix = NULL;   /* Destination pointer to copy the iterator->qsuffix to */
    
    /* Set the destination pointer to the beginning of the Question Section */
    destination_qname = (char *) packet + sizeof(struct pico_dns_header);
    destination_qsuffix = (struct pico_dns_query_suffix *) (destination_qname + iterator->qname_length);
    
    /* Iterate again over the question list */
    while (iterator) {
        /* Copy the qname of the question into the packet */
        memcpy(destination_qname, iterator->qname, iterator->qname_length);
        
        /* Copy the qtype and qclass fields */
        destination_qsuffix->qtype = iterator->qsuffix->qtype;
        destination_qsuffix->qclass = iterator->qsuffix->qclass;
        
        /* Remember the previous question */
        previous = iterator;
        
        /* Move to the next question in the list */
        iterator = iterator->next;
        
        /* Set the destination pointers correctly */
        destination_qname = (char *) destination_qsuffix + sizeof(struct pico_dns_query_suffix);
        destination_qsuffix = (struct pico_dns_query_suffix *) (destination_qname + previous->qname_length);
        
        /* Free space */
        PICO_FREE(previous->qname);
        PICO_FREE(previous->qsuffix);
        PICO_FREE(previous);
        previous = NULL;
    }
    
    return 0;
}

// MARK: RRECORD UTILITIES

/* **************************************************************************
 *
 *  Returns the size summed up of all the resource records contained in a
 *  linked list. Fills [count] with the number of records in the list.
 *
 * **************************************************************************/
static inline uint16_t pico_mdns_rr_list_size( struct pico_dns_res_record *list_begin, uint8_t *count )
{
    struct pico_dns_res_record *iterator = list_begin;  /* Put iterator at beginning of list */
    uint16_t size = 0;                                  /* Size of list, to return */
    *count = 0;                                         /* Clean out *count */
    
    /* Iterate over the linked list */
    while (iterator) {
        *count += 1;
        size += (uint16_t)(aniterator->qname_length + sizeof(struct pico_dns_answer_suffix) + aniterator->rsuffix->rdlength);
        iterator = iterator->next;
    }
    return size;
}

/* **************************************************************************
 *
 *  Copies the contents a resource record [res_record] to a single flat
 *  location in [destination]. [after] pointer will point to address
 *  right after this flat resource record on success.
 *
 * **************************************************************************/
static int pico_mdns_rr_copy_flat( struct pico_dns_res_record *res_record, uint8_t *destination )
{
    /* Check if there are no NULL-pointers given */
    if (!res_record || !destination || !after) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Initialise the destiation pointers to the right locations */
    char *destination_rname = (char *)destiation
    struct pico_dns_answer_suffix *destination_rsuffix = (struct pico_dns_answer_suffix *) (destination_rname + res_record->rname_length);
    uint8_t *destination_rdata = (uint8_t *) (destination_rsuffix + sizeof(struct pico_dns_answer_suffix));

    /* Copy the rname of the resource record into the flat location */
    memcpy(destination_rname, res_record->rname, res_record->rname_length);
    
    /* Copy the question suffix fields */
    destination_rsuffix->qtype = res_record->rsuffix->qtype;
    destination_rsuffix->qclass = res_record->rsuffix->qclass;
    destination_rsuffix->ttl = res_record->rsuffix->ttl;
    destination_rsuffix->rdlength = res_record->rsuffix->rdlength;
    
    /* Copy the rdata of the resource */
    memcpy(destination_rdata, res_record->rdata, res_record->rsuffix->rdlength);
    
    /* Point to location right after flat resource record */
    destination = (uint8_t *)(destination_rdata + res_record->rsuffix->rdlength);
    
    return 0;
}

/* **************************************************************************
 *
 * Fills in the resource record suffix following the mDNS-question suffix 
 * format, with MSB (cache flush bit) of the qclass set accordingly
 *
 * **************************************************************************/
static void pico_mdns_fill_record_suffix( struct pico_dns_query_suffix *rsuffix, uint16_t rtype, uint16_t rclass, uint16_t rclass_MSB, uint16_t rttl, uint16_t datalen )
{
    /* Cast the class to a 16-bit unsigned integer otherwise the MSB will be casted to a 8-bit unsigned integer when OR-ing */
    rclass_MSB = (uint16_t) rclass_MSB;
    rclass = (uint16_t) rclass;
    rclass |= rclass_MSB;
    
    pico_dns_fill_rr_suffix(rsuffix, rtype, rclass, rttl, datalen);
}

/* **************************************************************************
 *
 * Creates a standalone DNS resource record for given 'url'. Fills the 
 * 'len'-argument with the total length of the res_record.
 *
 * **************************************************************************/
static struct pico_dns_res_record *pico_mdns_create_res_record( const char *url, void *_rdata, uint16_t *len, uint16_t rtype, uint16_t rttl, uint8_t flags )
{
    struct pico_dns_res_record *res_record = NULL;  /* res_record to return */
    char *rname = NULL;                             /* res_record name */
    uint16_t slen, datalen;                         /* some lenghts */
    
    /* Cast the void pointer to a char pointer */
    char *rdata = (char *)_rdata;
    
    /* Get length + 2 for .-prefix en trailing zero-byte */
    slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    
    /* Determine the length of rdata */
    switch (rtype) {
        case PICO_DNS_TYPE_A: datalen = PICO_SIZE_IP4; break;
        case PICO_DNS_TYPE_AAAA: datalen = PICO_SIZE_IP6; break;
        default: datalen = (uint16_t)(strlen(rdata) + 1u) break;
    }
    
    /* Allocate space for the record and subfields */
    res_record = PICO_ZALLOC(sizeof(struct pico_dns_res_record));
    res_record->rname = PICO_ZALLOC(slen);
    res_record->rsuffix = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    res_record->rdata = PICO_ZALLOC(datalen);
    if (!res_record || !(res_record->rname) || !(res_record->rsuffix) || !(res_record->rdata)) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Determine the complete length of resource record including rname, rsuffix and rdata */
    *len = slen + (uint16_t)(sizeof(struct pico_dns_answer_suffix) + datalen);
    
    /* Fill in the rname_length field */
    res_record->rname_length = slen;
    
    /* Copy url into rname in DNS notation */
    strcpy(res_record->rname + 1u, url);
    pico_dns_name_to_dns_notation(res_record->rname);
    
    /* Fill in the resource record suffix */
    pico_mdns_fill_record_suffix(res_record->rsuffix, rtype, PICO_DNS_CLASS_IN, IS_CACHE_FLUSH_FLAG_SET(flags), rttl, datalen);
    
    /* Fill in the rdata */
    memcpy(res_record->rdata, rdata, datalen);
    
    return res_record;
}

/* **************************************************************************
 *
 *  Fills the resource record section of a DNS packet with provided record-
 *  lists. NULL-pointers can be passed on as regards to the list but not DNS-
 *  packet itself.
 *
 * **************************************************************************/
static int pico_mdns_dns_fill_rr_sections( struct pico_dns_header *packet, struct pico_dns_res_record *answer_list, struct pico_dns_res_record *authority_list, struct pico_dns_res_record *additional_list )
{
    
    struct pico_dns_res_record *iterator = NULL;                /* Put iterator at the beginning of list */
    struct pico_dns_res_record *previous = NULL;                /* Pointer to previous resource record in list when iterating */
    char *destination_rname = NULL;                             /* Destination pointer to copy iterator->rname to */
    
    if (!packet) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Begin with answers */
    iterator = answer_list;
    
    /* Initialise the destination pointers before iterating */
    destination = (char *) packet + sizeof(struct pico_dns_header);
    
    /* Keep iterating over the list until the end */
    while (iterator) {
        /* Copy resource record flat in packet */
        if (pico_mdns_rr_copy_flat(iterator, destination)) {
            mdns_dbg("Could not copy resource record with rname '%s' into Answer Section!\n", iterator->rname);
            return -1;
        }
        /* Move to the next resource record, and free space */
        previous = iterator;
        iterator = iterator->next;
        PICO_FREE(previous->rname);
        PICO_FREE(previous->rsuffix);
        PICO_FREE(previous->rdata);
        PICO_FREE(previous);
        previous = NULL;
    }
    
    /* Next, the authority records */
    iterator = authority_list;
    
    while (iterator) {
        if (pico_mdns_rr_copy_flat(iterator, destination)) {
            mdns_dbg("Could not copy resource record with rname '%s' into Authority Section!\n", iterator->rname);
            return -1;
        }
        /* Move to the next resource record, and free space */
        previous = iterator;
        iterator = iterator->next;
        PICO_FREE(previous->rname);
        PICO_FREE(previous->rsuffix);
        PICO_FREE(previous->rdata);
        PICO_FREE(previous);
        previous = NULL;
    }
    
    /* And last but not least, the additional records */
    iterator = additional_list;
    
    while (iterator) {
        if (pico_mdns_rr_copy_flat(iterator, destination)) {
            mdns_dbg("Could not copy resource record with rname '%s' into Authority Section!\n", iterator->rname);
            return -1;
        }
        /* Move to the next resource record, and free space */
        previous = iterator;
        iterator = iterator->next;
        PICO_FREE(previous->rname);
        PICO_FREE(previous->rsuffix);
        PICO_FREE(previous->rdata);
        PICO_FREE(previous);
        previous = NULL;
    }
    
    return 0;
}

// MARK: MDNS QUERY UTILITIES

/* **************************************************************************
 *
 * Creates a DNS packet meant for querying. Currently only questions can be
 * inserted in the packet.
 *
 * TODO: Allow resource records to be added to Authority & Answer Section
 *          - Answer Section: To implement Known-Answer Suppression
 *          - Authority Section: To implement probe queries and tiebreaking
 *
 * **************************************************************************/
static struct pico_dns_header *pico_mdns_dns_fill_query( struct pico_dns_question *question_list, uint16_t *len )
{
    struct pico_dns_header *packet = NULL;                  /* Pointer to DNS packet in memory */
    struct pico_dns_question *qiterator = question_list;    /* Put iterator at the beginning of list */
    uint8_t qdcount;                                        /* Question-count */
    
    /* The length starts with the size of the header */
    *len = (uint16_t) sizeof(struct pico_dns_header);
    
    /* Determine the length that the Question Section needs to be */
    while (qiterator != NULL) {
        qdcount++;
        *len += (uint16_t)(qiterator->qname_length + sizeof(struct pico_dns_query_suffix));
        qiterator = qiterator->next;
    }
    
    /* Provide space for the entire packet */
    packet = PICO_ZALLOC(*len);
    if (!packet) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Fill the Question Section with questions */
    if (pico_mdns_dns_fill_question_section(packet, question_list)) {
        mdns_dbg("Could not fill Question Section correctly!\n");
        return -1;
    }
    
    /* Fill the DNS packet header */
    pico_mdns_fill_packet_header(packet, qdcount, 0, 0, 0);
    
    return packet;
}

// MARK: MDNS ANSWER UTILITIES

static struct pico_dns_header *pico_mdns_dns_fill_answer( struct pico_dns_res_record *answer_list, struct pico_dns_res_record *authority_list, struct pico_dns_res_record *additional_list, uint16_t *len )
{
    struct pico_dns_header *packet = NULL;                      /* Pointer to DNS packet in memory */
    uint8_t ancount, authcount, addcount;                       /* Section-counts */
    
    /* The length start with the size of the header */
    *len = (uint16_t) sizeof(struct pico_dns_header);
    
    /* Get the size of the entire packet and determine the header counters */
    *len += pico_mdns_rr_list_size(answer_list, &ancount);
    *len += pico_mdns_rr_list_size(authority_list, &authcount);
    *len += pico_mdns_rr_list_size(additional_list, &addcount);
    
    /* Provide space for the entire packet */
    packet = PICO_ZALLOC(*len);
    if (!packet) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Fill the resource record sections */
    if (pico_mdns_dns_fill_rr_sections(packet, answer_list, authority_list, additional_list)) {
        mdns_dbg("Could not fill Resource Record Sections correctly!\n");
        return -1;
    }
    
    /* Fill the DNS packet header */
    pico_mdns_fill_packet_header(packet, 0, ancount, authcount, addcount);
    
    return packet;
}

/* Get the length of rdata depending on the type of record */
static uint16_t mdns_get_len(uint16_t qtype, char *rdata)
{
    uint16_t len = 0;
    switch(qtype)
    {
        case PICO_DNS_TYPE_A:
            len = PICO_SIZE_IP4;
            break;
#ifdef PICO_SUPPORT_IPV6
        case PICO_DNS_TYPE_AAAA:
            len = PICO_SIZE_IP6;
            break;
#endif
        case PICO_DNS_TYPE_PTR:
            len = (uint16_t)(strlen(rdata) + 1u);     /* +1 for null termination */
            break;
    }
    return len;
}

/* Create an mdns answer */
static struct pico_dns_header *pico_mdns_create_answer(char *url, unsigned int *len, uint16_t qtype, void *_rdata)
{
    /* mDNS headers are just the same as plain legacy DNS headers */
    struct pico_dns_header *header = NULL;
    
    /* string of the name requested in the question,
     MARK: SHOULD be called 'rname' */
    char *domain = NULL;
    
    uint8_t *answer = NULL;                         // Complete answer packet
    struct pico_dns_answer_suffix *asuffix = NULL;  // Resource Record Suffix
    
    /* RFC:
     *  the recommended TTL value for Multicast DNS
     *  resource records with a host name as the resource record’s name
     *  (e.g., A, AAAA, HINFO) or a host name contained within the resource
     *  record’s rdata (e.g., SRV, reverse mapping PTR record) SHOULD be 120
     *  seconds.
     */
    uint32_t ttl = 120;             // Default TTL
    uint16_t slen, datalen;         // Temporary storage
    char *rdata = (char*)_rdata;    // Resource Record Data
    
    /* Determine the length of rdata depending on the type of record it contains */
    datalen = mdns_get_len(qtype, rdata);
    if (!datalen) {
        mdns_dbg("Could not determine length of rdata!\n");
        return NULL;
    }
    
    /* Get length + 2 for .-prefix en trailing zero-byte */
    slen = (uint16_t)(pico_dns_client_strlen(url) + 2u);
    
    /* Determine the complete length of the answer packet including DNS Header Section and Answer Section */
    *len = (unsigned int)(sizeof(struct pico_dns_header) + slen + sizeof(struct pico_dns_answer_suffix) + datalen);
    
    /* Provide space for the DNS packet */
    header = PICO_ZALLOC(*len);
    if(!header) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Put the pointer 'domain' @ the rname-field & fill in the field */
    domain = (char *)header + sizeof(struct pico_dns_header);
    memcpy(domain + 1u, url, strlen(url));
    
    /* Put the pointer 'asuffix' @ the answer record suffix */
    asuffix = (struct pico_dns_answer_suffix *)(domain + slen);
    
    /* Put the pointer 'answer' @ the rdata-field and fill in the fild */
    answer = ((uint8_t *)asuffix + sizeof(struct pico_dns_answer_suffix));
    memcpy(answer, rdata, datalen);
    
    /* Fill the Header Section */
    pico_mdns_fill_packet_header(header, 0, 1, 0, 0); /* 0 questions, 1 answer */
    
    /* Change www.google.com to 3www6google3com0 */
    pico_dns_name_to_dns_notation(domain);
    
    /* Fill in the answer record suffix accorrding to the DNS format */
    pico_dns_fill_rr_suffix(asuffix, qtype, PICO_DNS_CLASS_IN, ttl, datalen);
    
    return header;
}

// MARK: CACHE UTILITIES

static int pico_mdns_cache_del_rr(char *url, uint16_t qtype, char *rdata)
{
    struct pico_mdns_cache_rr test, *found = NULL;
    
    test.suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    if(!test.suf)
        return -1;
    
    test.url = url;
    test.suf->qclass = PICO_DNS_CLASS_IN; /* We only support IN */
    test.suf->qtype = qtype;
    test.rdata = rdata;
    
    found = pico_tree_findKey(&CacheTable, &test);
    PICO_FREE(test.suf);
    
    if(!found) {
        mdns_dbg("Couldn't find cache RR to delete\n");
        return -1;
    }
    
    mdns_dbg("Removing RR: qtype '%d' url '%s'\n", qtype, url);
    
    pico_tree_delete(&CacheTable, found);
    PICO_FREE(found->url);
    PICO_FREE(found->suf);
    PICO_FREE(found->rdata);
    PICO_FREE(found);
    return 0;
}

static void pico_mdns_cache_tick(pico_time now, void *_arg)
{
    struct pico_mdns_cache_rr *rr = (struct pico_mdns_cache_rr *)_arg;
    IGNORE_PARAMETER(now);
    
    rr->suf->ttl--;
    mdns_dbg("TTL UPDATE: '%s' - qtype: %d - TTL: %d\n", rr->url, rr->suf->qtype, rr->suf->ttl);
    if(rr->suf->ttl < 1) {
        pico_mdns_cache_del_rr(rr->url, rr->suf->qtype, rr->rdata);
    }
    else
        rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);
    
    /* TODO: continuous querying: cache refresh at 80 or 85/90/95/100 % of TTL + 2% rnd */
}

/* Look for a RR in cache matching hostname and qtype */
static struct pico_mdns_cache_rr *pico_mdns_cache_find_rr(const char *url, uint16_t qtype)
{
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_dns_answer_suffix *suf = NULL;
    struct pico_mdns_cache_rr test;
    char temp[256] = { 0 };
    
    suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    if(!suf)
        return NULL;
    test.suf = suf;
    suf->qtype = qtype;
    
    strcpy(temp+1, url);
    pico_to_lowercase(temp);
    test.url = temp;
    pico_dns_name_to_dns_notation(test.url);
    
    mdns_dbg("Looking for '%s' with qtype '%d' in cache\n", url, qtype);
    
    rr = pico_tree_findKey(&CacheTable, &test);
    PICO_FREE(suf);
    return rr;
}

static int pico_mdns_cache_add_rr(char *url, struct pico_dns_answer_suffix *suf, char *rdata)
{
    struct pico_mdns_cache_rr *rr = NULL, *found = NULL;
    struct pico_dns_answer_suffix *rr_suf = NULL;
    char *rr_url = NULL;
    char *rr_rdata = NULL;
    
    if(!url || !suf || !rdata)
        return -1;
    
    /* Don't cache PTR answers */
    if(short_be(suf->qtype) == PICO_DNS_TYPE_PTR ) {
        mdns_dbg("Not caching PTR answer\n");
        return 0;
    }
    
    rr = PICO_ZALLOC(sizeof(struct pico_mdns_cache_rr));
    rr_suf = PICO_ZALLOC(sizeof(struct pico_dns_answer_suffix));
    rr_url = PICO_ZALLOC(strlen(url)+1);
    rr_rdata = PICO_ZALLOC(short_be(suf->rdlength));
    
    if(!rr || !rr_suf || !rr_url || !rr_rdata) {
        PICO_FREE(rr);
        PICO_FREE(rr_suf);
        PICO_FREE(rr_url);
        PICO_FREE(rr_rdata);
        return -1;
    }
    
    memcpy(rr_url+1, url, strlen(url));
    rr->url = rr_url;
    pico_dns_name_to_dns_notation(rr->url);
    memcpy(rr_suf, suf, sizeof(struct pico_dns_answer_suffix));
    rr->suf = rr_suf;
    rr->suf->qtype = short_be(rr->suf->qtype);
    rr->suf->qclass = short_be(rr->suf->qclass);
    rr->suf->ttl = long_be(suf->ttl);
    rr->suf->rdlength = short_be(suf->rdlength);
    memcpy(rr_rdata, rdata, rr->suf->rdlength);
    rr->rdata = rr_rdata;
    
    found = pico_mdns_cache_find_rr(url, rr->suf->qtype);
    if(found) {
        if(rr->suf->ttl > 0) {
            mdns_dbg("RR already in cache, updating TTL (was %ds now %ds)\n", found->suf->ttl, rr->suf->ttl);
            found->suf->ttl = rr->suf->ttl;
        }
        else {
            mdns_dbg("RR scheduled for deletion\n");
            found->suf->ttl = 1;  /* TTL 0 means delete from cache but we need to wait one second */
        }
    }
    else {
        if(rr->suf->ttl > 0) {
            pico_tree_insert(&CacheTable, rr);
            mdns_dbg("RR cached. Starting TTL counter, TICK TACK TICK TACK..\n");
            rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);
            return 0;
        }
        else {
            mdns_dbg("RR not in cache but TTL = 0\n");
        }
    }
    PICO_FREE(rr->suf);
    PICO_FREE(rr->url);
    PICO_FREE(rr->rdata);
    PICO_FREE(rr);
    return 0;
}


/* Callback for the timeout timer of a query cookie */
static void pico_mdns_timeout(pico_time now, void *_arg)
{
    /* Query cookie is passed in the arg pointer */
    struct pico_mdns_cookie *ck = (struct pico_mdns_cookie *)_arg;
    
    char url[256] = { 0 };  //
    IGNORE_PARAMETER(now);  //
    
    if(ck->callback)
        ck->callback(NULL, ck->arg);
    
    strcpy(url, ck->qname);
    
    pico_dns_notation_to_name(url);
    pico_mdns_del_cookie(url+1, ck->qtype);
    
    /* TODO: If the request was for a reconfirmation of a record, flush the corresponding record after the timeout */
}

// MARK: COOKIE UTILITIES

/* **************************************************************************
 *
 * Create an URL in *[url_addr] from any qname given in [qname]. [url_addr]
 * needs to be an addres to a NULL-pointer. *[url_addr] will be allocated 
 * 1 byte smaller in size than [qname] or 2 bytes smaller than the
 * string-length. Use PICO_FREE() to deallocate the memory for this pointer.
 *
 * f.e. *  4tass5local0 -> tass.local
 *      *  11112102107in-addr4arpa0 -> 1.1.10.10.in-addr.arpa
 *
 * **************************************************************************/
static int pico_mdns_qname_to_url( const char *qname, char **url_addr )
{
    char *temp = NULL;  // Temporary string
    
    /* Check if qname or url_addr is not a NULL-pointer */
    if (!qname || !url_addr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Check if qname is a NULL-pointer */
    if (!*url_addr) {
        /* Provide space for the url */
        *url_addr = PICO_ZALLOC(strlen(qname) - 2u);
        if (!*url_addr) {
            pico_err = PICO_ERR_ENOMEM;
            return - 1;
        }
    }
    else {
        mdns_dbg("Provide an address to a NULL pointer for [qname_addr].\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Provide space for a temporary string to work with */
    temp = PICO_ZALLOC(strlen(qname) + 1u);
    if (!temp) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    
    /* Convert qname to an URL*/
    strcpy(temp, qname);
    pico_dns_notation_to_name(temp);
    strcpy(*url_addr, temp + 1);
    
    /* We don't need temp anymore, free memory */
    PICO_FREE(temp);
    
    return 0;
}

/* **************************************************************************
 *
 * Create a qname in *[qname_addr] from any url given in [url]. [qname_addr]
 * needs to be an address to a NULL-pointer. *[qname_addr] will be allocated 
 * 1 byte larger in size than [url] or 2 bytes larger than the
 * string-length. use PICO_FREE() to deallocate the memory for this pointer.
 *
 * f.e. *  tass.local -> 4tass5local0
 *      *  1.1.10.10.in-addr.arpa -> 11112102107in-addr4arpa0
 *
 * **************************************************************************/
static int pico_mdns_url_to_qname( const char *url, char **qname_addr )
{
    /* Check if url or qname_addr is not a NULL-pointer */
    if (!url || !qname_addr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Check if qname is a NULL-pointer */
    if (!*qname_addr) {
        /* Provide space for the qname */
        *qname_addr = PICO_ZALLOC(strlen(url) + 2u);
        if (!*qname_addr) {
            pico_err = PICO_ERR_ENOMEM;
            return - 1;
        }
    }
    else {
        mdns_dbg("Provide an address to a NULL pointer for [qname_addr].\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Copy in the URL (+1 to leave space for leading '.') */
    strcpy(*qname_addr + 1, url);
    
    /* Change to DNS notation */
    pico_dns_name_to_dns_notation(*qname_addr);
    
    return 0;
}

/* **************************************************************************
 *
 * Delets for a certain query-cookie in the global cookie-tree given an [url]
 * and [qtype]. Qclass does not apply since all we use is qclass 'IN' or 1,
 * anyway.
 *
 * **************************************************************************/
static int pico_mdns_del_cookie( char *url, uint16_t qtype )
{
    /* First, find the cookie in the global tree */
    struct pico_mdns_cookie *found = pico_mdns_find_cookie(url, qtype);
    if (!found) {
        mdns_dbg("Could not find cookie '%s' to delete\n", url);
        return -1;
    }
    
    /* Delete and free memory for the cookie */
    pico_tree_delete(&QTable, found);
    PICO_FREE(found->header);
    PICO_FREE(found);
    
    mdns_dbg("Cookie deleted succesfully!\n");
    
    return 0;
}

/* **************************************************************************
 *
 * Looks for a certain query-cookie in the global cookie-tree given an [url]
 * and [qtype]. Qclass does not apply since all we use is qclass 'IN' or 1,
 * anyway.
 *
 * **************************************************************************/
static struct pico_mdns_cookie *pico_mdns_find_cookie( const char *url, uint16_t qtype )
{
    struct pico_mdns_cookie test;           /* Create a test-cookie for the tree_findKey-function */
    struct pico_mdns_cookie *found = NULL;  /* Pointer to return */
    char *qname = NULL;                     /* String to store the FQDN*/
    
    if(!url)
        return NULL;
    
    /* Change tass.local to 4tass5local0 */
    int ret = pico_mdns_url_to_qname(url, &qname);
    if (ret) {
        mdns_dbg("Could not convert URL to FQDN!\n");
        return NULL;
    }
    
    /* Set qname & qtype of the test-cookie*/
    test.qname = qname;
    test.qtype = qtype;
    
    /* Find the cookie in the tree */
    found = pico_tree_findKey(&QTable, &test);
    
    /* Free memory */
    PICO_FREE(qname);
    
    return found;
}

/* **************************************************************************
 *
 * Creates and fills in a cookie with a certain query [dns_packet] and add it
 * to the global cookie-tree. [len] is the length of the DNS packet in bytes.
 * [flags] are the MDNS-flags given for a certain query, like probing-flag,
 * unicast-response-flags. [callback] is callback that gets called when events
 * happen, [arg] is and argument passed to the callback-function
 *
 * **************************************************************************/
static struct pico_mdns_cookie *pico_mdns_add_cookie( struct pico_dns_header *dns_packet, uint16_t len, uint8_t flags, uint8_t count, void (*callback)(char *str, void *arg), void *arg )
{
    /* Query cookie structs */
    struct pico_mdns_cookie *ck = NULL;
    struct pico_mdns_cookie *found = NULL;
    
    /* Provide space for such a cookie */
    ck = PICO_ZALLOC(sizeof(struct pico_mdns_cookie));
    if (!ck)
        return NULL;
    
    /* Fill in the form */
    ck->header = dns_packet;
    ck->len = len;
    ck->qname = (char *)dns_packet + sizeof(struct pico_dns_header);
    pico_to_lowercase(ck->qname);
    ck->qtype = short_be(*(uint16_t *)((char *)dns_packet + len - 4));
    ck->qclass =  short_be(*(uint16_t *)((char *)dns_packet + len - 2));
    ck->flags = flags;
    ck->count = count;
    ck->callback = callback;
    ck->arg = arg;
    
    /* Insert the cookie into a tree */
    found = pico_tree_insert(&QTable, ck);
    
    /* If cookie is already in tree */
    if (found) {
        pico_err = PICO_ERR_EAGAIN;
        PICO_FREE(ck);
        PICO_FREE(dns_packet);
        return NULL;
    }
    
    mdns_dbg("Cookie '%s' with qtype '%x' added to QTable\n", ck->qname, ck->qtype);
    
    /* RFC:
     *  When no response is received within ten seconds, then, even though
     *  its TTL may indicate that it is not yet due to expire, that record
     *  SHOULD be promptly flushed from cache.
     */
    if(IS_PROBE_FLAG_SET(flags))
        ck->timer = pico_timer_add(PICO_MDNS_QUERY_TIMEOUT, pico_mdns_timeout, ck);
    
    return ck;
}

#ifdef PICO_SUPPORT_IPV6
static struct pico_ip6 *pico_get_ip6_from_ip4(struct pico_ip4 *ipv4_addr)
{
    struct pico_device *dev = NULL;
    struct pico_ipv6_link *link = NULL;
    if((dev = pico_ipv4_link_find(ipv4_addr)) == NULL) {
        mdns_dbg("Could not find device!\n");
        return NULL;
    }
    
    if((link = pico_ipv6_link_by_dev(dev)) == NULL) {
        mdns_dbg("Could not find link!\n");
        return NULL;
    }
    
    return &link->address;
}
#endif

// MARK: ASYNCHRONOUS MDNS RECEPTION

/* handle a single incoming answer */
static int pico_mdns_handle_answer(char *url, struct pico_dns_answer_suffix *suf, char *data)
{
    struct pico_mdns_cookie *ck = NULL;     // Temporary storage of query cookie
    
    /* Remove cache flush bit if set MARK: But why? */
    suf->qclass &= short_be((uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);
    
    /* Print some context */
    mdns_dbg("Answer for record %s was received:\n", url);
    mdns_dbg("rrtype: %u, rrclass: %u, ttl: %lu, rdlen: %u\n", short_be(suf->qtype), short_be(suf->qclass), (unsigned long)long_be(suf->ttl), short_be(suf->rdlength));
    
    /* Add a resource record to cache */
    pico_mdns_cache_add_rr(url, suf, data);
    
    mdns_dbg("Searching for a corresponding query cookie for url: %s and qtype: %d...\n", url, short_be(suf->qtype));
    
    /* Check in the query tree whether a request was sent to elicit this answer */
    ck = pico_mdns_find_cookie(url, short_be(suf->qtype));
    if(!ck) {
        /* MARK: Of course no cookie will be found if the responder doesn't sent the same qtype with probes*/
        mdns_dbg("Found NO corresponding cookie!\n");
        return 0;
    }
    
    mdns_dbg("Found a corresponding cookie!\n");
    
    /* if we are probing, set probe to zero so the probe timer stops the next time it goes off */
    if (IS_PROBE_FLAG_SET(ck->flags)) {
        mdns_dbg("Probe set to zero\n");
        ck->flags &= PICO_MDNS_FLAG_NO_PROBE;
        return 0;
    }
    
    /* If this was aan API request return answer passed in callback */
    if(short_be(suf->qtype) == PICO_DNS_TYPE_A) {
        uint32_t rdata = long_from(data);
        char peer_addr[46];
        pico_ipv4_to_string(peer_addr, long_from(&rdata));
        ck->callback(peer_addr, ck->arg);
    }
    
#ifdef PICO_SUPPORT_IPV6
    else if(short_be(suf->qtype) == PICO_DNS_TYPE_AAAA) {
        uint8_t *rdata = (uint8_t *) data;
        char peer_addr[46];
        pico_ipv6_to_string(peer_addr, rdata);
        ck->callback(peer_addr, ck->arg);
    }
#endif
    else if(short_be(suf->qtype) == PICO_DNS_TYPE_PTR) {
        pico_dns_notation_to_name(data);
        ck->callback(data + 1, ck->arg);    /* +1 to discard the beginning dot */
    } else {
        mdns_dbg("Unrecognised record type\n");
        ck->callback(NULL, ck->arg);
    }
    
    /* Remove the timer from the cookie and delete it */
    pico_timer_cancel(ck->timer);
    pico_mdns_del_cookie(url, ck->qtype);
    
    return 0;
}

/* Create a query answer according to the qtype (ANY, A, AAAA or PTR) of a certain IP address */
static struct pico_dns_header *pico_mdns_query_create_answer(union pico_address *local_addr, uint16_t qtype, unsigned int *len, char *name)
{
    // TODO: If type is ANY include all records corresponding to the name
    // TODO: Include negative responses for records this hosts knows they don't exist
    
    if(qtype == PICO_DNS_TYPE_A || qtype == PICO_DNS_TYPE_ANY) {
        return pico_mdns_create_answer(mdns_global_host, len, PICO_DNS_TYPE_A, local_addr);
    }
#ifdef PICO_SUPPORT_IPV6
    if(qtype == PICO_DNS_TYPE_AAAA || qtype == PICO_DNS_TYPE_ANY) {
        struct pico_ip6 *ip6 = pico_get_ip6_from_ip4(&local_addr->ip4);
        return pico_mdns_create_answer(mdns_global_host, len, PICO_DNS_TYPE_AAAA, ip6);
    }
#endif
    /* reply to PTR records */
    if(qtype == PICO_DNS_TYPE_PTR) {
        char host_conv[255] = { 0 };
        mdns_dbg("Replying on PTR query...\n");
        strcpy(host_conv + 1, mdns_global_host);
        pico_dns_name_to_dns_notation(host_conv);
        return pico_mdns_create_answer(name, len, qtype, host_conv);
    }
    
    mdns_dbg("Unknown qtype!\n");
    
    return NULL;
}

/* Reply on a single query */
static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer, char *name)
{
    /* Pointer to DNS packet */
    struct pico_dns_header *header = NULL;
    
    /* To store either an IPv4 or an IPv6 */
    union pico_address *local_addr = NULL;
    
    unsigned int len; // Temporary storage of the length of the reply
    
    // TODO: Check for authority sections / probing queries
    // TODO: Check for unicast response bit
    
    /* RFC:
     *  If a responder receives a query addressed to the mDNS IPv4 link-local multicast address,
     *  from a source address not apparently on the same subnet as the
     *  responder, then, even if the query indicates that a unicast
     *  response is preferred, the responder SHOULD elect to respond by multicast
     *  anyway, since it can reasonably predict that a unicast response with
     *  an apparently non-local source address will probably be ignored.
     */
    local_addr = (union pico_address *) pico_ipv4_source_find(&peer);
    if (!local_addr) {
        // TODO: Forced Response via multicast
        pico_err = PICO_ERR_EHOSTUNREACH;
        mdns_dbg("Peer not on same subnet!\n");
        return -1;
    }

    /* Creates an answer for the host's IP, depending on the qtype */
    // MARK: MUST contain all records for qtype ANY
    header = pico_mdns_query_create_answer(local_addr, qtype, &len, name);
    if (!header) {
        mdns_dbg("Error occured while creating an answer (pico_err:%d)!\n", pico_err);
        return -1;
    }
    
    /* Send a response on the wire */
    if(pico_mdns_send_packet(header, len) != (int)len) {
        mdns_dbg("Send error occurred!\n");
        return -1;
    }
    
    return 0;
}


/* Compare if the received query name is the same as the name currently assigned to this host */
static int pico_check_query_name(char *url)
{
    char addr[29] = { 0 };
    
    /* Check if query is a normal query for this hostname*/
    if(strcmp(url, mdns_global_host) == 0)
        return 1;
    
    /* Convert 192.168.1.1 decimal to '192.168.1.1'-string */
    pico_ipv4_to_string(addr, mdns_sock->local_addr.ip4.addr);
    
    /* Mirror 192.168.1.1 to 1.1.168.192 */
    pico_dns_mirror_addr(addr);
    
    /* Add a arpa-suffix */
    memcpy(addr + strlen(addr), ".in-addr.arpa", 13);
    
    /* Check if request name is reverse query for this hostname */
    if(strcmp(url, addr) == 0)
        return 1;
    
    return 0;
}

/* Handle a single incoming query */
static int pico_mdns_handle_query(char *name, struct pico_dns_query_suffix *suf, struct pico_ip4 peer)
{
    struct pico_mdns_cookie *ck = NULL; // Temporary storage of query cookie
    
    /* Remove cache flush bit if set MARK: but why? */
    suf->qclass &= short_be((uint16_t) ~PICO_MDNS_CACHE_FLUSH_BIT);
    
    mdns_dbg("Query type: %u, class: %u\n", short_be(suf->qtype), short_be(suf->qclass));
    
    /* Check if host has assigned itself a name already */
    if(mdns_global_host) {
        
        /* Check if queried name is the same as currently assigned name */
        // TODO: Check for all the records with that name and for wich this host has authority (Not only A and PTR)
        if(pico_check_query_name(name)) {
            /* Query is either a normal query or a reverse resolution query for this host */
            pico_mdns_reply_query(short_be(suf->qtype), peer, name);
        } else {
            /* Query is not meant for this host */
            /* TODO: Passive Observation Of Failures (POOF) */
            mdns_dbg("Received request for unknown hostname %s (my hostname: %s)\n", name, mdns_global_host);
        }
    } else {
        /* Find a corresponding query currently being queried */
        ck = pico_mdns_find_cookie(name, short_be(suf->qtype));
        if(ck && ck->count < 3) {
            /* TODO: Simultaneous Probe Tiebreaking */
        } else {
            mdns_dbg("Received query before init\n");
        }
    }
    
    return 0;
}

/* Parses an incoming packet */
static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer)
{
    /* Point to the DNS packet in the buffer */
    struct pico_dns_header *header = (struct pico_dns_header *) buf;
    
    /* Point to right after the header */
    char *ptr = (char *)header + sizeof(struct pico_dns_header);
    
    /* Depending on the header, we need to provide a query or answer struct */
    struct pico_dns_query_suffix *qsuf;
    struct pico_dns_answer_suffix *asuf;
    
    /* Count of questions and answers in the packet */
    uint16_t i, qcount, acount;
    
    /* Pointer to the data field of the questions or answers */
    char *data;
    
    /* Determine the count of questions and answers */
    // TODO: Authority Count and Additional count should be implemented
    qcount = short_be(header->qdcount);
    acount = short_be(header->ancount);
    mdns_dbg("\n>>>>>>> QDcount: %u, ANcount: %u\n", qcount, acount);
    if(qcount == 0 && acount == 0) {
        mdns_dbg("Query and answer count is 0!\n");
        return -1;
    }
    
    /* Handle queries */
    for(i = 0; i < qcount; i++) {
        /* Point to the qtype & qclass fields */
        qsuf = (struct pico_dns_query_suffix*) (ptr + pico_mdns_namelen_comp(ptr) + 1);
        
        /* Convert 3www6google3com0 to .www.google.com */
        pico_dns_notation_to_name(ptr);
        if (!ptr)
            return -1;
        
        /* Handle the query accordingly (+1 to skip the first '.') */
        pico_mdns_handle_query(ptr + 1, qsuf, peer);
        
        /* Point to the next question */
        ptr = (char *)qsuf + sizeof(struct pico_dns_query_suffix);
        if(ptr - (char *)header > buflen) {
            mdns_dbg("buffer is too short! ptr offset=%d buflen=%d\n", ptr - (char*)header, buflen);
            return -1;
        }
    }
    
    /* Handle answers */
    for(i = 0; i < acount; i++) {
        char *name;
        
        /* Point to the suffix of the answer contain in the answer section */
        asuf = (struct pico_dns_answer_suffix*) (ptr + pico_mdns_namelen_comp(ptr) + 1);
        
        /* Get the uncompressed name of the possibly compressed name contained in de rrname-field */
        if((name = pico_mdns_expand_name_comp(ptr, buf)) == NULL) {
            mdns_dbg("Received a zero name pointer\n");
            return -1;
        }
        
        /* Point to the data-field of the answer contained in the answer section */
        data = (char *)asuf + sizeof(struct pico_dns_answer_suffix);
        
        /* Handle the answer accordingly (+1 to skip the first '.') */
        pico_mdns_handle_answer(name + 1, asuf, data);
        
        /* Free memory */
        PICO_FREE(name);
        
        /* Move to the next answer */
        ptr = data + short_be(asuf->rdlength);
        if(ptr - (char *)header > buflen) {
            mdns_dbg("buffer is too short! ptr offset=%d buflen=%d\n", ptr - (char*)header, buflen);
            return -1;
        }
    }
    
    return 0;
}

/* Callback for UDP socket events */
// MARK: SHOULD be called 'pico_mdns_event'
static void pico_mdns_wakeup(uint16_t ev, struct pico_socket *s)
{
    // MARK: Why MTU 1400 and not 1500?
    char recvbuf[1400];
    
    int pico_read = 0;
    struct pico_ip4 peer = { 0 };
    uint16_t port = 0;
    char host[30];
    
    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        mdns_dbg("READ EVENT!\n");
        /* Receive while data is available in socket buffer */
        while((pico_read = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port)) > 0) {
            /* If pico_socket_setoption is implemented, this check is not needed */
            pico_ipv4_to_string(host, peer.addr);
            mdns_dbg("Received data from %s:%u\n", host, short_be(port));
            /* Handle the MDNS data received */
            pico_mdns_recv(recvbuf, pico_read, peer);
        }
    }
    /* Socket is closed */
    else if(ev == PICO_SOCK_EV_CLOSE) {
        mdns_dbg("Socket is closed. Bailing out.\n");
        return;
    }
    /* Process error event, socket error occured */
    else if(ev == PICO_SOCK_EV_ERR) {
        mdns_dbg("Socket Error received. Bailing out.\n");
        return;
    }
}

// MARK: CACHE FUNCTIONS

int pico_mdns_flush_cache(void)
{
    struct pico_mdns_cache_rr *rr = NULL;
    struct pico_tree_node *index = NULL;
    
    mdns_dbg("Flushing mDNS RR cache\n");
    pico_tree_foreach(index, &CacheTable) {
        rr = index->keyValue;
        mdns_dbg("Deleting '%s' (%d)\n", rr->url, rr->suf->qtype);
        pico_tree_delete(&CacheTable, rr);
        pico_timer_cancel(rr->timer);
        PICO_FREE(rr->url);
        PICO_FREE(rr->suf);
        PICO_FREE(rr->rdata);
        PICO_FREE(rr);
    }
    return 0;
}

// MARK: ADDRESS RESOLUTION

static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    if(!mdns_sock) {
        mdns_dbg("mDNS socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }
    
    //header = pico_mdns_create_query(url, &len, proto, PICO_DNS_TYPE_PTR, PICO_MDNS_FLAG_NO_PROBE);
    if(!header || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }
    
    if(pico_mdns_send_packet(header, len) != (int)len) {
        mdns_dbg("Send error!\n");
        return -1;
    }
    
    return 0;
}

static int pico_mdns_getname_generic(const char *ip, void (*callback)(char *url, void *arg), void *arg, uint16_t proto)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    if (!ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    if(!mdns_sock) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }
    
    //header = pico_mdns_create_query(ip, &len, proto, PICO_DNS_TYPE_PTR, PICO_MDNS_FLAG_NO_PROBE);
    if(!header || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }
    
    if(pico_mdns_send_packet(header, len) != (int)len) {
        mdns_dbg("Send error!\n");
        return -1;
    }
    
    return 0;
}

int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    struct pico_mdns_cache_rr *rr = NULL;
    char addr[46];
    rr = pico_mdns_cache_find_rr(url, PICO_DNS_TYPE_A);
    
    if(rr && rr->rdata) {
        pico_ipv4_to_string(addr, long_from(rr->rdata));
        mdns_dbg("Cache hit! Found A record for '%s' with addr '%s'\n", url, addr);
        callback(addr, arg);
        return 0;
    }
    else {
        mdns_dbg("Cache miss for A record - url '%s'\n", url);
        return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV4);
    }
}

int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV4);
}

#ifdef PICO_SUPPORT_IPV6
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg)
{
    struct pico_mdns_cache_rr *rr = NULL;
    char addr[46];
    rr = pico_mdns_cache_find_rr(url, PICO_DNS_TYPE_AAAA);
    
    if(rr && rr->rdata) {
        pico_ipv6_to_string(addr, (uint8_t *)rr->rdata);
        mdns_dbg("Cache hit! Found AAAA record for '%s' with addr '%s'\n", url, addr);
        callback(addr, arg);
        return 0;
    }
    else {
        mdns_dbg("Cache miss for AAAA record - url '%s'\n", url);
        return pico_mdns_getaddr_generic(url, callback, arg, PICO_PROTO_IPV6);
    }
}

int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV6);
}
#endif

// MARK: ANNOUNCEMENT

/* Utility function to send an announcement on the wire */
static int pico_mdns_send_packet_announcement(void)
{
    /* mDNS headers are just the same as plain legacy DNS headers */
    struct pico_dns_header *header = NULL;
    
    unsigned int len = 0;   // Temporary storage of packet length
    
    /* If global hostname isn't set */
    if(!mdns_global_host)
        return -1;
    
    /* Create an mDNS answer */
    header = pico_mdns_create_answer(mdns_global_host, &len, PICO_DNS_TYPE_A, &mdns_sock->local_addr);
    if(!header) {
        mdns_dbg("Could not create answer header!\n");
        return -1;
    }
    
    /* Send the mDNS answer unsollicited via multicast */
    if(pico_mdns_send_packet(header, len) != (int)len) {
        mdns_dbg("send error occured!\n");
        return -1;
    }
    
    return 0;
}

/* Callback function for the announcement timer */
static void pico_mdns_announce_timer(pico_time now, void *arg)
{
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(arg);
    
    /* Send a second unsollicited announcement */
    pico_mdns_send_packet_announcement();
}

/* announce the local hostname to the network */
static int pico_mdns_announce(void)
{
    /* Send a first unsollicited announcement */
    if (pico_mdns_send_packet_announcement() < 0)
        return -1;
    
    /* RFC:
     *  The Multicast DNS responder MUST send at least two unsolicited
     *  responses, one second apart.
     */
    pico_timer_add(1000, pico_mdns_announce_timer, NULL);
    
    return 0;
}

// MARK: PROBING

/* Callback function for the probe timer */
static void pico_mdns_probe_timer(pico_time now, void *arg)
{
    if(!arg) return;
    
    /* Cast the argument given in [arg] to a mDNS-cookie */
    struct pico_mdns_cookie *ck = (struct pico_mdns_cookie *) arg;
    char ok[] = "OK";
    char temp[255] = { 0 };
    
    IGNORE_PARAMETER(now);
    
    if(!ck) {
        mdns_dbg("Cookie does not exist! This shouldn't happen\n");
        return;
    }

    /* If probe flag is reset */
    if(!IS_PROBE_FLAG_SET(ck->flags)) {
        mdns_dbg("Hostname already in use!\n");
        ck->callback(NULL, ck->arg);
        return;
    }
    
    /* After 3 successful probing attempts */
    if(ck->count == 0) {
        mdns_global_host = PICO_ZALLOC(strlen(ck->qname) - 1);
        if (!mdns_global_host) {
            pico_err = PICO_ERR_ENOMEM;
            return;
        }
        strcpy(temp, ck->qname);
        pico_dns_notation_to_name(temp);
        strcpy(mdns_global_host, temp + 1);
        mdns_dbg("Count is zero! Claimed %s\n", mdns_global_host);
        pico_mdns_announce();
    
        ck->callback(ok, ck->arg);
        
        /* Create an URL from qname and delete a cookie for that URL */
        char *url = NULL;
        pico_mdns_qname_to_url(ck->qname, &url);
        pico_mdns_del_cookie(url, ck->qtype);
        PICO_FREE(url);
        
        return;
    }
    
    /* Send Probing query */
    if(pico_mdns_send_packet(ck->header, ck->len) != (int)ck->len) {
        mdns_dbg("Send error occurred!\n");
        PICO_FREE(arg);
        ck->callback(NULL, ck->arg);
        return;
    }
    
    mdns_dbg("Probed!\n");
    
    /* Decrement probe count */
    ck->count--;
    
    /* Schedule the next probe after 250 ms */
    pico_timer_add(250, pico_mdns_probe_timer, ck);
}

/* Checks whether the given name is in use */
static int pico_mdns_probe(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg)
{
    struct pico_dns_header *packet = NULL;  /* mDNS headers are just the same as plain legacy DNS headers */
    struct pico_mdns_cookie *cookie = NULL; /* Query cookie to pass to the time callback */
    uint16_t qlen = 0;                      /* Temporary storage of question length */
    uint16_t len = 0;                       /* Temporary storage of packet length */
    
    /* RFC:
     *  Probe querys SHOULD be sent with as "QU" questions with the unicast-response bit set.
     *  To a defending host to respond immediately via unicast, instead of potentially
     *  having to wait before replying via multicast.
     */
    struct pico_dns_question *probe_question = pico_mdns_dns_create_question(hostname, &qlen, PICO_PROTO_IPV4, PICO_DNS_TYPE_ANY, (PICO_MDNS_FLAG_PROBE | PICO_MDNS_FLAG_UNICAST_RES));
    
    /* Fill a DNS packet with the probe question */
    packet = pico_mdns_dns_fill_query(probe_question, &len);
    if (!packet || !len) {
        mdns_dbg("ERROR: mdns_create_query returned NULL\n");
        return -1;
    }
    
    /* Add a cookie to the global tree so we don't have to create the query everytime */
    cookie = pico_mdns_add_cookie(packet, len, (PICO_MDNS_FLAG_PROBE | PICO_MDNS_FLAG_UNICAST_RES), 3, cb_initialised, arg);
    if (!cookie) {
        mdns_dbg("ERROR: mdns_add_cookie returned NULL\n");
        return 1;
    }
    
    /* RFC:
     *  When the host is ready to send his probe query he SHOULD delay it's
     *  transmission with a randomly chosen time between 0 and 250 ms.
     */
    pico_timer_add(pico_rand() % 250, pico_mdns_probe_timer, cookie);
    
    return 0;
}

/* Opens the socket, probes for the usename and calls back the user when a host name is set up */
int pico_mdns_init(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg)
{
    /* Request struct for multicast socket */
    struct pico_ip_mreq mreq;
    
    uint16_t proto = PICO_PROTO_IPV4, port;
    
    int loop = 0;   // LOOPBACK = 0
    int ttl = 255;  // IP TTL SHOULD = 255
    
    /* Check hostname parameter */
    if(!hostname) {
        mdns_dbg("No hostname given!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Check callbcak parameter */
    if(!cb_initialised) {
        mdns_dbg("No callback function suplied!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Open global mDNS socket */
    mdns_sock = pico_socket_open(proto, PICO_PROTO_UDP, &pico_mdns_wakeup);
    if(!mdns_sock) {
        mdns_dbg("Open returned empty socket\n");
        return -1;
    }
    
    /* Set multicast group-address to 224.0.0.251 IPv4 */
    if(pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &mreq.mcast_group_addr.addr) != 0) {
        mdns_dbg("String to ipv4 error\n");
        return -1;
    }
    
    /* Receive data on any network interface */
    mreq.mcast_link_addr = inaddr_any;
    
    /* Don't want the multicast data to be looped back to the host */
    if(pico_socket_setoption(mdns_sock, PICO_IP_MULTICAST_LOOP, &loop) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_LOOP failed\n");
        return -1;
    }
    
    /* Tell the kernel we're interested in this particular multicast group */
    if(pico_socket_setoption(mdns_sock, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
        mdns_dbg("socket_setoption PICO_IP_ADD_MEMBERSHIP failed\n");
        return -1;
    }
    
    /* RFC:
     *  All multicast responses (including answers sent via unicast) SHOULD
     *  be send with IP TTL set to 255 for backward-compatibility reasons
     */
    if(pico_socket_setoption(mdns_sock, PICO_IP_MULTICAST_TTL, &ttl) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_TTL failed\n");
        return -1;
    }
    
    /* RFC:
     *  fully compliant mDNS Querier MUST send its Multicast DNS queries from
     *  UDP source port 5353, and MUST listen for Multicast DNS replies sent
     *  to UDP destination port 5353 at the mDNS link-local multicast address
     *  (224.0.0.251 and/or its IPv6 equivalent FF02::FB)
     */
    port = short_be(mdns_port);
    if (pico_socket_bind(mdns_sock, &inaddr_any, &port) != 0) {
        mdns_dbg("Bind error!\n");
        return -1;
    }
    
    if(pico_mdns_probe(hostname, cb_initialised, arg) != 0) {
        mdns_dbg("Probe error\n");
        return -1;
    }
    
    return 0;
}

#endif /* PICO_SUPPORT_MDNS */
