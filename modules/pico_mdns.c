/*********************************************************************
   PicoTCP. Copyright (c) 2014-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Toon Stegen, Jelle De Vleeschouwer
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_mdns.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

/* --- Debugging --- */
#define DEBUG 0

#if DEBUG == 0
#define mdns_dbg(...) do {} while(0)
#else
#define mdns_dbg dbg
#endif

#define PICO_MDNS_QUERY_TIMEOUT (10000) /* Ten seconds */
#define PICO_MDNS_RR_TTL_TICK (1000)    /* One second */

/* mDNS MTU size */
#define PICO_MDNS_MTU 1400u

/* Cookie flags */
#define PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT 0x01u
#define PICO_MDNS_COOKIE_TYPE_ANSWER 0x02u
#define PICO_MDNS_COOKIE_TYPE_QUERY 0x04u
#define PICO_MDNS_COOKIE_TYPE_PROBE 0x08u
/* Cookie status */
#define PICO_MDNS_COOKIE_STATUS_ACTIVE 0xffu
#define PICO_MDNS_COOKIE_STATUS_INACTIVE 0x00u
#define PICO_MDNS_COOKIE_STATUS_CANCELLED 0x77u

/* Question flags */
#define PICO_MDNS_QUESTION_FLAG_PROBE 0x01u
#define PICO_MDNS_QUESTION_FLAG_NO_PROBE 0x00u
#define PICO_MDNS_QUESTION_FLAG_UNICAST_RES 0x02u
#define PICO_MDNS_QUESTION_FLAG_MULTICAST_RES 0x00u

#define IS_QUESTION_PROBE_FLAG_SET(x) \
(((x) & PICO_MDNS_QUESTION_FLAG_PROBE) ? 1 : 0 )
#define IS_QUESTION_UNICAST_FLAG_SET(x) \
(((x) & PICO_MDNS_QUESTION_FLAG_UNICAST_RES) ? 1 : 0 )
#define IS_QUESTION_MULTICAST_FLAG_SET(x) \
(((x) & PICO_MDNS_QUESTION_FLAG_UNICAST_RES) ? 0 : 1 )

/* Resource Record flags */
#define PICO_MDNS_RECORD_HOSTNAME 0x02u
#define PICO_MDNS_RECORD_ADDITIONAL 0x08u
#define PICO_MDNS_RECORD_SEND_UNICAST 0x10u
#define PICO_MDNS_RECORD_CURRENTLY_PROBING 0x20u
#define PICO_MDNS_RECORD_PROBED 0x40u
#define PICO_MDNS_RECORD_CLAIMED 0x80u

#define IS_RES_RECORD_FLAG_CLAIM_SHARED_SET(x) \
(((x) & PICO_MDNS_RECORD_SHARED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_CLAIM_UNIQUE_SET(x) \
(((x) & PICO_MDNS_RECORD_SHARED) ? 0 : 1)
#define IS_RES_RECORD_FLAG_HOSTNAME_SET(x) \
(((x) & PICO_MDNS_RECORD_HOSTNAME) ? 1 : 0)
#define IS_RES_RECORD_FLAG_CURRENTLY_PROBING(x) \
(((x) & PICO_MDNS_RECORD_CURRENTLY_PROBING) ? 1 : 0)
#define IS_RES_RECORD_FLAG_PROBED_SET(x) \
(((x) & PICO_MDNS_RECORD_PROBED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_CLAIMED_SET(x) \
(((x) & PICO_MDNS_RECORD_CLAIMED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_ADDITIONAL_SET(x) \
(((x) & PICO_MDNS_RECORD_ADDITIONAL) ? 1 : 0)
#define IS_RES_RECORD_FLAG_SEND_UNICAST_SET(x) \
(((x) & PICO_MDNS_RECORD_SEND_UNICAST) ? 1 : 0)

/* Set and clear flags */
#define PICO_MDNS_SET_FLAG(x, b) (x = ((x) | (uint8_t)(b)))
#define PICO_MDNS_CLR_FLAG(x, b) (x = ((x) & (~((uint8_t)(b)))))

/* Set and clear MSB of BE short */
#define PICO_MDNS_SET_MSB_BE(x) (x = x | (uint16_t)(0x0080u))
#define PICO_MDNS_CLR_MSB_BE(x) (x = x & (uint16_t)(0xff7fu))
#define PICO_MDNS_IS_MSB_SET(x) (((x & 0x8000u) >> 15u) ? 1 : 0)

/* ****************************************************************************
 *  mDNS cookie
 * ****************************************************************************/
struct pico_mdns_cookie
{
    pico_dns_question_vector qvector;   // Question vector
    pico_mdns_record_vector rvector;    // Record vector
    uint8_t count;                      // Times to send the query
    uint8_t type;                       // QUERY/ANNOUNCE/PROBE/ANSWER
    uint8_t status;                     // Active status
    uint8_t timeout;                    // Timeout counter
    struct pico_timer *send_timer;      // For sending events
    void (*callback)(pico_mdns_record_vector *,
                     char *,
                     void *);           // Callback
    void *arg;                          // Argument to pass to callback
};

/* ****************************************************************************
 *  MARK: PROTOTYPES                                                          */
static int
pico_mdns_record_am_i_lexi_later( struct pico_mdns_record *my_record,
                                  struct pico_mdns_record *peer_record);

static struct pico_mdns_record *
pico_mdns_record_copy_with_new_name( struct pico_mdns_record *record,
                                     const char *new_rname );

static struct pico_mdns_record *
pico_mdns_record_copy( struct pico_mdns_record *record );

static int
pico_mdns_record_vector_delete( pico_mdns_record_vector *vector,
                                uint16_t index );

static int
pico_mdns_record_tree_del_url( const char *url, struct pico_tree *tree );

static int
pico_mdns_record_tree_del_record( struct pico_mdns_record *record,
                                  struct pico_tree *tree );

static int
pico_mdns_getrecord_generic( const char *url, uint16_t type,
                             void (*callback)(pico_mdns_record_vector *,
                                              char *,
                                              void *),
                             void *arg);

static void
pico_mdns_send_probe_packet( pico_time now, void *arg );

static int
pico_mdns_reclaim( pico_mdns_record_vector record_vector,
                   void (*callback)(pico_mdns_record_vector *,
                                    char *,
                                    void *),
                   void *arg );
/*  EOF PROTOTYPES
 * ****************************************************************************/

// MARK: TREES & GLOBAL VARIABLES

/* ****************************************************************************
 *  Compares two data buffers
 * ****************************************************************************/
static int
pico_mdns_rdata_cmp( uint8_t *a, uint8_t *b,
                     uint16_t rdlength_a, uint16_t rdlength_b )
{
    uint16_t i = 0;
    uint16_t longest_rdlength = 0;

    /* Check params */
    if (!a || !b) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    if (rdlength_a >= rdlength_b)
        longest_rdlength = rdlength_a;
    else
        longest_rdlength = rdlength_b;

    for (i = 0; i < longest_rdlength; i++) {
        if (i < rdlength_a && i < rdlength_b) {
            if ((uint8_t)a[i] == (uint8_t)b[i])
                continue;
            else
                return (((uint8_t)a[i] < (uint8_t)b[i]) ? -1 : 1);
        } else if (rdlength_a == rdlength_b)
            return 0;
        else if (rdlength_a == longest_rdlength)
            return 1;
        else
            return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Compares two mDNS record by name and type
 * ****************************************************************************/
static int
pico_mdns_cmp_name_type( struct pico_mdns_record *a,
                         struct pico_mdns_record *b )
{
    uint16_t a_type = 0, b_type = 0;

    /* Check params */
    if (!a || !b)
        return -2;

    if (!(a->record) || !(b->record))
        return -2;
    if (a->record && !(b->record))
        return 1;
    if (!(a->record) && b->record)
        return -1;

    if (!(a->record->rsuffix) || !(b->record->rsuffix))
        return -2;
    if (a->record->rsuffix && !(b->record->rsuffix))
        return 1;
    if (!(a->record->rsuffix) && b->record->rsuffix)
        return -1;

    a_type = short_be(a->record->rsuffix->rtype);
    b_type = short_be(b->record->rsuffix->rtype);

    /* First, compare the rrtypes */
    if(a_type < b_type)
        return -1;
    if(b_type < a_type)
        return 1;

    /* Then, compare the rrnames */
    return pico_mdns_rdata_cmp((uint8_t *)a->record->rname,
                               (uint8_t *)b->record->rname,
                               (uint16_t)strlen(a->record->rname),
                               (uint16_t)strlen(b->record->rname));
}

/* ****************************************************************************
 *  Function for comparing 2 resource records in the tree.
 * ****************************************************************************/
static int
pico_mdns_cmp( void *ka, void *kb )
{
    struct pico_mdns_record *a = NULL;
    struct pico_mdns_record *b = NULL;
    int ret = 0;

    /* Parse in the records */
    a = (struct pico_mdns_record *)ka;
    b = (struct pico_mdns_record *)kb;

    /* First compare name and type */
    ret = pico_mdns_cmp_name_type(a, b);
    if(ret)
        return ret;

    /* Finally compare rdata for unique comparising */
    return pico_mdns_rdata_cmp((uint8_t *)a->record->rdata,
                               (uint8_t *)b->record->rdata,
                               short_be(a->record->rsuffix->rdlength),
                               short_be(b->record->rsuffix->rdlength));
}

/* ****************************************************************************
 *  Function for comparing 2 cookies in the tree.
 * ****************************************************************************/
static int
pico_mdns_cookie_cmp( void *ka, void *kb )
{
    struct pico_mdns_cookie *a = NULL;
    struct pico_mdns_cookie *b = NULL;

    /* To compare questions */
    struct pico_dns_question *qa = NULL;
    struct pico_dns_question *qb = NULL;

    /* To compare records */
    struct pico_mdns_record *ra = NULL;
    struct pico_mdns_record *rb = NULL;
    int ret = 0;
    uint16_t i = 0, j = 0, a_type = 0, b_type = 0;

    /* Parse in the cookies */
    a = (struct pico_mdns_cookie *)ka;
    b = (struct pico_mdns_cookie *)kb;

    /* Start comparing the questions */

    for (i = 0, j = 0; ((i < a->qvector.count) && (j < b->qvector.count));
         i++, j++) {
        /* Get questions at current index */
        qa = pico_dns_question_vector_get(&(a->qvector), i);
        qb = pico_dns_question_vector_get(&(b->qvector), j);

        a_type = short_be(qa->qsuffix->qtype);
        b_type = short_be(qb->qsuffix->qtype);

        /* First, compare the qtypes */
        if(a_type < b_type)
            return -1;
        if(b_type < a_type)
            return 1;

        /* Then compare qnames */
        ret = pico_mdns_rdata_cmp((uint8_t *)qa->qname,
                                  (uint8_t *)qb->qname,
                                  (uint16_t)strlen(qa->qname),
                                  (uint16_t)strlen(qb->qname));

        if (ret)
            return ret;
    }

    /* All the questions currently compared are the same. Check which has the
     most questions, if they have the same amount, move on */
    if (a->qvector.count < b->qvector.count)
        return -1;
    if (b->qvector.count < a->qvector.count)
        return 1;

    for (i = 0, j = 0;
         ((i < a->rvector.count) && (j < b->rvector.count));
         i++, j++) {
        /* Get records at current index */
        ra = pico_mdns_record_vector_get(&(a->rvector), i);
        rb = pico_mdns_record_vector_get(&(b->rvector), j);

        /* Compare records */
        ret = pico_mdns_cmp((void *)ra, (void *)rb);

        /* If records differ, return return-value */
        if (ret)
            return ret;
    }

    /* All the records currently compared are the same. Check Which has the most
     records, if they have the same amount, move on */
    if (a->rvector.count < b->rvector.count)
        return -1;
    if (b->rvector.count < a->rvector.count)
        return 1;

    /* Cookies contain exactly the same questions and records */
    return 0;
}

/* Cache records for the mDNS hosts in the network */
PICO_TREE_DECLARE(Cache, pico_mdns_cmp);

/* My records for which I want to have the authority */
PICO_TREE_DECLARE(MyRecords, pico_mdns_cmp);

/* Cookie-tree */
PICO_TREE_DECLARE(Cookies, pico_mdns_cookie_cmp);

/* Global socket and port for all mdns communication */
static struct pico_socket *mdns_sock_ipv4 = NULL;
static uint16_t mdns_port = 5353u;
static struct pico_ip4 inaddr_any = { 0 };
static void (*init_callback)(pico_mdns_record_vector *, char *, void *) = 0;

/* ****************************************************************************
 *  Hostname for this machine, only 1 hostname can be set.
 * ****************************************************************************/
static char *hostname = NULL;

// MARK: MDNS PACKET UTILITIES

/* ****************************************************************************
 *  Sends an mdns packet on the global socket
 * ****************************************************************************/
static int
pico_mdns_send_packet(pico_dns_packet *packet, uint16_t len)
{
    struct pico_ip4 dst4;

    /* Set the destination address to the mDNS multicast-address */
    pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &dst4.addr);

    /* Send packet to IPv4 socket */
    return pico_socket_sendto(mdns_sock_ipv4, packet, (int)len, &dst4,
                              short_be(mdns_port));
}

/* ****************************************************************************
 *  Sends an mdns packet on the global socket via unicast
 * ****************************************************************************/
static int
pico_mdns_send_packet_unicast(pico_dns_packet *packet,
                              uint16_t len,
                              struct pico_ip4 peer)
{
    /* Send packet to IPv4 socket */
    return pico_socket_sendto(mdns_sock_ipv4, packet, (int)len, &peer,
                              short_be(mdns_port));
}

// MARK: COOKIE UTILITIES

/* ****************************************************************************
 *  Deletes a mDNS packet cookie and free's memory.
 * ****************************************************************************/
static int
pico_mdns_cookie_delete( struct pico_mdns_cookie **cookie )
{
    /* Check params */
    if (!cookie || !(*cookie)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Destroy the vectors contained */
    pico_dns_question_vector_destroy(&((*cookie)->qvector));
    pico_mdns_record_vector_destroy(&((*cookie)->rvector));

    /* Delete the cookie itself */
    PICO_FREE(*cookie);
    *cookie = NULL;
    cookie = NULL;

    return 0;
}

/* ****************************************************************************
 *  Creates a mDNS cookie
 * ****************************************************************************/
static struct pico_mdns_cookie *
pico_mdns_cookie_create( pico_dns_question_vector qvector,
                         pico_mdns_record_vector rvector,
                         uint8_t count,
                         uint8_t type,
                         void (*callback)(pico_mdns_record_vector *,
                                          char *,
                                          void *),
                         void *arg )
{
    struct pico_mdns_cookie *cookie = NULL; // Packet cookie to send

    /* Provide space for the mDNS packet cookie */
    cookie = PICO_ZALLOC(sizeof(struct pico_mdns_cookie));
    if (!cookie) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Fill in the fields */
    cookie->qvector = qvector;
    cookie->rvector = rvector;
    cookie->count = count;
    cookie->type = type;
    cookie->status = PICO_MDNS_COOKIE_STATUS_INACTIVE;
    cookie->timeout = 10u;
    cookie->send_timer = NULL;
    cookie->callback = callback;
    cookie->arg = arg;
    return cookie;
}

/* ****************************************************************************
 *  Find a query cookie that contains a questions for a specific name
 * ****************************************************************************/
static struct pico_mdns_cookie *
pico_mdns_cookie_tree_find_query_cookie( const char *name )
{
    struct pico_mdns_cookie *cookie = NULL;
    struct pico_tree_node *node = NULL;
    struct pico_dns_question *found = NULL;

    /* Check params */
    if (!name) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Iterate over the cookie-tree to find a cookie that contains a question
     for this name */
    pico_tree_foreach(node, &Cookies) {
        cookie = node->keyValue;
        found = pico_dns_question_vector_find_name(&(cookie->qvector), name);
        if (found)
            return cookie;
    }

    return NULL;
}

/* ****************************************************************************
 *  Delete a specific cookie from the cookie-tree
 * ****************************************************************************/
static int
pico_mdns_cookie_tree_del_cookie( struct pico_mdns_cookie *cookie )
{
    /* Check params */
    if (!cookie) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Delete cookie */
    pico_tree_delete(&Cookies, cookie);
    if (pico_mdns_cookie_delete(&cookie)) {
        mdns_dbg("Could not delete cookie from Cookie tree!\n");
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Add a cookie to the cookie-tree
 * ****************************************************************************/
static int
pico_mdns_cookie_tree_add_cookie( struct pico_mdns_cookie *cookie )
{
    if (pico_tree_insert(&Cookies, cookie)) {
        return -1;
    }
    return 0;
}

/* ****************************************************************************
 *  Finds an mDNS record in a cookie by comparing name and type. There can only
 *  be 1 record in a PROBE! cookie with a unique name and type combination,
 *  so this function only returns 1 record.
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_cookie_find_record( struct pico_mdns_cookie *cookie,
                              struct pico_dns_record *dns_record )
{
    /* In a cookie only one */
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record record = {0};
    uint16_t i = 0;

    /* Check params */
    if (!cookie || !dns_record) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    if (cookie->type != PICO_MDNS_COOKIE_TYPE_PROBE) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Create test record */
    record.record = dns_record;

    /* Iterate over record vector */
    for (i = 0; i < pico_mdns_record_vector_count(&(cookie->rvector)); i++) {
        node_record = pico_mdns_record_vector_get(&(cookie->rvector), i);
        if (node_record) {
            if (pico_mdns_cmp_name_type(node_record, &record) == 0) {
                return node_record;
            }
        }
    }
    return NULL;
}

/* ****************************************************************************
 *  Apply simultaneous probe tiebreaking on a probe cookie
 * ****************************************************************************/
static int
pico_mdns_cookie_apply_spt( struct pico_mdns_cookie *cookie,
                            struct pico_dns_record *answer)
{
    struct pico_mdns_record *my_record = NULL;
    struct pico_mdns_record peer_record;
    int ret = 0;

    /* Check params */
    if (!cookie || !answer) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (cookie->type != PICO_MDNS_COOKIE_TYPE_PROBE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    cookie->status = PICO_MDNS_COOKIE_STATUS_INACTIVE;

    /* Implement Simultaneous Probe Tiebreaking */
    my_record = pico_mdns_cookie_find_record(cookie, answer);
    if (!my_record) {
        mdns_dbg("This is weird! Record magically removed from cookie...\n");
        return -1;
    }

    peer_record.record = answer;
    ret = pico_mdns_record_am_i_lexi_later(my_record, &peer_record);
    if (ret > 0) {
        mdns_dbg("My record is lexographically later! Yay!\n");
        cookie->status = PICO_MDNS_COOKIE_STATUS_ACTIVE;
    } else {
        pico_timer_cancel(cookie->send_timer);
        cookie->timeout = 10u;
        cookie->count = 3;
        cookie->send_timer = pico_timer_add(1000, pico_mdns_send_probe_packet,
                                            (void *)cookie);
        mdns_dbg("Probing postponed with 1s because of S.P.T.\n");
    }

    return 0;
}

/* ****************************************************************************
 *  Checks whether there is a conflict-suffix already present in the first lbl
 *  of a name or not. If there is a conflict-suffix present, the 
 *  opening-bracket and the closing-bracket pointer will be set accordingly an 
 *  the suffix-string will be filled in.
 * ****************************************************************************/
static uint8_t
pico_mdns_is_suffix_present( char rname[],
                             char **opening_bracket_index,
                             char **closing_bracket_index,
                             char suffix[][5])
{
    uint8_t suffix_is_present = 0, s_i = 0;
    char temp[5] = {0};
    char *i = 0;

    /* Check params */
    if (!opening_bracket_index || !closing_bracket_index || !suffix) {
        pico_err = PICO_ERR_EINVAL;
        return 0;
    }

    /* First clean out those pointers */
    *opening_bracket_index = NULL;
    *closing_bracket_index = NULL;

    for (i = rname + 1; i < ((rname + 1) + *rname); i++) {
        /* Find the first opening bracket */
        if (*i == '(') {
            *opening_bracket_index = i;
            suffix_is_present = 1;
        } else {
            /* Check if what follows is numeric and copy if so */
            if (*opening_bracket_index && i > *opening_bracket_index) {
                if (*i < '0' || *i > '9') {
                    if (*i == ')') {
                        *closing_bracket_index = i;
                    } else {
                        suffix_is_present = 0;
                    }
                } else {
                    if (s_i < 5)
                        (*suffix)[s_i++] = *i;
                }
            }
        }
    }

    if (!suffix_is_present) {
        *opening_bracket_index = NULL;
        *closing_bracket_index = NULL;
        memcpy(suffix[0], temp, 5);
    }

    return suffix_is_present;
}

/* ****************************************************************************
 *  Utility function to append a conflict resolution suffix to the first label
 *  of a FQDN.
 * ****************************************************************************/
static char *
pico_mdns_resolve_name_conflict( char rname[] )
{
    char *new_rname = NULL;
    uint16_t new_rlen = 0;
    char *opening_bracket_index = NULL;
    char *closing_bracket_index = NULL;
    char suffix[5] = { 0 };
    char new_suffix[5] = { 0 };
    char *str = NULL;
    uint16_t temp = 0;

    /* Check params */
    if (!rname) {
        return NULL;
    }

    /* Check whether a conflict-suffix is already present in the first label
       of the name */
    if (pico_mdns_is_suffix_present(rname, &opening_bracket_index,
                                    &closing_bracket_index,&suffix)){
        /* If suffix is '()' */
        if (strlen(suffix) == 0) {
            new_rlen = (uint16_t)(strlen(rname) + 1);
            strcpy(new_suffix, "2");
        } else {
            /* If suffix is numeric update the number & generate new suffix */
            str = suffix;
            while (*str >= '0' && *str <= '9')
                temp = (uint16_t)(temp * 10 + *str++ - '0');
            temp++;
            sprintf(new_suffix, "%u", temp);
            new_rlen = (uint16_t)(strlen(rname) + (strlen(new_suffix) -
                                                   strlen(suffix)));
        }
    } else {
        /* If no suffix is present at all */
        opening_bracket_index = rname + rname[0];
        closing_bracket_index = opening_bracket_index + 1;
        new_rlen = (uint16_t)(strlen(rname) + 4u);
        strcpy(new_suffix, " (2)");
    }

    /* Provide space for the new name */
    new_rname = (char *)PICO_ZALLOC(new_rlen + 1u);
    if (!new_rname) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Assemble the new name again */
    memcpy(new_rname, rname, (size_t)(opening_bracket_index - rname + 1));
    strcpy(new_rname + (opening_bracket_index - rname) + 1, new_suffix);
    strcpy(new_rname + (opening_bracket_index - rname) +
           strlen(new_suffix) + 1, closing_bracket_index);
    new_rname[0] = (char)(new_rname[0] + (char)(strlen(new_rname) -
                                                strlen(rname)));
    return new_rname;
}

/* ****************************************************************************
 *  Utility function to generate new records from conflicting ones (copy) with
 *  another name.
 * ****************************************************************************/
static int
pico_mdns_generate_new_records( pico_mdns_record_vector *conflict_vector,
                                char *conflict_name,
                                pico_mdns_record_vector *new_vector,
                                char *new_name )
{
    struct pico_mdns_record *record = NULL, *new_record = NULL;
    uint16_t i = 0;

    for (i = 0; i < pico_mdns_record_vector_count(conflict_vector); i++) {
        record = pico_mdns_record_vector_get(conflict_vector, i);
        if (strcmp(record->record->rname, conflict_name) == 0) {
            /* Create a new record */
            new_record = pico_mdns_record_copy_with_new_name(record, new_name);
            if (!new_record) {
                mdns_dbg("Could not create new non-conflicting record!\n");
                return -1;
            }
            /* Reset status bits */
            new_record->flags &= 0x1F;
            /* Add the record to a vector */
            if (pico_mdns_record_vector_add(new_vector, new_record) < 0) {
                mdns_dbg("Could not add record to vector!\n");
                pico_mdns_record_delete(&new_record);
                return -1;
            }
            /* Remove current conflicting record */
            if (pico_mdns_record_vector_delete(conflict_vector, i) < 0) {
                mdns_dbg("Could not delete conflicting record from vector!\n");
                pico_mdns_record_delete(&new_record);
                return -1;
            }
            /* Because the record is deleted from the vector, when the next
               iteration occurs count may be OOB, so decrement i. */
            --i;
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Apply conflict resolution for a certain name on a probe cookie.
 * ****************************************************************************/
static int
pico_mdns_cookie_resolve_conflict( struct pico_mdns_cookie *cookie,
                                   char *rname )
{
    pico_mdns_record_vector rvector = { 0 };
    char *new_name = NULL, *url = NULL;

    /* Check params */
    if (!cookie || !rname) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (cookie->type != PICO_MDNS_COOKIE_TYPE_PROBE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Convert rname to url */
    url = pico_dns_qname_to_url(rname);
    mdns_dbg("CONFLICT for probe query with name '%s' occured!\n", url);

    /* Prerequisite step: delete all conflicting records from my records */
    if (pico_mdns_record_tree_del_url(url, &MyRecords) < 0)
        mdns_dbg("Could not delete my conflicting records!\n");
    PICO_FREE(url);

    /* Step 1: Remove question with that name from cookie */
    if (pico_dns_question_vector_del_name(&(cookie->qvector), rname) < 0) {
        mdns_dbg("Could not delete question with nameconflict from cookie!\n");
        return -1;
    }
    
    /* Step 1b: Stop timer events if cookie contains no other questions */
    if (pico_dns_question_vector_count(&(cookie->qvector)) == 0) {
        pico_timer_cancel(cookie->send_timer);
        cookie->send_timer = NULL;
        mdns_dbg("Stopped timer events for conflicting cookie.\n");
    }

    /* Step 2: Create a new name depending on current name */
    if (!(new_name = pico_mdns_resolve_name_conflict(rname))) {
        mdns_dbg("Resolving name conflict returned NULL!\n");
        return -1;
    }

    /* Step 3: Create records with new name for the records with that name */
    if (pico_mdns_generate_new_records(&(cookie->rvector), rname,
                                       &rvector, new_name) < 0) {
        mdns_dbg("Could not generate new records from conflicting ones!\n");
        PICO_FREE(new_name);
        return -1;
    }
    PICO_FREE(new_name);

    /* Step 5: Try to reclaim the newly created records */
    if (pico_mdns_reclaim(rvector, cookie->callback, cookie->arg) < 0) {
        mdns_dbg("Could not claim new records!\n");
        return -1;
    }

    /* Step 6: Check if cookie is not empty now */
    if (cookie->qvector.count == 0 && cookie->rvector.count == 0) {
        mdns_dbg("Deleting empty cookie...");
        if (pico_mdns_cookie_tree_del_cookie(cookie) < 0)
            mdns_dbg("could not delete empty cookie!\n");
        else
            mdns_dbg("done\n");
    } else
        mdns_dbg("Leftover records are still being probed..\n");

    return 0;
}

// MARK: MDNS QUESTION UTILITIES

static struct pico_dns_question *
pico_mdns_question_create( const char *url,
                          uint16_t *len,
                          uint8_t proto,
                          uint16_t qtype,
                          uint8_t flags,
                          uint8_t reverse )
{
    uint16_t _qtype = 0;                            // qtype
    uint16_t qclass = short_be(PICO_DNS_CLASS_IN);  // qclass

    /* Set the MSB of the qclass field according to the mDNS format */
    if (IS_QUESTION_UNICAST_FLAG_SET(flags)) {
        PICO_MDNS_SET_MSB_BE(qclass);
    } else
        PICO_MDNS_CLR_MSB_BE(qclass);

    /* Make the class LE again */
    qclass = short_be(qclass);

    /* Fill in the question suffix */
    if (IS_QUESTION_PROBE_FLAG_SET(flags)) {
        /* RFC:
         *  All probe queries SHOULD be done using the desired resource
         *  record name and class (usually class 1, "Internet"), and
         *  query type "ANY" (255), to elicit answers for all
         *  types of records with that name.
         */
        _qtype = PICO_DNS_TYPE_ANY;
    } else {
        _qtype = qtype;
    }

    /* Create a question as you would with plain DNS */
    return pico_dns_question_create(url, len, proto, _qtype, qclass, reverse);
}

// MARK: MDNS RR UTILITIES

/* ****************************************************************************
 *  Create a resource record for the mDNS resource record format, that is
 *  with the MSB of the rclass field being set accordingly.
 * ****************************************************************************/
static struct pico_dns_record *
pico_mdns_dns_record_create( const char *url,
                             void *_rdata,
                             uint16_t datalen,
                             uint16_t *len,
                             uint16_t rtype,
                             uint32_t rttl,
                             uint8_t flags )
{
    uint16_t rclass = short_be(PICO_DNS_CLASS_IN);  // rclass

    /* Set the MSB of the rclass field according to the mDNS format */
    if (IS_RES_RECORD_FLAG_CLAIM_UNIQUE_SET(flags))
        PICO_MDNS_SET_MSB_BE(rclass);
    else
        PICO_MDNS_CLR_MSB_BE(rclass);

    /* Make the class LE again */
    rclass = short_be(rclass);

    /* Create a resource record as you would with plain DNS */
    return pico_dns_record_create(url, _rdata, datalen, len,
                                  rtype, rclass, rttl);
}

static int
pico_mdns_record_resolve_conflict( struct pico_mdns_record *record,
                                   char *rname )
{
    pico_mdns_record_vector rvector = { 0 };
    struct pico_mdns_record *new_record = NULL;
    char *new_name = NULL;

    /* Check params */
    if (!record || !rname) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    /* There is no problem if my record is a shared record */
    if (IS_RES_RECORD_FLAG_CLAIM_SHARED_SET(record->flags))
        return 0;

    mdns_dbg("Record conflict occured for %s\n", rname);

    /* Step 2: Create a new name depending on current name */
    new_name = pico_mdns_resolve_name_conflict(rname);
    if (!new_name) {
        mdns_dbg("Resolving name conflict returned NULL!\n");
        return -1;
    }

    /* Try to create new record */
    new_record = pico_mdns_record_copy_with_new_name(record, new_name);
    if (!new_record) {
        mdns_dbg("Could not create new non-conflicting record!\n");
        PICO_FREE(new_name);
        return -1;
    }
    new_record->flags = new_record->flags & 0x1F;
    PICO_FREE(new_name);

    /* Step 3: delete conflicting record from my records */
    if (pico_mdns_record_tree_del_record(record, &MyRecords) < 0)
        mdns_dbg("Could not delete my conflicting records!\n");

    /* Add the record to a vector */
    if (pico_mdns_record_vector_add(&rvector, new_record) < 0) {
        mdns_dbg("Could not add record to vector!\n");
        return -1;
    }

    /* Step 4: Try to reclaim the newly created record */
    if (pico_mdns_reclaim(rvector, init_callback, NULL) < 0) {
        mdns_dbg("Could not claim new records!\n");
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Determines if my_record is lexographically later than peer_record, returns
 *  1 when this is the case.
 * ****************************************************************************/
static int
pico_mdns_record_am_i_lexi_later( struct pico_mdns_record *my_record,
                                  struct pico_mdns_record *peer_record)
{
    uint16_t my_type = 0, peer_type = 0, my_class = 0, peer_class = 0;

    /* Check params */
    if (!my_record || !peer_record) {
        pico_err = PICO_ERR_EINVAL;
        return -2;
    }

    /* First, check class */
    my_class = short_be(my_record->record->rsuffix->rclass);
    peer_class = short_be(peer_record->record->rsuffix->rclass);
    if (my_class > peer_class)
        return 1;


    /* Then, check type */
    my_type = short_be(my_record->record->rsuffix->rtype);
    peer_type = short_be(peer_record->record->rsuffix->rtype);
    if (my_type > peer_type)
        return 1;

    /* At last, check rdata */
    return pico_mdns_rdata_cmp(my_record->record->rdata,
                               peer_record->record->rdata,
                               short_be(my_record->record->rsuffix->rdlength),
                               short_be(peer_record->record->rsuffix->rdlength));
}

/* ****************************************************************************
 *  Creates a new mDNS resource record from an already existing DNS record
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_record_create_from_dns( struct pico_dns_record *dns_record )
{
    struct pico_mdns_record *record = NULL;  // Address to set afterwards

    /* Provide space for the new mDNS resource record */
    record = PICO_ZALLOC(sizeof(struct pico_mdns_record));
    if (!record) {
        mdns_dbg("Could not provide space for the mDNS resource record");
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Set the DNS record */
    record->record = dns_record;
    record->current_ttl = long_be(dns_record->rsuffix->rttl);
    record->flags = 0;
    record->claim_id = 0;

    return record;
}

/* ****************************************************************************
 *  Copies an mDNS resource record with another name
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_record_copy_with_new_name( struct pico_mdns_record *record,
                                     const char *new_rname )
{
    struct pico_mdns_record *copy = NULL;

    /* Check params */
    if (!record && !new_rname) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Copy the record */
    copy = pico_mdns_record_copy(record);
    if (!copy) {
        mdns_dbg("Could not copy record!\n");
        return NULL;
    }

    /* Free the copied rname */
    PICO_FREE(copy->record->rname);

    /* Provide a new string */
    copy->record->rname = PICO_ZALLOC(strlen(new_rname) + 1);
    if (!(copy->record->rname)) {
        pico_err = PICO_ERR_ENOMEM;
        pico_mdns_record_delete(&copy);
        return NULL;
    }
    strcpy(copy->record->rname, new_rname);
    copy->record->rname_length = (uint16_t)(strlen(new_rname) + 1);

    return copy;
}

/* ****************************************************************************
 *  Just copies an mDNS resource record
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_record_copy( struct pico_mdns_record *record )
{
    struct pico_mdns_record *copy = NULL;

    /* Check params */
    if (!record) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Provide space for the copy */
    copy = PICO_ZALLOC(sizeof(struct pico_mdns_record));
    if (!copy) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Copy the DNS record */
    copy->record = pico_dns_record_copy(record->record);
    if (!(copy->record)) {
        PICO_FREE(copy);
        return NULL;
    }

    /* Copy the fields */
    copy->current_ttl = record->current_ttl;
    copy->flags = record->flags;
    copy->claim_id = record->claim_id;

    return copy;
}

/* ****************************************************************************
 *  Creates a new mDNS resource record. The address of a mDNS res record-struct
 *  needs to be given in record_out to return the created record in. If passed
 *  in record is an element of a list, the record will be appended to the end
 *  of the list. So you will have to iterate until the end of the list to
 *  access the newly created record.
 * ****************************************************************************/
struct pico_mdns_record *
pico_mdns_record_create( const char *url,
                         void *_rdata,
                         uint16_t datalen,
                         uint16_t rtype,
                         uint32_t rttl,
                         uint8_t flags )
{
    struct pico_mdns_record *record = NULL;
    uint16_t len = 0;

    /* Check params */
    if (!url || !_rdata) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Provide space for the new mDNS resource record */
    record = PICO_ZALLOC(sizeof(struct pico_mdns_record));
    if (!record) {
        mdns_dbg("Could not provide space for the mDNS resource record");
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Create a new record at the end of the list */
    record->record = pico_mdns_dns_record_create(url, _rdata, datalen, &len,
                                                 rtype, rttl, flags);
    if (!((record)->record)) {
        mdns_dbg("Creating mDNS resource record failed!\n");
        PICO_FREE(record);
        return NULL;
    }

    /* Initialise fields */
    record->current_ttl = rttl;
    record->flags = flags;
    record->claim_id = 0;

    return record;
}

/* ****************************************************************************
 *  Deletes a mDNS resource record.
 * ****************************************************************************/
int
pico_mdns_record_delete( struct pico_mdns_record **record )
{
    /* Check params */
    if (!record || !(*record)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Delete DNS record contained */
    if ((*record)->record)
        pico_dns_record_delete(&((*record)->record));

    /* Delete the record itself */
    PICO_FREE(*record);
    *record = NULL;
    record = NULL;

    return 0;
}

/* ****************************************************************************
 *  Initialise an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_init( pico_mdns_record_vector *vector )
{
    /* Check params */
    if (!vector)
        return -1;

    vector->records = NULL;
    vector->count = 0;
    return 0;
}

/* ****************************************************************************
 *  Returns the amount of records contained in an mDNS record vector
 * ****************************************************************************/
uint16_t
pico_mdns_record_vector_count( pico_mdns_record_vector *vector )
{
    /* Check params */
    if (!vector)
        return 0;
    return vector->count;
}

/* ****************************************************************************
 *  Adds an mDNS record to an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_add( pico_mdns_record_vector *vector,
                            struct pico_mdns_record *record )
{
    struct pico_mdns_record **new_records = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!vector || !record)
        return -1;

    /* Create a new array with larger size */
    new_records = PICO_ZALLOC(sizeof(struct pico_mdns_record *) *
                              (vector->count + 1u));
    if (!new_records)
        return -1;

    /* Copy all the record-pointers from the previous array to the new one */
    for (i = 0; i < vector->count; i++)
        new_records[i] = vector->records[i];
    new_records[i] = record;

    /* Free the previous array */
    if (vector->records)
        PICO_FREE(vector->records);

    /* Set the records array to the new one and update count */
    vector->records = new_records;
    vector->count++;
    return 0;
}

/* ****************************************************************************
 *  Gets an mDNS record from an mDNS record vector at a certain index
 * ****************************************************************************/
struct pico_mdns_record *
pico_mdns_record_vector_get( pico_mdns_record_vector *vector,
                             uint16_t index )
{
    /* Check params */
    if (!vector)
        return NULL;

    /* Return record with conditioned index */
    if (index < vector->count)
        return vector->records[index];

    return NULL;
}

static int
pico_mdns_record_vector_del_generic( pico_mdns_record_vector *vector,
                                     uint16_t index,
                                     uint8_t delete )
{
    struct pico_mdns_record **new_records = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!vector) return -1;
    if (index >= vector->count) return 0;

    if (delete) {
        /* Delete record */
        if (pico_mdns_record_delete(&(vector->records[index])) < 0)
            return -1;
    }

    vector->count--;
    if (vector->count) {
        new_records = PICO_ZALLOC(sizeof(struct pico_mdns_record *) *
                                  vector->count);
        if (!new_records) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
    }

    /* Move up subsequent records */
    for (i = index; i < vector->count; i++) {
        vector->records[i] = vector->records[i + 1];
        vector->records[i + 1] = NULL;
    }

    /* Copy records */
    for (i = 0; i < vector->count; i++)
        new_records[i] = vector->records[i];

    /* Free the previous array */
    PICO_FREE(vector->records);

    /* Set the records array to the new one */
    vector->records = new_records;
    return 0;
}

/* ****************************************************************************
 *  Removes an mDNS record from an mDNS record vector at a certain index
 * ****************************************************************************/
static int
pico_mdns_record_vector_remove( pico_mdns_record_vector *vector,
                                uint16_t index )
{
    return pico_mdns_record_vector_del_generic(vector, index, 0);
}

/* ****************************************************************************
 *  Deletes an mDNS record an mDNS record vector at a certain index
 * ****************************************************************************/
static int
pico_mdns_record_vector_delete( pico_mdns_record_vector *vector,
                                uint16_t index )
{
    return pico_mdns_record_vector_del_generic(vector, index, 1);
}

/* ****************************************************************************
 *  Deletes every mDNS record from an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_destroy( pico_mdns_record_vector *vector )
{
    uint16_t i = 0;

    /* Check params */
    if (!vector) return -1;

    /* Delete every record in the vector */
    for (i = 0; i < vector->count; i++) {
        if (pico_mdns_record_delete(&(vector->records[i])) < 0) {
            mdns_dbg("Could not delete record from vector!\n");
            return -1;
        }
    }

    /* Update the fields */
    vector->records = NULL;
    vector->count = 0;
    return 0;
}

/* ****************************************************************************
 *  Append two mDNS record vectors to each other
 * ****************************************************************************/
static int
pico_mdns_record_vector_append( pico_mdns_record_vector *vector,
                               pico_mdns_record_vector *vector_b )
{
    struct pico_mdns_record **new_records = NULL;
    uint16_t i = 0, offset = 0;

    /* Check params */
    if (!vector || !vector_b)
        return -1;

    /* Create a new array with larger size */
    new_records = PICO_ZALLOC(sizeof(struct pico_mdns_record *) *
                              (size_t)(vector->count + vector_b->count));
    if (!new_records)
        return -1;

    /* Copy all the record-pointers from the previous array to the new one */
    for (i = 0; i < vector->count; i++)
        new_records[i] = vector->records[i];
    offset = i;

    for (i = offset; i < (offset + vector_b->count); i++)
        new_records[i] = vector_b->records[i - offset];

    /* Free the previous array */
    if (vector->records)
        PICO_FREE(vector->records);

    /* Set the records array to the new one and update count */
    vector->records = new_records;
    vector->count = (uint16_t)(vector->count + vector_b->count);

    /* Remove all the records from the second vector */
    for (i = 0; i < vector_b->count; i++)
        pico_mdns_record_vector_remove(vector_b, i);

    return 0;
}

/* ****************************************************************************
 *  Find multiple mDNS res records in a record tree by URL
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_record_tree_find_url( const char *url,
                                struct pico_tree *tree )
{
    pico_mdns_record_vector cache_hits = { 0 };
    struct pico_mdns_record *node_record = NULL;
    struct pico_tree_node *node = NULL;
    char *rname = NULL;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return cache_hits;
    }

    /* We need the FQDN to compare */
    rname = pico_dns_url_to_qname(url);
    if (!rname)
        return cache_hits;

    /* Iterate over the Cache-tree */
    pico_tree_foreach(node, tree) {
        node_record = node->keyValue;
        if (strcmp(node_record->record->rname, rname) == 0) {
            /* Add the record to the an mDNS res record vector */
            if (pico_mdns_record_vector_add(&cache_hits, node_record) < 0) {
                mdns_dbg("Could not add copy of cache record to vector!\n");
                return cache_hits;
            }
        }
    }
    PICO_FREE(rname);
    return cache_hits;
}

/* ****************************************************************************
 *  Find multiple mDNS res records in a record tree by URL and rtype
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_record_tree_find_url_type( const char *url,
                                     uint16_t rtype,
                                     struct pico_tree *tree )
{
    pico_mdns_record_vector cache_hits = { 0 };
    struct pico_mdns_record test_record;
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record *copy = NULL;
    struct pico_tree_node *node = NULL;
    uint16_t len = 0;
    uint8_t rdata = 0;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return cache_hits;
    }
    /* Create a test record */
    test_record.record = pico_dns_record_create(url, &rdata, 1, &len, rtype,
                                                PICO_DNS_CLASS_IN, 0);
    /* Iterate over the Cache-tree */
    pico_tree_foreach(node, tree) {
        node_record = node->keyValue;
        if (pico_mdns_cmp_name_type(node_record, &test_record) == 0) {
            /* Make a copy of found record */
            copy = pico_mdns_record_copy(node_record);
            if (copy) {
                /* Add the copy to an mDNS record vector */
                if (pico_mdns_record_vector_add(&cache_hits, copy) < 0) {
                    mdns_dbg("Could not add copy of cache record to vector!\n");
                    return cache_hits;
                }
            }
        }
    }

    /* Delete the test DNS record */
    if (pico_dns_record_delete(&(test_record.record)) < 0) {
        mdns_dbg("Could not delete DNS test record!\n");
        return cache_hits;
    }

    return cache_hits;
}

/* ****************************************************************************
 *  Find a unique mDNS res record in a record tree by rname, rtype and rdata
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_record_tree_find_record( struct pico_mdns_record *record,
                                   struct pico_tree *tree )
{
    struct pico_mdns_record *node_record = NULL;
    struct pico_tree_node *node = NULL;

    /* Check params */
    if (!record) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Iterate over the Cache-tree */
    pico_tree_foreach(node, tree) {
        node_record = node->keyValue;
        if ((*tree).compare(node_record, record) == 0)
            return node_record;
    }

    return NULL;
}

/* ****************************************************************************
 *  Delete multiple mDNS res records in a record tree by URL and rtype
 * ****************************************************************************/
static int
pico_mdns_record_tree_del_url( const char *url,
                               struct pico_tree *tree )
{
    pico_mdns_record_vector cache_hits = { 0 };
    struct pico_mdns_record *record = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Find all the records by name in the tree */
    cache_hits = pico_mdns_record_tree_find_url(url, tree);

    /* Iterate over the results and remove them from the cache tree */
    for (i = 0; i < pico_mdns_record_vector_count(&cache_hits); i++) {
        record = pico_mdns_record_vector_get(&cache_hits, i);
        pico_tree_delete(tree, record);
    }

    /* Delete all the cache records */
    if (pico_mdns_record_vector_destroy(&cache_hits) < 0) {
        mdns_dbg("Could not delete mDNS cache records!\n");
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Delete multiple mDNS res records in a record tree by URL and rtype
 * ****************************************************************************/
static int
pico_mdns_record_tree_del_url_type( const char *url,
                                    uint16_t type,
                                    struct pico_tree *tree )
{
    struct pico_mdns_record test_record;
    struct pico_mdns_record *node_record = NULL;
    struct pico_tree_node *node = NULL;
    struct pico_tree_node *next = NULL;

    uint8_t rdata = 0;
    uint16_t len = 0;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Create a test record */
    test_record.record = pico_dns_record_create(url, &rdata, 1, &len, type,
                                                PICO_DNS_CLASS_IN, 0);

    /* Iterate over the tree */
    pico_tree_foreach_safe(node, tree, next) {
        node_record = node->keyValue;
        if (pico_mdns_cmp_name_type(node_record, &test_record) == 0) {
            /* Move the node to the next */
            node = pico_tree_next(node);
            /* Delete from the tree */
            pico_tree_delete(tree, node_record);
            if (pico_mdns_record_delete(&node_record) < 0) {
                mdns_dbg("Could not delete mDNS res record from tree!\n");
                return -1;
            }
            /* Move the node to the previous, otherwise, a node will be 
               skipped in the next iteration */
            node = pico_tree_prev(node);
        }
    }

    /* Delete the test DNS record */
    if (pico_dns_record_delete(&(test_record.record)) < 0) {
        mdns_dbg("Could not delete DNS test record!\n");
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Delete a unique res record in a record tree by rname, rtype and rdata
 * ****************************************************************************/
static int
pico_mdns_record_tree_del_record( struct pico_mdns_record *record,
                                  struct pico_tree *tree )
{
    struct pico_mdns_record *found = NULL;

    /* Check params */
    if (!record) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Try to find a unique record in the tree */
    found = pico_mdns_record_tree_find_record(record, tree);

    /* If found, delete unique record */
    if (found) {
        pico_tree_delete(tree, found);
        if (pico_mdns_record_delete(&found) < 0) {
            mdns_dbg("Could not delete mDNS res record from tree!\n");
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Adds a record to the tree if a same record is not already found in the tree
 * ****************************************************************************/
static int
pico_mdns_record_tree_add_record( struct pico_mdns_record *record,
                                  struct pico_tree *tree)
{
    /* Check params */
    if (!record || !tree) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (!(record->record)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    pico_tree_insert(tree, record);
    return 0;
}

// MARK: MY RECORDS UTILS

/* ****************************************************************************
 *  Finds a mDNS record in my records by url and type
 * ****************************************************************************/
static struct pico_mdns_record *
pico_mdns_my_records_find_url_type( const char *url,
                                    uint16_t type )
{
    struct pico_mdns_record *node_record = NULL;
    struct pico_tree_node *node = NULL;
    struct pico_mdns_record test_record;
    uint16_t len = 0;
    uint8_t rdata = 0;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Create a test record */
    test_record.record = pico_dns_record_create(url, &rdata, 1, &len, type,
                                                PICO_DNS_CLASS_IN, 0);
    /* Iterate over the Cache-tree */
    pico_tree_foreach(node, &MyRecords) {
        node_record = node->keyValue;
        if (pico_mdns_cmp_name_type(node_record, &test_record) == 0)
            return node_record;
    }

    /* Delete the test DNS record */
    if (pico_dns_record_delete(&(test_record.record)) < 0) {
        mdns_dbg("Could not delete DNS test record!\n");
        return NULL;
    }

    return NULL;
}

/* ****************************************************************************
 *  Adds records contained in mdns_record_vector to my records, returns a
 *  mdns_record_vector with all the records who are added to my records, since,
 *  when a unique comination of name and type is already present in my records,
 *  the duplicate record will be removed from the vector and not added again.
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_my_records_add( pico_mdns_record_vector vector, uint8_t reclaim )
{
    struct pico_mdns_record *record = NULL, *found = NULL;
    static uint8_t claim_id_count = 0;
    char *url = NULL;
    uint16_t i = 0, j = 0;

    if (!reclaim)
        ++claim_id_count;

    /* Iterate over record vector */
    for (i = 0; i < pico_mdns_record_vector_count(&vector); i++) {
        record = pico_mdns_record_vector_get(&vector, i);

        /* Check if record with this combination of name and type is already
           contained in my records and if so, skip adding */
        url = pico_dns_qname_to_url(record->record->rname);
        found = pico_mdns_my_records_find_url_type(url,
                                    short_be(record->record->rsuffix->rtype));
        PICO_FREE(url);
        if (found) {
            /* Remove duplicate record from the vector */
            pico_mdns_record_vector_remove(&vector, i);
            continue;
        }

        /* Set probed flag if shared record */
        if (IS_RES_RECORD_FLAG_CLAIM_SHARED_SET(record->flags))
            PICO_MDNS_SET_FLAG(record->flags, PICO_MDNS_RECORD_PROBED);
        if (!reclaim)
            record->claim_id = claim_id_count;

        /* If unique combination is not found, add record */
        if (pico_mdns_record_tree_add_record(record, &MyRecords) < 0) {
            mdns_dbg("Could not add record to My Records! \n");
            /* Remove the leftover records from the vector */
            for (j = i; j < pico_mdns_record_vector_count(&vector); j++)
                pico_mdns_record_vector_remove(&vector, i);
            break;
        }
    }
    return vector;
}

/* ****************************************************************************
 *  Generates a list of all my records for which the probe flag already has
 *  been set and for which the claimed flag hasn't been set yet. Copies the
 *  records from my records, so you have to manually delete them.
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_my_records_find_probed( void )
{
    pico_mdns_record_vector vector = { 0 };
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record *copy = NULL;
    struct pico_tree_node *node = NULL;

    pico_tree_foreach(node, &MyRecords) {
        node_record = node->keyValue;
        if (IS_RES_RECORD_FLAG_PROBED_SET(node_record->flags) &&
            !IS_RES_RECORD_FLAG_CLAIMED_SET(node_record->flags)) {
            copy = pico_mdns_record_copy(node_record);
            if (copy) {
                if (pico_mdns_record_vector_add(&vector, copy) < 0) {
                    mdns_dbg("Could not add copy of mDNS record to vector!\n");
                    pico_mdns_record_delete(&copy);
                    return vector;
                }
            }
        }
    }
    return vector;
}

/* ****************************************************************************
 *  Generates a list of all my records for which the probe flag and the
 *  the claimed flag has not yet been set. Copies the records from my records,
 *  so you have to manually delete them.
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_my_records_find_to_probe( void )
{
    pico_mdns_record_vector vector = { 0 };
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record *copy = NULL;
    struct pico_tree_node *node = NULL;

    pico_tree_foreach(node, &MyRecords) {
        node_record = node->keyValue;
        /* Check if probed flag is not set of a record */
        if (!IS_RES_RECORD_FLAG_PROBED_SET(node_record->flags) &&
            !IS_RES_RECORD_FLAG_CLAIMED_SET(node_record->flags) &&
            IS_RES_RECORD_FLAG_CLAIM_UNIQUE_SET(node_record->flags) &&
            !IS_RES_RECORD_FLAG_CURRENTLY_PROBING(node_record->flags)) {
            node_record->flags |= PICO_MDNS_RECORD_CURRENTLY_PROBING;
            copy = pico_mdns_record_copy(node_record);
            if (copy) {
                if (pico_mdns_record_vector_add(&vector, copy) < 0) {
                    mdns_dbg("Could not add copy of mDNS record to vector!\n");
                    pico_mdns_record_delete(&copy);
                    break;
                }
            }
        }
    }
    return vector;
}

/* ****************************************************************************
 *  Checks for all my records with a certain claim id if they've been claimed,
 *  returns 1 if this is the case, returns 0 otherwise.
 *  Adds all claimed records to the vector passed in.
 * ****************************************************************************/
static uint8_t
pico_mdns_my_records_claimed_id( uint8_t claim_id,
                                 pico_mdns_record_vector *vector )
{
    struct pico_mdns_record *record = NULL;
    struct pico_tree_node *node = NULL;

    /* Initialise the iterator for iterating over my records */
    pico_tree_foreach(node, &MyRecords) {
        record = node->keyValue;
        if (record->claim_id == claim_id) {
            /* Check if records are claimed for a certain claim ID */
            if (!IS_RES_RECORD_FLAG_CLAIMED_SET(record->flags)) {
                return 0;
            } else {
                if (pico_mdns_record_vector_add(vector, record) < 0) {
                    mdns_dbg("Could not add record to vector!\n");
                    return 0;
                }
            }
        }
    }

    return 1;
}

/* ****************************************************************************
 *  Marks mDNS resource records contained in [records]-list as claimed.
 *  Checks 'my records' for other records that are claimed with the same
 *  claim ID and if all records with the same claim ID as these recordes are
 *  marked as claimed, the [cb_claimed]-callback will be called. Deletes the
 *  records contained in the list, because after a specific record has been
 *  claimed, there is no use in keeping it.
 * ****************************************************************************/
static int
pico_mdns_my_records_claimed( pico_mdns_record_vector rvector,
                              void (*callback)(pico_mdns_record_vector *,
                                               char *,
                                               void *),
                              void *arg )
{
    pico_mdns_record_vector vector = { 0 };
    struct pico_mdns_record *record = NULL;
    struct pico_mdns_record *found = NULL;
    char *url = NULL;
    uint16_t i = 0;
    uint8_t all_claimed = 1;
    uint8_t claim_id = 0;

    /* Get the claim ID of the first claimed record */
    if (pico_mdns_record_vector_count(&rvector) > 0) {
        claim_id = pico_mdns_record_vector_get(&rvector, 0)->claim_id;
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Iterate over records and set the CLAIMED flag */
    for (i = 0; i < pico_mdns_record_vector_count(&rvector); i++) {
        record = pico_mdns_record_vector_get(&rvector, i);
        found = pico_mdns_record_tree_find_record(record, &MyRecords);
        if (found) {
            /* Set the flags of my records */
            PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RECORD_CLAIMED);
            PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RECORD_PROBED);

            /* If the record is for the hostname, update it */
            if (IS_RES_RECORD_FLAG_HOSTNAME_SET(found->flags)) {
                url = pico_dns_qname_to_url(found->record->rname);
                PICO_FREE(hostname);
                hostname = url;
            }
        }
    }

    /* Check if all records with saim */
    all_claimed = pico_mdns_my_records_claimed_id(claim_id, &vector);

    /* If all_claimed is still true */
    if (all_claimed) {
        mdns_dbg("%d records with claim ID '%d' are claimed!\n",
                 vector.count, claim_id);
        callback(&vector, NULL, arg);
    }

    return 0;
}

// MARK: MDNS QUERY UTILITIES

/* ****************************************************************************
 *  Creates a DNS packet meant for querying. Resource records can be added
 *  to query to allow:
 *      - Answer Section: To implement Known-Answer Suppression
 *      - Authority Section: To implement probe queries and tiebreaking
 * ****************************************************************************/
static pico_dns_packet *
pico_mdns_query_create( pico_dns_question_vector *qvector,
                        pico_dns_record_vector *anvector,
                        pico_dns_record_vector *nsvector,
                        pico_dns_record_vector *arvector,
                        uint16_t *len )
{
    pico_dns_packet *packet = NULL;

    /* Create an answer as you would with plain DNS */
    packet = pico_dns_query_create(qvector, anvector, nsvector, arvector, len);
    if (!packet) {
        mdns_dbg("Could not create DNS query!\n");
        return NULL;
    }

    /* Set the id of the DNS packet to 0 */
    packet->id = 0;

    return packet;
}

// MARK: MDNS ANSWER UTILITIES

/* ****************************************************************************
 *  Create a resource record for the mDNS answer message format, that is
 *  with the identifier of the DNS packet being 0.
 * ****************************************************************************/
static pico_dns_packet *
pico_mdns_answer_create( pico_dns_record_vector *anvector,
                         pico_dns_record_vector *nsvector,
                         pico_dns_record_vector *arvector,
                         uint16_t *len )
{
    pico_dns_packet *packet = NULL;

    /* Create an answer as you would with plain DNS */
    packet = pico_dns_answer_create(anvector, nsvector, arvector, len);
    if (!packet) {
        mdns_dbg("Could not create DNS answer!\n");
        return NULL;
    }

    /* Set the id of the DNS packet to 0 */
    packet->id = 0;

    return packet;
}

// MARK: CACHE UTILITIES

/* ****************************************************************************
 *  Utility function to update the TTL of a cache entry
 * ****************************************************************************/
static void
pico_mdns_cache_update_ttl( struct pico_mdns_record *record,
                            uint32_t ttl )
{
    /* Check params */
    if (!record)
        return;

    /* Update the TTL and timer */
    if(ttl > 0) {
        mdns_dbg("RR already in cache, updating TTL (was %ds, now %ds)\n",
                 long_be(record->record->rsuffix->rttl), ttl);

        /* Update the TTL's */
        record->record->rsuffix->rttl = long_be(ttl);
        record->current_ttl = ttl;
    } else {
        mdns_dbg("RR scheduled for deletion\n");
        /* TTL 0 means delete from cache but we need to wait one second */
        record->record->rsuffix->rttl = long_be(1u);
        record->current_ttl = 1u;
    }
}

/* ****************************************************************************
 *  Utility function to add a cache entry
 * ****************************************************************************/
static int
pico_mdns_cache_add( struct pico_mdns_record *record, char *url )
{
    struct pico_dns_record_suffix *suffix = NULL;

    /* Check param */
    if (!record || !url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check if cache flush bit is set */
    suffix = record->record->rsuffix;
    if (PICO_MDNS_IS_MSB_SET(short_be(suffix->rclass))) {
        mdns_dbg("FLUSH - Cache flush bit was set, triggered flush.\n");
        if (pico_mdns_record_tree_del_url_type(url, short_be(suffix->rtype),
                                               &Cache) < 0) {
            mdns_dbg("Could not flush records from cache!\n");
            return -1;
        }
    }

    /* Add copy to cache */
    if (long_be(suffix->rttl) > 0) {
        /* If the record is not a Goodbye Record, add it to the cache */
        pico_tree_insert(&Cache, record);
        mdns_dbg("RR cached. TICK TACK TICK TACK...\n");
    } else {
        mdns_dbg("RR is Goodbye Record.\n");
    }

    return 0;
}

/* ****************************************************************************
 *  Add a copy of an mDNS resource record to the cache tree.
 * ****************************************************************************/
static int
pico_mdns_cache_add_record( struct pico_mdns_record *record )
{
    struct pico_mdns_record *found = NULL;
    char *url = NULL;

    /* Check params */
    if (!record) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }


    /* See if the record is already contained in the cache */
    found = pico_mdns_record_tree_find_record(record, &Cache);
    if (found) {
        pico_mdns_cache_update_ttl(found,
                                   long_be(record->record->rsuffix->rttl));
        return 1;
    } else {
        /* Convert the rname to an URL */
        url = pico_dns_qname_to_url(record->record->rname);
        if (!url) {
            mdns_dbg("Could not convert rname to url!\n");
            return -1;
        }
        if (pico_mdns_cache_add(record, url) < 0) {
            mdns_dbg("Could not add cache entry!\n");
            return -1;
        }
        /* Free the url created */
        PICO_FREE(url);
    }

    return 0;
}

/* ****************************************************************************
 *  Flush all the records in the cache
 * ****************************************************************************/
int pico_mdns_flush_cache(void)
{
    struct pico_mdns_record *record = NULL;
    struct pico_tree_node *node = NULL;

    mdns_dbg("FLUSH - Flushing *ALL* cache records...\n");

    /* Iterate over all the cache-entries and delete them */
    pico_tree_foreach(node, &Cache) {
        record = node->keyValue;
        if (record) {
            node = pico_tree_next(node);
            pico_tree_delete(&Cache, record);
            if (pico_mdns_record_delete(&record) < 0) {
                mdns_dbg("Could not flush record from cache!\n");
                return -1;
            }
            node = pico_tree_prev(node);
        }
    }

    return 0;
}

#if PICO_MDNS_CONTINUOUS_REFRESH == 1
/* ****************************************************************************
 *  Determine if the current TTL is at a refresh point
 * ****************************************************************************/
static int
pico_mdns_ttl_at_refresh_time( uint32_t original,
                               uint32_t current )
{
    uint32_t rnd = 0;
    rnd = pico_rand() % 3;

    if (((original - current ==
          ((original * (80 + rnd)) / 100)) ? 1 : 0) ||
        ((original - current ==
          ((original * (85 + rnd)) / 100)) ? 1 : 0) ||
        ((original - current ==
          ((original * (90 + rnd)) / 100)) ? 1 : 0) ||
        ((original - current ==
          ((original * (95 + rnd)) / 100)) ? 1 : 0))
        return 1;
    else
        return 0;
}
#endif

/* ****************************************************************************
 *  Utility function to update the TTL of cache entries and check for expired 
 *  ones.
 * ****************************************************************************/
static void
pico_mdns_cache_check_expiries( void )
{
    struct pico_mdns_record *node_record = NULL;
    struct pico_tree_node *node = NULL;
#if PICO_MDNS_CONTINUOUS_REFRESH == 1
    uint32_t current = 0;
    uint32_t original = 0;
    char *url = NULL;
#endif

    /* Check for expired cache records */
    pico_tree_foreach(node, &Cache) {
        node_record = node->keyValue;
        if (node_record) {
            /* Update current ttl */
            node_record->current_ttl--;
            if (node_record->current_ttl < 1) {
                /* Move the node to the next for a second */
                node = pico_tree_next(node);
                pico_tree_delete(&Cache, node_record);
                /* Move the node back to the previous, otherwise a record will
                 be skipped in the next iteration */
                node = pico_tree_prev(node);
            }
#if PICO_MDNS_CONTINUOUS_REFRESH == 1
            /* Determine original and current ttl */
            original = long_be(node_record->record->rsuffix->rttl);
            current = node_record->current_ttl;

            /* Cache refresh at 80 or 85/90/95% of TTL + 2% rnd */
            if (pico_mdns_ttl_at_refresh_time(original, current)) {
                /* Parse the rname to an url */
                url = pico_dns_qname_to_url(node_record->record->rname);
                /* Reconfirm record */
                if (pico_mdns_getrecord_generic(url,
                            short_be(node_record->record->rsuffix->rtype),
                                                NULL, NULL) < 0)
                    mdns_dbg("Could not reconfirm record '%s'!\n", url);
                PICO_FREE(url);
            }
#endif
        }
    }
}

/* ****************************************************************************
 *  Utility function to update the TTL of cookies and check for expired
 *  ones.
 * ****************************************************************************/
static void
pico_mdns_cookies_check_timeouts( void )
{
    struct pico_mdns_cookie *node_cookie = NULL;
    struct pico_tree_node *node = NULL;

    pico_tree_foreach(node, &Cookies) {
        node_cookie = node->keyValue;

        /* Update the timeout counter */
        node_cookie->timeout--;

        if (node_cookie->timeout == 0) {
            /* Call callback */
            if (node_cookie->callback) {
                node_cookie->callback(NULL, NULL, node_cookie->arg);
            }

            /* Move to the next node for a second */
            node = pico_tree_next(node);

            /* Delete cookie */
            if (pico_mdns_cookie_tree_del_cookie(node_cookie) < 0) {
                mdns_dbg("Could not delete cookie after timeout!\n");
                return;
            }

            /* Move back to the previous node, otherwise a node will be skipped
             in the next iteration */
            node = pico_tree_prev(node);

            mdns_dbg("Query cookie timed out, deleted!\n");

            /* If the request was for a reconfirmation of a record,
             flush the corresponding record after the timeout */
        }
    }
}

/* ****************************************************************************
 *  mDNS module-tick function, central point where all the timing occurs.
 * ****************************************************************************/
static void
pico_mdns_tick( pico_time now, void *_arg )
{
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(_arg);

    /* Update the cache */
    pico_mdns_cache_check_expiries();

    /* Update the cookies */
    pico_mdns_cookies_check_timeouts();

    /* Schedule new tick */
    pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_tick, NULL);
}

// MARK: ASYNCHRONOUS MDNS RECEPTION

/* ****************************************************************************
 *  Utility function to populate an answer vector depending on url, qtype and
 *  qclass.
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_populate_answer_vector( char *url, uint16_t qtype, uint16_t qclass )
{
    pico_mdns_record_vector anvector = {0};
    struct pico_mdns_record *record = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!url)
        return anvector;

    /* Create an answer record vector */
    if (qtype == PICO_DNS_TYPE_ANY)
        anvector = pico_mdns_record_tree_find_url(url, &MyRecords);
    else
        anvector = pico_mdns_record_tree_find_url_type(url, qtype, &MyRecords);

    /* Remove answer which aren't succesfully registered yet */
    for (i = 0; i < anvector.count; i++) {
        record = pico_mdns_record_vector_get(&anvector, i);
        if (!IS_RES_RECORD_FLAG_PROBED_SET(record->flags)) {
            pico_mdns_record_vector_delete(&anvector, i);
            continue;
        }
    }

    /* Check if question is a QU-question */
    if (PICO_MDNS_IS_MSB_SET(qclass)) {
        /* Set the SEND_UNICAST flag of all the answer records */
        for (i = 0; i < anvector.count; i++)
            PICO_MDNS_SET_FLAG(record->flags, PICO_MDNS_RECORD_SEND_UNICAST);
    }

    return anvector;
}

/* ****************************************************************************
 *  Handle a single received question
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_handle_single_question( struct pico_dns_question *question,
                                  pico_dns_packet *packet )
{
    pico_mdns_record_vector anvector = { 0 };
    struct pico_mdns_cookie *found_cookie = NULL;
    char *qname_original = NULL, *url = NULL;
    uint16_t qtype = 0, qclass = 0;

    /* Check params */
    if (!question || !packet) {
        pico_err = PICO_ERR_EINVAL;
        return anvector;
    }

    /* Decompress qname and convert to URL */
    qname_original = question->qname;
    question->qname = pico_dns_decompress_name(question->qname, packet);
    if (!question->qname) {
        mdns_dbg("Could not decompress name correctly!\n");
        return anvector;
    }
    url = pico_dns_qname_to_url(question->qname);
    mdns_dbg("Question RCVD for '%s'\n", url);

    /* Find currently active query cookie */
    found_cookie = pico_mdns_cookie_tree_find_query_cookie(question->qname);
    if (found_cookie) {
        /* Cancel the planned query-cookie */
        mdns_dbg("Query cookie found for question, suppress duplicate.\n");
        found_cookie->status = PICO_MDNS_COOKIE_STATUS_CANCELLED;
    } else {
        /* Popoluate answer vector depending on url, qtype and qclass */
        qtype = short_be(question->qsuffix->qtype);
        qclass = short_be(question->qsuffix->qclass);
        anvector = pico_mdns_populate_answer_vector(url, qtype, qclass);
    }

    /* Free the qname, with the decompression, memory was allocated */
    PICO_FREE(url);
    PICO_FREE(question->qname);
    question->qname = qname_original;
    return anvector;
}

/* ****************************************************************************
 *  Handle a single received answer
 * ****************************************************************************/
static int
pico_mdns_handle_cookie_with_answer( struct pico_mdns_cookie *cookie,
                                     struct pico_mdns_record *answer )
{
    pico_mdns_record_vector anvector = {0};
    uint8_t type = 0, status = 0;

    /* Check params */
    if (!cookie || !answer) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    type = cookie->type;
    status = cookie->status;

    if (PICO_MDNS_COOKIE_TYPE_PROBE == type &&
        PICO_MDNS_COOKIE_STATUS_ACTIVE == status) {
        /* Found cookie is a probe cookie, apply conflict resolution */
        if (pico_mdns_cookie_resolve_conflict(cookie, answer->record->rname)
            < 0)
            mdns_dbg("Could not resolve conflict correctly!\n");
    } else if (PICO_MDNS_COOKIE_TYPE_QUERY == type &&
               PICO_MDNS_COOKIE_STATUS_ACTIVE == status) {
        /* Call callback if any */
        if (cookie->callback) {
            if (pico_mdns_record_vector_add(&anvector, answer) < 0) {
                mdns_dbg("Could not create vector to pass to callback!\n");
                return -1;
            }

            /* Callback is responsible for aggregating all the records */
            cookie->callback(&anvector, NULL, cookie->arg);
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Handle a single received answer
 * ****************************************************************************/
static int
pico_mdns_handle_single_answer( struct pico_mdns_record *answer )
{
    struct pico_mdns_record *found_record = NULL;
    struct pico_mdns_cookie *found = NULL;
    char *url = NULL;
    uint16_t type = 0;

    /* Check params */
    if (!answer) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    mdns_dbg("Answer RCVD for '%s'\n", answer->record->rname);

    /* Find currently active query cookie */
    found = pico_mdns_cookie_tree_find_query_cookie(answer->record->rname);
    if (found) {
        if (pico_mdns_handle_cookie_with_answer(found, answer) < 0) {
            mdns_dbg("Could not handle found cookie correctly!\n");
            return -1;
        }
    } else {
        /* Received unsolicited answer, see if  */
        mdns_dbg("RCVD an unsolicited record!\n");

        /* Check for conflicting 'my record' */
        url = pico_dns_qname_to_url(answer->record->rname);
        if (!url) return -1;
        type = short_be(answer->record->rsuffix->rtype);
        found_record = pico_mdns_my_records_find_url_type(url, type);
        PICO_FREE(url);

        /* Resolve conflict if found */
        if (found_record)
            pico_mdns_record_resolve_conflict(found_record,
                                              answer->record->rname);
    }

    return 0;
}

/* ****************************************************************************
 *  Handle a single received authority
 * ****************************************************************************/
static int
pico_mdns_handle_single_authority( struct pico_mdns_record *answer )
{
    struct pico_mdns_cookie *found = NULL;

    /* Check params */
    if (!answer) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    mdns_dbg("Authority RCVD for '%s'\n", answer->record->rname);

    /* Find currently active probe cookie */
    found = pico_mdns_cookie_tree_find_query_cookie(answer->record->rname);
    if (found) {
        if (found->type == PICO_MDNS_COOKIE_TYPE_PROBE &&
            found->status == PICO_MDNS_COOKIE_STATUS_ACTIVE) {
            mdns_dbg("Simultaneous Probing occured, went tiebreaking...\n");
            if (pico_mdns_cookie_apply_spt(found, answer->record) < 0) {
                mdns_dbg("Could not apply S.P.T. to cookie!\n");
                return -1;
            }
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Handle a single received additional
 * ****************************************************************************/
static int
pico_mdns_handle_single_additional( struct pico_mdns_record *answer )
{
    /* Don't need this for now ... */
    IGNORE_PARAMETER(answer);
    return 0;
}

/* ****************************************************************************
 *  Handles a flat chunk of memory as if it were all questions in it.
 *  Generates record vector with responses if there are any questions for
 *  records for which this module has the authority to answer.
 * ****************************************************************************/
static pico_mdns_record_vector
pico_mdns_handle_data_as_questions ( uint8_t **ptr,
                                     uint16_t qdcount,
                                     pico_dns_packet *packet )
{
    pico_mdns_record_vector anvector = { 0 };
    pico_mdns_record_vector rvector = { 0 };
    struct pico_dns_question question;         // Temporary store question
    uint16_t i = 0;

    /* Check params */
    if (!ptr) {
        pico_err = PICO_ERR_EINVAL;
        return anvector;
    }
    if (!(*ptr) || !packet) {
        pico_err = PICO_ERR_EINVAL;
        return anvector;
    }

    for (i = 0; i < qdcount; i++) {
        /* Set qname of the question to the correct location */
        question.qname = (char *)(*ptr);

        /* Set qsuffix of the question to the correct location */
        question.qsuffix = (struct pico_dns_question_suffix *)
        (question.qname + pico_dns_namelen_comp(question.qname) + 1);

        /* Handle a single question and append the returend vector */
        rvector = pico_mdns_handle_single_question(&question, packet);

        pico_mdns_record_vector_append(&anvector, &rvector);

        /* Move to next question */
        *ptr = (uint8_t *)question.qsuffix +
        sizeof(struct pico_dns_question_suffix);
    }

    return anvector;
}

int
pico_mdns_handle_data_as_answers_generic( uint8_t **ptr,
                                          uint16_t count,
                                          pico_dns_packet *packet,
                                          uint8_t type )
{
    struct pico_mdns_record *mdns_answer = NULL;
    struct pico_dns_record answer, *copy = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!ptr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (!(*ptr) || !packet) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    for (i = 0; i < count; i++) {
        /* Set rname of the record to the correct location */
        answer.rname = (char *)(*ptr);

        /* Set rsuffix of the record to the correct location */
        answer.rsuffix = (struct pico_dns_record_suffix *)
        (answer.rname + pico_dns_namelen_comp(answer.rname) + 1u);

        /* Set rdata of the record to the correct location */
        answer.rdata = (uint8_t *) answer.rsuffix +
        sizeof(struct pico_dns_record_suffix);

        answer.rname_length = short_be((uint16_t)(strlen(answer.rname) + 1u));

        /* Make an mDNS record copy from the answer */
        copy = pico_dns_record_copy(&answer);
        if (!copy)
            return -1;
        PICO_FREE(copy->rname);
        copy->rname = pico_dns_decompress_name(answer.rname, packet);
        mdns_answer = pico_mdns_record_create_from_dns(copy);
        if (!mdns_answer) {
            pico_dns_record_delete(&copy);
            return -1;
        }

        /* Handle a single aswer */
        switch (type) {
            case 1:
                pico_mdns_handle_single_authority(mdns_answer);
                pico_mdns_record_delete(&mdns_answer);
                break;
            case 2:
                pico_mdns_handle_single_additional(mdns_answer);
                pico_mdns_record_delete(&mdns_answer);
                break;
            default:
                pico_mdns_handle_single_answer(mdns_answer);
                if (pico_mdns_cache_add_record(mdns_answer)) {
                    pico_mdns_record_delete(&mdns_answer);
                }
                break;
        }

        /* Move to next record */
        *ptr = (uint8_t *) answer.rdata + short_be(answer.rsuffix->rdlength);
    }

    return 0;
}

int
pico_mdns_handle_data_as_answers( uint8_t **ptr,
                                  uint16_t count,
                                  pico_dns_packet *packet )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, packet, 0);
}

int
pico_mdns_handle_data_as_authorities( uint8_t **ptr,
                                      uint16_t count,
                                      pico_dns_packet *packet )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, packet, 1);
}

int
pico_mdns_handle_data_as_additionals( uint8_t **ptr,
                                      uint16_t count,
                                      pico_dns_packet *packet )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, packet, 2);
}

/* ****************************************************************************
 *  Splits a mDNS record vector in two DNS record vectors, one for unicast 
 *  responses, one for multicast responses
 * ****************************************************************************/
static int
pico_mdns_sort_unicast_multicast( pico_mdns_record_vector *answers,
                                  pico_dns_record_vector *unicast_vector,
                                  pico_dns_record_vector *multicast_vector )
{
    struct pico_mdns_record *record = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!answers || !unicast_vector || !multicast_vector) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    for (i = 0; i < answers->count; i++) {
        record = pico_mdns_record_vector_get(answers, i);
        if (IS_RES_RECORD_FLAG_SEND_UNICAST_SET(record->flags))
            pico_dns_record_vector_add(unicast_vector, record->record);
        else
            pico_dns_record_vector_add(multicast_vector, record->record);
    }

    return 0;
}

/* ****************************************************************************
 *  Send DNS records as answers to a peer via unicast
 * ****************************************************************************/
static int
pico_mdns_unicast_reply( pico_dns_record_vector *unicast_vector,
                         struct pico_ip4 peer )
{
    pico_dns_packet *packet = NULL;
    union pico_address *local_addr = NULL;
    uint16_t len = 0;

    if (pico_dns_record_vector_count(unicast_vector) > 0) {
        /* Create response DNS packet */
        packet = pico_mdns_answer_create(unicast_vector, NULL, NULL, &len);
        if (!packet || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* Check if source address is on the local link */
        local_addr = (union pico_address *) pico_ipv4_source_find(&peer);
        if (!local_addr) {
            mdns_dbg("Peer not on same link!\n");
            /* Forced response via multicast */
            if (pico_mdns_send_packet(packet, len) < 0) {
                mdns_dbg("Could not send multicast response!\n");
                return -1;
            }
        } else {
            /* Send the packet via unicast */
            if (pico_mdns_send_packet_unicast(packet, len, peer) < 0) {
                mdns_dbg("Could not send unicast response!\n");
                return -1;
            }
            mdns_dbg("Unicast response sent succesfully!\n");
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Send DNS records as answers to peers via multicast
 * ****************************************************************************/
static int
pico_mdns_multicast_reply( pico_dns_record_vector *multicast_vector )
{
    pico_dns_packet *packet = NULL;
    uint16_t len = 0;

    /* If there are any unicast records */
    if (pico_dns_record_vector_count(multicast_vector) > 0) {
        /* Create response DNS packet */
        packet = pico_mdns_answer_create(multicast_vector, NULL, NULL, &len);
        if (!packet || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* Send the packet via multicast */
        if (pico_mdns_send_packet(packet, len) < 0) {
            mdns_dbg("Could not send multicast response!\n");
            return -1;
        }
        mdns_dbg("Multicast response sent succesfully!\n");
    }

    return 0;
}

/* ****************************************************************************
 *  Parses DNS records from a plain chunk of data and looks for them in the
 *  vector. If they're found, they will be removed from the vector.
 * ****************************************************************************/
static int
pico_mdns_apply_known_answer_suppression( pico_mdns_record_vector *vector,
                                          pico_dns_packet *packet,
                                          uint16_t ancount,
                                          uint8_t **data )
{
    struct pico_dns_record answer = {0}, *copy = NULL;
    struct pico_mdns_record *record = NULL;
    struct pico_mdns_record ka = {0};
    uint16_t i = 0, j = 0;

    /* Check params */
    if (!data) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (!(*data) || !vector || !packet) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    for (i = 0; i < ancount; i++) {
        /* Set rname of the record to the correct location */
        answer.rname = (char *)(*data);

        /* Set rsuffix of the record to the correct location */
        answer.rsuffix = (struct pico_dns_record_suffix *)
        (answer.rname + pico_dns_namelen_comp(answer.rname) + 1u);

        /* Set rdata of the record to the correct location */
        answer.rdata = (uint8_t *) answer.rsuffix +
        sizeof(struct pico_dns_record_suffix);

        copy = pico_dns_record_copy(&answer);
        if (!copy)
            return -1;
        copy->rname = pico_dns_decompress_name(answer.rname, packet);
        ka.record = &answer;

        /* If the answer is in the record vector */
        for (j = 0; j < vector->count; j++) {
            record = pico_mdns_record_vector_get(vector, j);
            if (pico_mdns_cmp(record, &ka) == 0) {
                if (pico_mdns_record_vector_delete(vector, i) < 0) {
                    mdns_dbg("Could not delete record from vector!\n");
                    return -1;
                }
            }
        }
        pico_dns_record_delete(&copy);
        ka.record = NULL;

        /* Move to next record */
        *data = (uint8_t *) answer.rdata + short_be(answer.rsuffix->rdlength);
    }
    return 0;
}

/* ****************************************************************************
 *  Handle a single incoming query packet without Known Answer Suppression
 * ****************************************************************************/
static int
pico_mdns_handle_query_packet( pico_dns_packet *packet, struct pico_ip4 peer )
{
    pico_mdns_record_vector anvector = { 0 };
    pico_dns_record_vector anvector_m = { 0 };
    pico_dns_record_vector anvector_u = { 0 };
    uint8_t *data = NULL;
    uint16_t qdcount = 0, ancount = 0;

    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);

    /* Generate a list of answers */
    qdcount = short_be(packet->qdcount);
    anvector = pico_mdns_handle_data_as_questions(&data, qdcount, packet);
    if (pico_mdns_record_vector_count(&anvector) == 0) {
        mdns_dbg("No records found that correspond with this query!\n");
        return 0;
    }

    /* Apply Known Answer Suppression */
    ancount = short_be(packet->ancount);
    if (pico_mdns_apply_known_answer_suppression(&anvector, packet, ancount,
                                                 &data) < 0){
        mdns_dbg("Could not apply known answer suppression!\n");
        return -1;
    }

    /* Sort the records in 2 two vectors by unicast or multicast */
    if (pico_mdns_sort_unicast_multicast(&anvector, &anvector_u,
                                         &anvector_m) < 0) {
        mdns_dbg("Could not sort answers into unicast/multicast vector!\n");
        return -1;
    }

    if (pico_mdns_unicast_reply(&anvector_u, peer) < 0)
        mdns_dbg("Could not sent reply via unicast!\n");

    if (pico_mdns_multicast_reply(&anvector_m) < 0)
        mdns_dbg("Could not sent reply via multicast!\n");

    return 0;
}

/* ****************************************************************************
 *  Handle a probe packet
 * ****************************************************************************/
static int
pico_mdns_handle_probe_packet( pico_dns_packet *packet, struct pico_ip4 peer )
{
    pico_mdns_record_vector anvector = { 0 };
    pico_dns_record_vector anvector_m = { 0 };
    pico_dns_record_vector anvector_u = { 0 };
    uint8_t *data = NULL;

    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);

    /* Generate a list of answers */
    anvector = pico_mdns_handle_data_as_questions(&data,
                                                  short_be(packet->qdcount),
                                                  packet);

    /* Check if we need to tiebreak simultaneous probing */
    if (pico_mdns_handle_data_as_authorities(&data, short_be(packet->nscount),
                                             packet) < 0)
        mdns_dbg("No Simultaneous Probe Tiebreaking needed!\n");

    if (pico_mdns_record_vector_count(&anvector) == 0) {
        mdns_dbg("No records found that correspond with this query!\n");
        return 0;
    }

    /* Sort the records in 2 two vectors by unicast or multicast */
    if (pico_mdns_sort_unicast_multicast(&anvector, &anvector_u, &anvector_m)
        < 0) {
        mdns_dbg("Could not sort answers into unicast/multicast vector!\n");
        return -1;
    }

    if (pico_mdns_unicast_reply(&anvector_u, peer) < 0)
        mdns_dbg("Could not sent reply via unicast!\n");

    if (pico_mdns_multicast_reply(&anvector_m) < 0)
        mdns_dbg("Could not sent reply via multicast!\n");

    return 0;
}

/* ****************************************************************************
 *  Handle a DNS response packet
 * ****************************************************************************/
static int
pico_mdns_handle_response_packet( pico_dns_packet *packet,
                                  struct pico_ip4 peer )
{
    uint8_t *data = NULL;

    /* We can't do anything with the peer in a response */
    IGNORE_PARAMETER(peer);

    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);

    /* Generate a list of answers */
    if (pico_mdns_handle_data_as_answers(&data, short_be(packet->ancount),
                                         packet) < 0) {
        mdns_dbg("Could not handle data as answers\n");
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Parses an incoming packet and handles it according to the type of packet
 * ****************************************************************************/
static int
pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer)
{
    pico_dns_packet *packet = NULL; // DNS packet received
    uint16_t qdcount = 0, ancount = 0, authcount = 0, addcount = 0;

    IGNORE_PARAMETER(buflen);

    /* Parse buf into packet */
    packet = (pico_dns_packet *) buf;

    /* Determine the count of questions and answers */
    qdcount = short_be(packet->qdcount);
    ancount = short_be(packet->ancount);
    authcount = short_be(packet->nscount);
    addcount = short_be(packet->arcount);
    mdns_dbg(">>>>>>> QDcount: %u, ANcount: %u, NScount: %u, ARcount: %u\n",
             qdcount, ancount, authcount, addcount);

    IGNORE_PARAMETER(addcount);

    /* Determine what kind of DNS packet we have to deal with */
    if ((qdcount > 0)) {
        if (authcount > 0) {
            mdns_dbg(">>>>>>> RCVD a mDNS probe query:\n");
            /* Packet is probe query */
            if (pico_mdns_handle_probe_packet(packet, peer) < 0) {
                mdns_dbg("Could not handle mDNS probe query!\n");
                return -1;
            }
        } else {
            mdns_dbg(">>>>>>> RCVD a plain mDNS query:\n");
            /* Packet is a plain query */
            if (pico_mdns_handle_query_packet(packet, peer) < 0) {
                mdns_dbg("Could not handle plain DNS query!\n");
                return -1;
            }
        }
    } else {
        if (ancount > 0) {
            mdns_dbg(">>>>>>> RCVD a mDNS response:\n");
            /* Packet is a response */
            if (pico_mdns_handle_response_packet(packet, peer) < 0) {
                mdns_dbg("Could not handle DNS response!\n");
                return -1;
            }
        } else {
            /* Here went something wrong... */
            mdns_dbg("RCVD Packet contains no questions or answers...\n");
            return -1;
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Callback for UDP IPv4 socket events
 * ****************************************************************************/
static void
pico_mdns_event4( uint16_t ev, struct pico_socket *s )
{
    char recvbuf[PICO_MDNS_MTU] = { 0 };
    struct pico_ip4 peer = { 0 };
    int pico_read = 0;
    uint16_t port = 0;
    char host[30];

    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        mdns_dbg("\n>>>>>>> READ EVENT! <<<<<<<\n");
        /* Receive while data is available in socket buffer */
        while((pico_read = pico_socket_recvfrom(s, recvbuf, PICO_MDNS_MTU,
                                                &peer, &port)) > 0) {
            pico_ipv4_to_string(host, peer.addr);
            mdns_dbg("Received data from %s:%u\n", host, short_be(port));
            /* Handle the MDNS data received */
            pico_mdns_recv(recvbuf, pico_read, peer);
        }
    } else if (ev == PICO_SOCK_EV_CLOSE) {
        mdns_dbg("Socket is closed. Bailing out.\n");
        return;
    } else {
        mdns_dbg("Socket Error received. Bailing out.\n");
        return;
    }
}

// MARK: ADDRESS RESOLUTION

static void
pico_mdns_send_query_packet( pico_time now, void *arg )
{
    struct pico_mdns_cookie *query_cookie = NULL;
    pico_dns_packet *packet = NULL;
    uint16_t len = 0;

    IGNORE_PARAMETER(now);

    /* Check params */
    if (!arg) {
        pico_err = PICO_ERR_EINVAL;
        return;
    }

    /* Parse in the cookie */
    query_cookie = (struct pico_mdns_cookie *)arg;
    if (query_cookie->type != PICO_MDNS_COOKIE_TYPE_QUERY)
        return;

    /* Create an mDNS answer */
    packet = pico_mdns_query_create(&(query_cookie->qvector), NULL,
                                    NULL, NULL, &len);
    if (!packet) {
        mdns_dbg("Could not create query packet!\n");
    }

    /* Send the mDNS answer unsollicited via multicast */
    if (query_cookie->status != PICO_MDNS_COOKIE_STATUS_CANCELLED) {
        query_cookie->status = PICO_MDNS_COOKIE_STATUS_ACTIVE;
        if(pico_mdns_send_packet(packet, len) != (int)len) {
            mdns_dbg("Send error occured!\n");
            return;
        }
        mdns_dbg("DONE - Sent query.\n");
    } else {
        mdns_dbg("DONE - Duplicate query suppressed.\n");
        if (query_cookie->send_timer)
            pico_timer_cancel(query_cookie->send_timer);
        pico_mdns_cookie_tree_del_cookie(query_cookie);
    }
}

static int
pico_mdns_getrecord_generic( const char *url, uint16_t type,
                             void (*callback)(pico_mdns_record_vector *,
                                              char *,
                                              void *),
                             void *arg)
{
    struct pico_mdns_cookie *query_cookie = NULL;
    pico_dns_question_vector qvector = { 0 };
    pico_mdns_record_vector anvector = { 0 };
    struct pico_dns_question *question = NULL;
    uint16_t qlen = 0;

    /* Create a single question */
    question = pico_mdns_question_create(url, &qlen, PICO_PROTO_IPV4, type,
                                         PICO_MDNS_QUESTION_FLAG_NO_PROBE, 0);
    if (!question) {
        mdns_dbg("question_create returned NULL!\n");
        return -1;
    }

    /* Add the question to a vector */
    if (pico_dns_question_vector_add(&qvector, question) < 0) {
        mdns_dbg("Could not add question to vector!\n");
        return -1;
    }

    /* Create a mDNS cookie to send */
    query_cookie = pico_mdns_cookie_create(qvector, anvector, 1,
                                           PICO_MDNS_COOKIE_TYPE_QUERY,
                                           callback, arg);
    if (!query_cookie) {
        mdns_dbg("cookie_create returned NULL!\n");
        return -1;
    }

    /* Add the query cookie to the end of Cookies
     to be able to find it afterwards */
    if (pico_mdns_cookie_tree_add_cookie(query_cookie) < 0) {
        mdns_dbg("Could not append cookie to Cookies!\n");
        return -1;
    }

    pico_timer_add((pico_rand() % 120) + 20, pico_mdns_send_query_packet,
                   (void *)query_cookie);

    return 0;
}

int
pico_mdns_getrecord( const char *url, uint16_t type,
                     void (*callback)(pico_mdns_record_vector *,
                                      char *,
                                      void *),
                     void *arg )
{
    pico_mdns_record_vector cache_hits = { 0 };

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* First, try to find records in the cache */
    cache_hits = pico_mdns_record_tree_find_url_type(url, type, &Cache);
    if (pico_mdns_record_vector_count(&cache_hits) > 0) {
        mdns_dbg("CACHE HIT! Passed copies of cache records to callback.\n");
        callback(&cache_hits, NULL, arg);
    } else {
        mdns_dbg("CACHE MISS! Trying to resolve URL '%s'...\n", url);
        return pico_mdns_getrecord_generic(url, type, callback, arg);
    }

    return 0;
}

// MARK: PROBING & ANNOUNCING

/* ****************************************************************************
 *  Utility function to create an announcement packet from an mDNS packet
 *  cookie passed in [arg] and send it on the wire.
 * ****************************************************************************/
static void
pico_mdns_send_announcement_packet( pico_time now, void *arg )
{
    pico_dns_packet *packet = NULL;
    struct pico_mdns_cookie *cookie = NULL;
    struct pico_mdns_record *record = NULL;
    pico_dns_record_vector anvector = { 0 };
    uint16_t i = 0, len = 0;

    IGNORE_PARAMETER(now);

    /* Parse argument */
    cookie = (struct pico_mdns_cookie *)arg;

    if (cookie->type != PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT)
        return;

    if (cookie->count > 0) {
        cookie->status = PICO_MDNS_COOKIE_STATUS_ACTIVE;
        /* Iterate over records in cookie */
        for (i = 0; i < cookie->rvector.count; i++) {
            record = pico_mdns_record_vector_get(&(cookie->rvector), i);
            /* Add DNS records to announcement records */
            if (pico_dns_record_vector_add(&anvector, record->record) < 0) {
                mdns_dbg("Could not append DNS resource record to list\n");
            }
        }

        /* Create an mDNS answer */
        packet = pico_mdns_answer_create(&anvector, NULL, NULL, &len);
        if (!packet) {
            mdns_dbg("Could not create announcement packet!\n");
            return;
        }

        /* Send the mDNS answer unsollicited via multicast */
        if(pico_mdns_send_packet(packet, len) != (int)len) {
            mdns_dbg("Send error occured!\n");
            return;
        }

        /* Decrement the count */
        cookie->count--;
        mdns_dbg("DONE - Sent announcement!\n");

        /*  The Multicast DNS responder MUST send at least two unsolicited
         *  responses, one second apart. */
        if (cookie->count > 0)
            cookie->send_timer = pico_timer_add(1000,
                                        pico_mdns_send_announcement_packet,
                                                (void *)cookie);
        else
            pico_mdns_send_announcement_packet(0, (void *)cookie);
    } else {
        cookie->status = PICO_MDNS_COOKIE_STATUS_INACTIVE;
        pico_mdns_my_records_claimed(cookie->rvector, cookie->callback,
                                     cookie->arg);
        /* Try to delete the cookie */
        if (pico_mdns_cookie_tree_del_cookie(cookie) < 0) {
            mdns_dbg("Could not delete cookie after initialisation!\n");
            return;
        }

        mdns_dbg("DONE - Announcing.\n");
    }
}

/* ****************************************************************************
 *  Utility function to announce all 'my records' which passed the probed-
 *  state. When all the records are announced for a particular claim ID,
 *  the callback passed in this function will be called.
 * ****************************************************************************/
static int
pico_mdns_announce( void (*callback)(pico_mdns_record_vector *,
                                     char *,
                                     void *),
                    void *arg )
{
    struct pico_mdns_cookie *announcement_cookie = NULL;
    pico_mdns_record_vector rvector = { 0 };
    pico_dns_question_vector qvector = { 0 };

    /* Check params */
    if (!callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    IGNORE_PARAMETER(arg);

    /* Find out which resource records can be announced */
    rvector = pico_mdns_my_records_find_probed();
    if (pico_mdns_record_vector_count(&rvector) == 0)
        return 0;

    /* Create a mDNS packet cookie */
    announcement_cookie = pico_mdns_cookie_create(qvector, rvector, 2,
                                        PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT,
                                                  callback, arg);
    if (!announcement_cookie) {
        mdns_dbg("cookie_create returned NULL!\n");
        return -1;
    }

    /* Send a first unsollicited announcement */
    pico_mdns_send_announcement_packet(0, announcement_cookie);
    mdns_dbg("DONE - Started announcing.\n");

    return 0;
}

/* ****************************************************************************
 *  Utility functions to create an probe packet from an mDNS packet
 *  cookie passed in [arg] and send it on the wire.
 * ****************************************************************************/
static void
pico_mdns_send_probe_packet( pico_time now, void *arg )
{
    pico_dns_packet *packet = NULL; // DNS packet we need to create
    struct pico_mdns_cookie *cookie = NULL; // To parse argument in arg
    struct pico_mdns_record *record = NULL;
    struct pico_mdns_record *found = NULL;
    pico_dns_record_vector nsvector = { 0 };
    uint16_t i = 0, len = 0;

    IGNORE_PARAMETER(now);

    /* Check params */
    if (!arg || !mdns_sock_ipv4) {
        mdns_dbg("Socket not initialised, did you call pico_mdns_init()?\n");
        pico_err = PICO_ERR_EINVAL;
        return;
    }

    /* Parse argument */
    cookie = (struct pico_mdns_cookie *)arg;
    cookie->status = PICO_MDNS_COOKIE_STATUS_ACTIVE;
    if (cookie->type != PICO_MDNS_COOKIE_TYPE_PROBE)
        return;

    if (cookie->count > 0) {
        for (i = 0; i < cookie->rvector.count; i++) {
            record = pico_mdns_record_vector_get(&(cookie->rvector), i);
            /* We don't want the cache flush bit set here */
            PICO_MDNS_CLR_MSB_BE(record->record->rsuffix->rclass);
            pico_dns_record_vector_add(&nsvector, record->record);
        }

        /* Create an mDNS answer */
        packet = pico_mdns_query_create(&(cookie->qvector), NULL, &nsvector,
                                        NULL, &len);
        if (!packet) {
            mdns_dbg("Could not create probe packet!\n");
            return;
        }

        /* Send the mDNS answer unsollicited via multicast */
        if(pico_mdns_send_packet(packet, len) != (int)len) {
            mdns_dbg("Send error occured!\n");
            return;
        }
        cookie->count--;
        mdns_dbg("DONE - Sent probe!\n");

        /*  250 ms after the first query, the host should send a second;
         *  then, 250 ms after that, a third. */
        cookie->send_timer = pico_timer_add(250, pico_mdns_send_probe_packet,
                                            (void *)cookie);
    } else {
        mdns_dbg("DONE - Probing.\n");
        for (i = 0; i < cookie->rvector.count; i++) {
            record = pico_mdns_record_vector_get(&(cookie->rvector), i);
            /* Set the cache flush bit again */
            PICO_MDNS_SET_MSB_BE(record->record->rsuffix->rclass);
            found = pico_mdns_record_tree_find_record(record, &MyRecords);
            if (found) /* Set probed flag of corresponding my record */
                PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RECORD_PROBED);
        }

        /* Delete all the question in the cookie */
        if (pico_dns_question_vector_destroy(&(cookie->qvector)) < 0) {
            mdns_dbg("Could not delete all probe questions!\n");
        }

        /* Start announcing the records */
        cookie->count = 2;
        cookie->type = PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT;
        pico_mdns_send_announcement_packet(0, (void*) cookie);
    }

    return;
}

/* ****************************************************************************
 *  Utility functions to add a new probe question to the question vector, if a
 *  name is already in the vector, it will not be appended again.
 * ****************************************************************************/
static int
pico_mdns_add_probe_question( pico_dns_question_vector *vector,
                              char *name )
{
    struct pico_dns_question *found = NULL, *new = NULL;
    char *url = NULL;
    uint16_t qlen = 0;
    uint8_t flags = 0;

    /* Try to find an existing question in the vector */
    found = pico_dns_question_vector_find_name(vector, name);
    if (!found) {
        /* Set the flags */
        if (PICO_MDNS_PROBE_UNICAST)
            flags = (PICO_MDNS_QUESTION_FLAG_PROBE |
                     PICO_MDNS_QUESTION_FLAG_UNICAST_RES);
        else
            flags = PICO_MDNS_QUESTION_FLAG_PROBE;

        /* Convert name to URL */
        url = pico_dns_qname_to_url(name);
        if (!url)
            return -1;

        /* Create a new probe question */
        new = pico_mdns_question_create(url, &qlen, PICO_PROTO_IPV4,
                                        PICO_DNS_TYPE_ANY, flags, 0);

        /* Free memory */
        PICO_FREE(url);
        url = NULL;

        /* Append probe question to question list */
        if (pico_dns_question_vector_add(vector, new) < 0) {
            mdns_dbg("Could not add question to question vector!\n");
            return -1;
        }
    }

    return 0;
}

/* ****************************************************************************
 *  Try to find any of my records that need to be probed, and probe them
 * ****************************************************************************/
static int pico_mdns_probe( void (*callback)(pico_mdns_record_vector *,
                                             char *,
                                             void *),
                            void *arg )
{
    struct pico_mdns_cookie *probe_cookie = NULL;
    struct pico_mdns_record *record = NULL;
    pico_dns_question_vector qvector = { 0 };
    pico_mdns_record_vector rvector = { 0 };
    uint16_t i = 0;

    /* Check params */
    if (!callback) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Find my records that need to pass the probing step first */
    rvector = pico_mdns_my_records_find_to_probe();
    if (pico_mdns_record_vector_count(&rvector)) {
        /* Iterate over the found records */
        for (i = 0; i < pico_mdns_record_vector_count(&rvector); i++) {
            record = pico_mdns_record_vector_get(&rvector, i);
            /* Find a probe question for the record name */
            if (pico_mdns_add_probe_question(&qvector, record->record->rname)
                < 0) {
                mdns_dbg("Could not add probe question to vector!\n");
                return -1;
            }
        }

        /* Create a mDNS packet to send */
        probe_cookie = pico_mdns_cookie_create(qvector, rvector, 3,
                                               PICO_MDNS_COOKIE_TYPE_PROBE,
                                               callback, arg);
        if (!probe_cookie) {
            mdns_dbg("Cookie_create returned NULL @ probe()!\n");
            return -1;
        }
        if (pico_mdns_cookie_tree_add_cookie(probe_cookie) < 0) {
            mdns_dbg("Could not append cookie to Cookies!\n");
            return -1;
        }

        /*  When the host is ready to send his probe query he SHOULD delay it's
            transmission with a randomly chosen time between 0 and 250 ms. */
        probe_cookie->send_timer = pico_timer_add(pico_rand() % 250,
                                                  pico_mdns_send_probe_packet,
                                                  (void *)probe_cookie);
        mdns_dbg("DONE - Started probing.\n");
    }

    return 0;
}

// MARK: API functions

/* ****************************************************************************
 *  Claim or reclaim all the mDNS records contained in an mDNS record vector
 *  at once.
 * ****************************************************************************/
static int
pico_mdns_claim_generic( pico_mdns_record_vector vector,
                         uint8_t reclaim,
                         void (*callback)(pico_mdns_record_vector *,
                                          char *,
                                          void *),
                         void *arg )
{
    /* Check if arguments are passed correctly */
    if (!callback) {
        mdns_dbg("NULL pointers passed to 'pico_mdns_claim()'!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check if module is initialised */
    if (!mdns_sock_ipv4) {
        mdns_dbg("Socket not initialised, did you call 'pico_mdns_init()'?\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* 1.) Appending records to 'my records' */
    vector = pico_mdns_my_records_add(vector, reclaim);
    
    /* 2a.) Try to probe any records */
    pico_mdns_probe(callback, arg);

    /* 2b.) Try to announce any records */
    pico_mdns_announce(callback, arg);

    return 0;
}

/* ****************************************************************************
 *  Claim all the mDNS records contained in an mDNS record vector at once.
 * ****************************************************************************/
int
pico_mdns_claim( pico_mdns_record_vector record_vector,
                 void (*callback)(pico_mdns_record_vector *,
                                  char *,
                                  void *),
                 void *arg )
{
    return pico_mdns_claim_generic(record_vector, 0, callback, arg);
}

/* ****************************************************************************
 *  Reclaim all the mDNS records contained in an mDNS record vector at once.
 * ****************************************************************************/
static int
pico_mdns_reclaim( pico_mdns_record_vector record_vector,
                   void (*callback)(pico_mdns_record_vector *,
                                    char *,
                                    void *),
                   void *arg )
{
    return pico_mdns_claim_generic(record_vector, 1, callback, arg);
}

/* ****************************************************************************
 *  Set the hostname for this machine. Claims it automatically as a unique
 *  'A' record for the local address of the bound socket.
 * ****************************************************************************/
int
pico_mdns_set_hostname( const char *url, void *arg )
{
    pico_mdns_record_vector vector = { 0 };
    struct pico_mdns_record *record = NULL;

    /* Check params */
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check if module is initialised */
    if (!mdns_sock_ipv4) {
        mdns_dbg("mDNS socket not initialised, did you call 'pico_mdns_init()'?\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Check if hostname is already set */
    if (hostname)
        PICO_FREE(hostname);

    hostname = PICO_ZALLOC(strlen(url) + 1);
    if (!hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    strcpy(hostname, url);

    /* Create an A record for hostname */
    record = pico_mdns_record_create(hostname,
                                (void*)&(mdns_sock_ipv4->local_addr.ip4.addr),
                                     4, PICO_DNS_TYPE_A, PICO_MDNS_DEFAULT_TTL,
                                     (PICO_MDNS_RECORD_UNIQUE |
                                      PICO_MDNS_RECORD_HOSTNAME));
    if (!record) {
        mdns_dbg("Could not create A record for hostname!\n");
        return -1;
    }

    /* TODO: Create a reverse resolution record */

    /* Add the record a vector */
    if (pico_mdns_record_vector_add(&vector, record) < 0) {
        mdns_dbg("Could not add hostname record to vector!\n");
        pico_mdns_record_delete(&record);
        return -1;
    }

    /* Try to claim the record */
    if (pico_mdns_claim(vector, init_callback, arg) < 0) {
        mdns_dbg("Could not claim record for hostname %s!\n", url);
        pico_mdns_record_vector_destroy(&vector);
        return -1;
    }

    return 0;
}

/* ****************************************************************************
 *  Returns the hostname for this machine
 * ****************************************************************************/
const char *
pico_mdns_get_hostname( void )
{
    /* Check if module is initialised */
    if (!mdns_sock_ipv4) {
    mdns_dbg("mDNS socket not initialised, did you call 'pico_mdns_init()'?\n");
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    return (const char *)hostname;
}

/* ****************************************************************************
 *  Initialises the global mDNS socket and sets the hostname for this machine.
 *  Calls cb_initialised when succeeded.
 *  [flags] is for future use. f.e. Opening a IPv4 multicast socket or an
 *  IPv6 one or both.
 * ****************************************************************************/
int
pico_mdns_init( const char *_hostname,
               struct pico_ipv4_link *link,
               uint8_t flags,
               void (*callback)(pico_mdns_record_vector *,
                                char *,
                                void *),
               void *arg )
{
    struct pico_ip_mreq mreq4;
    uint16_t proto4 = PICO_PROTO_IPV4;
    uint16_t port = 0;
    uint16_t loop = 0;   // Loopback = 0
    uint16_t ttl = 255;  // IP TTL SHOULD = 255

    /* For now */
    IGNORE_PARAMETER(flags);

    /* Initialise port */
    port = short_be(mdns_port);

    /* Check callbcak parameter */
    if(!callback || !_hostname || !link) {
        mdns_dbg("No callback function suplied!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Open global IPv4 mDNS socket */
    mdns_sock_ipv4 = pico_socket_open(proto4,
                                      PICO_PROTO_UDP,
                                      &pico_mdns_event4);
    if(!mdns_sock_ipv4) {
        mdns_dbg("Open returned empty IPv4 socket\n");
        return -1;
    }

    /* Convert the mDNS IPv4 destination address to struct */
    if(pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4,
                           &mreq4.mcast_group_addr.addr) != 0) {
        mdns_dbg("String to IPv4 error\n");
        return -1;
    }

    /* Receive data on any network interface */
    mreq4.mcast_link_addr = inaddr_any;

    /* Don't want the multicast data to be looped back to the host */
    if(pico_socket_setoption(mdns_sock_ipv4,
                             PICO_IP_MULTICAST_LOOP,
                             &loop) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_LOOP failed\n");
        return -1;
    }

    /* Tell the stack we're interested in this particular multicast group */
    if(pico_socket_setoption(mdns_sock_ipv4,
                             PICO_IP_ADD_MEMBERSHIP,
                             &mreq4) < 0) {
        mdns_dbg("socket_setoption PICO_IP_ADD_MEMBERSHIP failed\n");
        return -1;
    }

    /* RFC:
     *  All multicast responses (including answers sent via unicast) SHOULD
     *  be send with IP TTL set to 255 for backward-compatibility reasons
     */
    if(pico_socket_setoption(mdns_sock_ipv4,
                             PICO_IP_MULTICAST_TTL,
                             &ttl) < 0) {
        mdns_dbg("socket_setoption PICO_IP_MULTICAST_TTL failed\n");
        return -1;
    }
    
    /* Bind to mDNS port */
    if (pico_socket_bind(mdns_sock_ipv4, &(link->address), &port) != 0) {
        mdns_dbg("Bind error!\n");
        return -1;
    }
    
    /* Set the global init callback variable */
    init_callback = callback;
    
    /* Set the hostname for this machine */
    if (pico_mdns_set_hostname(_hostname, arg) < 0) {
        mdns_dbg("Setting hostname returned error\n");
        return -1;
    }
    
    pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_tick, NULL);
    
    return 0;
}

#endif /* PICO_SUPPORT_MDNS */