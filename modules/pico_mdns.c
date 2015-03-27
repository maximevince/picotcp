/* ****************************************************************************
 *  PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 *  See LICENSE and COPYING for usage.
 *  .
 *  Author: Toon Stegen
 * ****************************************************************************/

/* picoTCP */
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_mdns.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_MDNS

/* Debugging */
//#define mdns_dbg(...) do {} while(0)
#define mdns_dbg dbg

#define DEBUG(s, args...) mdns_dbg("pico_err: %d: %s", pico_err, s, ##args)

#define PICO_MDNS_QUERY_TIMEOUT (10000) /* Ten seconds */
#define PICO_MDNS_RR_TTL_TICK (1000)    /* One second */

/* mDNS MTU size */
#define PICO_MDNS_MTU 1400u

/* Constant strings */
#define PICO_ARPA_IPV4_SUFFIX ".in-addr.arpa"
#define PICO_ARPA_IPV6_SUFFIX ".IP6.ARPA"

/* Cookie flags */
#define PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT 0x01u
#define PICO_MDNS_COOKIE_TYPE_ANSWER 0x02u
#define PICO_MDNS_COOKIE_TYPE_QUERY 0x04u
#define PICO_MDNS_COOKIE_TYPE_PROBE 0x08u

#define PICO_MDNS_COOKIE_ACTIVE 0xffu
#define PICO_MDNS_COOKIE_INACTIVE 0x00u

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
#define PICO_MDNS_RES_RECORD_ADDITIONAL 0x08u
#define PICO_MDNS_RES_RECORD_SEND_UNICAST 0x10u
#define PICO_MDNS_RES_RECORD_PROBED 0x40u
#define PICO_MDNS_RES_RECORD_CLAIMED 0x80u

#define IS_RES_RECORD_FLAG_CLAIM_SHARED_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_SHARED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_CLAIM_UNIQUE_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_SHARED) ? 0 : 1)
#define IS_RES_RECORD_FLAG_PROBED_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_PROBED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_CLAIMED_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_CLAIMED) ? 1 : 0)
#define IS_RES_RECORD_FLAG_ADDITIONAL_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_ADDITIONAL) ? 1 : 0)
#define IS_RES_RECORD_FLAG_SEND_UNICAST_SET(x) \
        (((x) & PICO_MDNS_RES_RECORD_SEND_UNICAST) ? 1 : 0)

/* Set and Clear MSB of BE short */
#define PICO_MDNS_SET_MSB_BE(x) (x = x | (uint16_t)(0x0080u))
#define PICO_MDNS_CLR_MSB_BE(x) (x = x & (uint16_t)(0xff7fu))
#define PICO_MDNS_IS_MSB_SET(x) (((x & 0x8000u) >> 15u) ? 1 : 0)

#define PICO_MDNS_SET_FLAG(x, b) (x = ((x) | (uint8_t)(b)))
#define PICO_MDNS_CLR_FLAG(x, b) (x = ((x) & (~((uint8_t)(b)))

static struct pico_ip4 inaddr_any = { 0 };

/* Global socket and port for all mdns communication */
static struct pico_socket *mdns_sock_ipv4 = NULL;

/* RFC:
 *  fully compliant mDNS Querier MUST send its Multicast DNS queries from
 *  UDP source port 5353, and MUST listen for Multicast DNS replies sent
 *  to UDP destination port 5353 at the mDNS link-local multicast address
 *  (224.0.0.251 and/or its IPv6 equivalent FF02::FB)
 */
static uint16_t mdns_port = 5353u;

static char *hostname = NULL;

/* ****************************************************************************
 * Contents can be either for probe-, query- or answer-cookies
 * ****************************************************************************/
struct pico_mdns_cookie_contents
{
    pico_dns_question_list *questions;  // Questions
    pico_mdns_res_record_list *records; // Records (Depends on context)
};

/* ****************************************************************************
 *  mDNS cookie
 * ****************************************************************************/
struct pico_mdns_cookie
{
    struct pico_mdns_cookie_contents *contents; // Cookie contents
    uint8_t count;                              // Times to send the query
    uint8_t flags;                              // ... | uni/multi | probe |
    uint8_t status;                             // Active status
    struct pico_timer *timer;                   // For timer events
    void (*callback)(char *, void *);           // Callback
    void *arg;                                  // Argument to pass to callback
    struct pico_mdns_cookie *next;              // Possibility to create a list
};

/* ****************************************************************************
 *  A list of mDNS cookies is just the same
 * ****************************************************************************/
typedef struct pico_mdns_cookie pico_mdns_cookie_list;

/* ****************************************************************************
 *  mDNS cookie old
 * ****************************************************************************/
struct pico_mdns_cookie_old
{
    pico_dns_packet *packet;          // Pointer to DNS packet
    char *qname;                      // Hostname being queried
    uint16_t qtype;                   // qtype
    uint16_t qclass;                  // qclass
    uint8_t count;                    // Number of packets to send
    uint8_t flags;                    // Flags: ... | uni/multi | probe |
    uint16_t len;                     // Length of packet
    struct pico_timer *timer;         // For Timer events
    void (*callback)(char *, void *); // Callback
    void *arg;                        // Argument to pass to callback
};

/* ****************************************************************************
 *  Contains information about a cache record
 * ****************************************************************************/
struct pico_mdns_cache_rr
{
    char *url;                              // Hostname
    struct pico_dns_res_record_suffix *suf; // Type, Class, TTL and rdata length
    char *rdata;                            // Resource Record Data
    struct pico_timer *timer;               // For Timer events
};


static int
pico_mdns_cookie_list_delete_cookie( struct pico_mdns_cookie *cookie,
                                     pico_mdns_cookie_list **cookies );
static int
pico_mdns_cookie_delete( struct pico_mdns_cookie **cookie );
static int
pico_mdns_cookie_contents_delete( struct pico_mdns_cookie_contents **contents );
static int
pico_mdns_res_record_am_i_lexi_later( struct pico_mdns_res_record *my_record,
                                      struct pico_mdns_res_record *peer_record);
static void
pico_mdns_send_probe_packet( pico_time now, void *arg );

/* List containing packet cookies */
static pico_mdns_cookie_list *PacketCookies = NULL;

/* List containing 'my records' */
static pico_mdns_res_record_list *MyRecords = NULL;

// MARK: MDNS PACKET UTILITIES

/* ****************************************************************************
 *  Sends an mdns packet on the global socket
 * ****************************************************************************/
static int
pico_mdns_send_packet(pico_dns_packet *packet, uint16_t len)
{
    struct pico_ip4 dst4;
    
    /* Send packet to IPv4 socket */
    pico_string_to_ipv4(PICO_MDNS_DEST_ADDR4, &dst4.addr);
    return pico_socket_sendto(mdns_sock_ipv4,
                              packet,
                              (int)len,
                              &dst4,
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
    return pico_socket_sendto(mdns_sock_ipv4,
                              packet,
                              (int)len,
                              &peer,
                              short_be(mdns_port));
}

// MARK: COOKIE UTILITIES

static int
pico_mdns_cookie_apply_spt( struct pico_mdns_cookie *cookie,
                            struct pico_dns_res_record *answer )
{
    struct pico_mdns_res_record *my_record = NULL;
    struct pico_mdns_res_record peer_record;
    int ret = 0;
    
    /* Check params */
    if (!cookie || !answer) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (cookie->flags != PICO_MDNS_COOKIE_TYPE_PROBE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    cookie->status = PICO_MDNS_COOKIE_INACTIVE;
    peer_record.record = answer;
    
    /* Implement Simultaneous Probe Tiebreaking */
    my_record = pico_mdns_res_record_list_find(&peer_record,
                                               cookie->contents->records);
    if (!my_record) {
        mdns_dbg("This is weird!\n");
        return -1;
    }
    
    ret = pico_mdns_res_record_am_i_lexi_later(my_record, &peer_record);
    if (ret > 0) {
        mdns_dbg("My record is lexographically later! Yay!\n");
        cookie->status = PICO_MDNS_COOKIE_ACTIVE;
    } else if (ret == 0) {
        pico_timer_cancel(cookie->timer);
        cookie->count = 3;
        cookie->timer = pico_timer_add(1000,
                                       pico_mdns_send_probe_packet,
                                       (void *)cookie);
        mdns_dbg("Probing postponed with 1s because of S.P.T.\n");
    } else {
        mdns_dbg("Checking for lexographically later failed!\n");
        return -1;
    }
    
    return 0;
}

static char *
pico_mdns_resolve_name_conflict( char rname[] )
{
    /* New rname and size with conflict resolved */
    char *new_rname = NULL;
    uint16_t new_rlen = 0;
    
    /* To store the suffix-strings in */
    char *opening_bracket_index = NULL;
    char *closing_bracket_index = NULL;
    uint8_t suffix_is_present = 0;
    uint8_t s_i = 0;
    
    /* To store the suffix-strings in */
    char suffix[5] = { 0 };
    char new_suffix[5] = { 0 };
    
    /* To convert suffix string to number */
    char *str = NULL;
    uint16_t temp = 0;
    
    /* To iterate over rname */
    char *i = 0;
    
    /* Check params */
    if (!rname) {
        return NULL;
    }
    
    for (i = rname + 1; i < ((rname + 1) + *rname); i++) {
        /* Find the first opening bracket */
        if (*i == '(') {
            opening_bracket_index = i;
            suffix_is_present = 1;
        } else {
            /* Check if what follows is numeric and copy if so */
            if (opening_bracket_index && i > opening_bracket_index) {
                if (*i < '0' || *i > '9') {
                    if (*i == ')') {
                        closing_bracket_index = i;
                    } else {
                        suffix_is_present = 0;
                    }
                } else {
                    suffix[s_i++] = *i;
                }
            }
        }
    }
    
    if (suffix_is_present) {
        /* If suffix is '()' */
        if (strlen(suffix) == 0) {
            new_rlen = (uint16_t)(strlen(rname) + 1);
            strcpy(new_suffix, "2");
        } else {
            /* If suffix is numeric update the number & generate new suffix */
            str = suffix;
            while (*str >= '0' && *str <= '9')
                temp = temp * 10 + *str++ - '0';
            temp++;
            sprintf(new_suffix, "%u", temp);
            new_rlen = strlen(rname) + (strlen(new_suffix) - strlen(suffix));
        }
    } else {
        /* If no suffix is present at all */
        opening_bracket_index = rname + rname[0];
        closing_bracket_index = opening_bracket_index + 1;
        new_rlen = strlen(rname) + 4u;
        strcpy(new_suffix, " (2)");
    }
    
    /* Provide space for the new name */
    new_rname = (char *)malloc(new_rlen + 1u);
    if (!new_rname) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Assemble the new name again */
    memcpy(new_rname, rname, opening_bracket_index - rname + 1);
    strcpy(new_rname + (opening_bracket_index - rname) + 1, new_suffix);
    strcpy(new_rname + (opening_bracket_index - rname) + strlen(new_suffix) + 1, closing_bracket_index);
    new_rname[0] += strlen(new_rname) - strlen(rname);
    
    return new_rname;
}

static int
pico_mdns_cookie_resolve_conflict( struct pico_mdns_cookie *cookie,
                                   char *rname )
{
    /* Handle questions in cookie */
    struct pico_dns_question *qprevious = NULL;
    struct pico_dns_question *qiterator = NULL;
    
    /* Handle records in cookie */
    struct pico_mdns_res_record *rprevious = NULL;
    struct pico_mdns_res_record *riterator = NULL;
    struct pico_mdns_res_record *found_my_record = NULL;
    
    /* New records */
    pico_mdns_res_record_list *new_records = NULL;
    char *new_name = NULL;
    char *new_url = NULL;
    uint8_t claim_id = 0;
    
    /* Check params */
    if (!cookie || !rname) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    if (cookie->flags != PICO_MDNS_COOKIE_TYPE_PROBE) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    mdns_dbg("CONFLICT for probe query with name '%s' occured!\n", rname);
    
    /* Prerequisite step: delete all conflicting records from my records */
    if (pico_mdns_res_record_list_delete_name(rname, &MyRecords) < 0) {
        mdns_dbg("Could not delete my conflicting records!\n");
    }
    
    /* Step 1: Remove question with that name from cookie */
    qiterator = cookie->contents->questions;
    while (qiterator) {
        if (strcmp(qiterator->qname, rname) == 0) {
            if (qprevious) {
                /* Don't allow a gap to arise when deleting */
                qprevious->next = qiterator->next;
            } else {
                /* If question is in beginning update contents of cookie */
                cookie->contents->questions = qiterator->next;
            }
            if (pico_dns_question_delete(&qiterator) < 0) {
                mdns_dbg("Could not delete question from probe cookie!\n");
                return -1;
            }
            break;
        } else {
            qprevious = qiterator;
            qiterator = qiterator->next;
        }
    }
    
    /* Step 1b: Stop timer events if cookie contains no other questions */
    if (cookie->contents->questions == NULL) {
        pico_timer_cancel(cookie->timer);
        cookie->timer = NULL;
        mdns_dbg("Stopped timer events for conflicting cookie.\n");
    }
    
    /* Step 2: Create a new name depending on current name */
    new_name = pico_mdns_resolve_name_conflict(rname);
    if (!new_name) {
        mdns_dbg("Resolving name conflict returned NULL!\n");
        return -1;
    }
    new_url = pico_dns_qname_to_url(new_name);
    PICO_FREE(new_name);

    /* Step 3: Create records with new name for the records with that name */
    riterator = cookie->contents->records;
    while (riterator) {
        if (strcmp(riterator->record->rname, rname) == 0) {
            /* Set the temporary claim ID */
            if (!claim_id)
                claim_id = riterator->claim_id;
            
            /* Create the same record with a new name */
            if (pico_mdns_res_record_list_append_create(new_url,
                                        riterator->record->rdata,
                                short_be(riterator->record->rsuffix->rtype),
                                long_be(riterator->record->rsuffix->rttl),
                                        riterator->flags,
                                        &new_records) < 0) {
                mdns_dbg("Could not create new non-conflicting record.\n");
            }
            mdns_dbg("Created new record with name '%s' and type '%d'\n",
                     new_url, short_be(riterator->record->rsuffix->rtype));
            
            if (rprevious) {
                /* Don't allow a gap to arise when deleting */
                rprevious->next = riterator->next;
            } else {
                /* If record is in beginning update contents-ptr of cookie */
                cookie->contents->records = riterator->next;
                rprevious = cookie->contents->records;
            }
            
            /* Step 4: Remove all records in cookie with that name */
            if (pico_mdns_res_record_delete(&riterator) < 0) {
                mdns_dbg("Could not delete record from probe cookie!\n");
                return -1;
            }
            
            riterator = rprevious;
            if (riterator == cookie->contents->records) rprevious = NULL;
            continue;
        }
        
        /* Move to next record but remember the previous */
        rprevious = riterator;
        riterator = riterator->next;
    }
    
    /* We don't need this anymore .. */
    PICO_FREE(new_url);
    
    /* Set the claim ID to the one of the conflicting records */
    riterator = new_records;
    while (riterator) {
        riterator->claim_id = claim_id;
        riterator = riterator->next;
    }
    
    /* Step 5: Try to reclaim the newly created records */
    if (pico_mdns_claim(new_records, 1, cookie->callback, cookie->arg) < 0) {
        mdns_dbg("Could not claim new records!\n");
        return -1;
    }
    
    /* Step 6: Check if cookie is not empty now */
    if (cookie->contents->questions == NULL &&
        cookie->contents->records == NULL) {
        mdns_dbg("Deleting empty cookie...");
        
        if (pico_mdns_cookie_list_delete_cookie(cookie, &PacketCookies) < 0)
            mdns_dbg("could not delete empty cookie!\n");
        else
            mdns_dbg("done\n");
    } else {
        /* There are still questions && records in the cookie for which no 
           conflict occured. So don't delete the cookie, let it finish it's
           initialisation for leftover records. */
        mdns_dbg("For now, this shouldn't happen..\n");
    }
    
    return 0;
}

static struct pico_mdns_cookie *
pico_mdns_cookie_list_find_query_cookie( char *name,
                                         pico_mdns_cookie_list **cookies )
{
    struct pico_mdns_cookie *iterator = NULL; // To iterate over cookies
    struct pico_dns_question *found = NULL;
    
    /* Check params */
    if (!cookies || !(*cookies)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    iterator = *cookies;
    while (iterator) {
        found = pico_dns_question_list_find(name,
                                            iterator->contents->questions);
        if (found) {
            /* Found a cookie which contains searched name */
            return iterator;
        }
        
        iterator = iterator->next;
    }
    
    return NULL;
}

/* ****************************************************************************
 *  Add an mDNS cookie to a mDNS cookie list (e.g. my cookies)
 * ****************************************************************************/
static int
pico_mdns_cookie_list_append( struct pico_mdns_cookie *cookie,
                              pico_mdns_cookie_list **cookies )
{
    struct pico_mdns_cookie **iterator = NULL; // To iterate over global cookies
    
    /* Check params */
    if (!cookie || !cookies) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Initialise iterators */
    iterator = cookies;
    
    /* Iterate until the end of the packet cookie list */
    while (*iterator) {
        iterator = &((*iterator)->next);
    }
    
    /* Append the cookie */
    *iterator = cookie;
    
    return 0;
}

static int
pico_mdns_cookie_list_delete_cookie( struct pico_mdns_cookie *cookie,
                                     pico_mdns_cookie_list **cookies )
{
    struct pico_mdns_cookie **iterator = NULL;
    struct pico_mdns_cookie **previous = NULL;
    struct pico_mdns_cookie *temp = NULL;
    
    iterator = cookies;
    while (*iterator) {
        if (*iterator == cookie) {
            if (previous) {
                (*previous)->next = (*iterator)->next;
                
                if (pico_mdns_cookie_delete(iterator) < 0) {
                    mdns_dbg("Could not delete cookie from list!\n");
                    return -1;
                }
            } else {
                temp = (*cookies)->next;
                
                if (pico_mdns_cookie_delete(iterator) < 0) {
                    mdns_dbg("Could not delete cookie from list!\n");
                    return -1;
                }
                
                *cookies = temp;
            }
            break;
        }
        
        previous = iterator;
        iterator = &((*iterator)->next);
    }
}

/* ****************************************************************************
 *  Deletes a mDNS packet cookie and free's memory. Doesn't take linked lists
 *  into account, so if you use this on a cookie which is in a list, most likely
 *  gaps will arise.
 * ****************************************************************************/
static int
pico_mdns_cookie_delete( struct pico_mdns_cookie **cookie )
{
    /* Check params */
    if (!cookie || !(*cookie)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Delete contents contained in cookie */
    if ((*cookie)->contents)
        pico_mdns_cookie_contents_delete(&((*cookie)->contents));
    
    /* Cancel and delete timer */
    if ((*cookie)->timer) {
        pico_timer_cancel((*cookie)->timer);
        (*cookie)->timer = NULL;
    }
    
    /* Delete the cookie itself */
    PICO_FREE(*cookie);
    *cookie = NULL;
    cookie = NULL;
    
    return 0;
}

/* ****************************************************************************
 *  Create a mDNS packet cookie with certain contents
 * ****************************************************************************/
static struct pico_mdns_cookie *
pico_mdns_cookie_create( struct pico_mdns_cookie_contents *contents,
                         uint8_t count,
                         uint8_t flags,
                         void (*cb_callback)(char *str, void *arg),
                         void *arg )
{
    struct pico_mdns_cookie *packet_cookie = NULL; // Packet cookie to send
    
    /* Check params */
    if (!contents || !cb_callback) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Provide space for the mDNS packet cookie */
    packet_cookie = PICO_ZALLOC(sizeof(struct pico_mdns_cookie));
    if (!packet_cookie) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Fill in the fields */
    packet_cookie->contents = contents;
    packet_cookie->count = count;
    packet_cookie->flags = flags;
    packet_cookie->timer = NULL;
    packet_cookie->callback = cb_callback;
    packet_cookie->arg = arg;
    packet_cookie->next = NULL;
    
    return packet_cookie;
}

/* ****************************************************************************
 *  Create the generic contents of an mDNS cookie
 * ****************************************************************************/
static struct pico_mdns_cookie_contents *
pico_mdns_cookie_contents_create( pico_dns_question_list *questions,
                                  pico_mdns_res_record_list *records )
{
    struct pico_mdns_cookie_contents *contents = NULL; // Contents to return
    
    /* Provide space for the content */
    contents = PICO_ZALLOC(sizeof(struct pico_mdns_cookie_contents));
    if (!contents) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    contents->questions = questions;
    contents->records = records;
    
    return contents;
}

static int
pico_mdns_cookie_contents_delete( struct pico_mdns_cookie_contents **contents )
{
    int ret = 0;
    
    /* Check params */
    if (!contents || !(*contents)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Delete questions if there are any */
    if ((*contents)->questions)
        ret = pico_dns_question_list_delete(&((*contents)->questions));

    /* Delete records if there are any */
    if ((*contents)->records)
         ret = pico_mdns_res_record_list_delete(&((*contents)->records));
    
    PICO_FREE(*contents);
    *contents = NULL;
    contents = NULL;
    
    return 0;
}

/* ****************************************************************************
 *  Create the probe contents of an mDNS cookie
 * ****************************************************************************/
static struct pico_mdns_cookie_contents *
pico_mdns_probe_content_create( pico_dns_question_list *questions,
                                pico_mdns_res_record_list *records )
{
    return pico_mdns_cookie_contents_create(questions, records);
}

/* ****************************************************************************
 *  Create the query contents of an mDNS cookie
 * ****************************************************************************/
static struct pico_mdns_cookie_contents *
pico_mdns_query_content_create( pico_dns_question_list *questions )
{
    return pico_mdns_cookie_contents_create(questions, NULL);
}

/* ****************************************************************************
 *  Create the answer contents of an mDNS cookie
 * ****************************************************************************/
static struct pico_mdns_cookie_contents *
pico_mdns_answer_content_create( pico_mdns_res_record_list *records )
{
    return pico_mdns_cookie_contents_create(NULL, records);
}

// MARK: QUESTION UTILITIES

static struct pico_dns_question *
pico_mdns_question_create( const char *url,
                           uint16_t *len,
                           uint8_t proto,
                           uint16_t qtype,
                           uint8_t flags )
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
    return pico_dns_question_create(url, len, proto, _qtype, qclass);
}

// MARK: MDNS QUERY UTILITIES

/* ****************************************************************************
 *  Creates a DNS packet meant for querying. Resource records can be added
 *  to query to allow:
 *      - Answer Section: To implement Known-Answer Suppression
 *      - Authority Section: To implement probe queries and tiebreaking
 * ****************************************************************************/
static pico_dns_packet *
pico_mdns_query_create( struct pico_dns_question *question_list,
                        struct pico_dns_res_record *answer_list,
                        struct pico_dns_res_record *authority_list,
                        struct pico_dns_res_record *additional_list,
                        uint16_t *len )
{
    pico_dns_packet *packet = NULL;
    
    /* Create an answer as you would with plain DNS */
    packet = pico_dns_query_create(question_list, answer_list, authority_list, additional_list, len);
    if (!packet) {
        mdns_dbg("Could not create DNS query!\n");
        return NULL;
    }
    
    /* Set the id of the DNS packet to 0 */
    packet->id = 0;
    
    return packet;
}

// MARK: RRECORD UTILITIES

/* ****************************************************************************
 *  Just copies an mDNS resource record
 * ****************************************************************************/
struct pico_mdns_res_record *
pico_mdns_res_record_copy( struct pico_mdns_res_record *record )
{
    struct pico_mdns_res_record *copy = NULL;
    char *url = NULL;
    
    /* Check params */
    if (!record) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Convert rname to url */
    url = pico_dns_qname_to_url(record->record->rname);
    if (!url) {
        mdns_dbg("Could not convert rname to url!\n");
        return NULL;
    }
    
    /* Create the copy */
    copy = pico_mdns_res_record_create(url,
                                       record->record->rdata,
                                       short_be(record->record->rsuffix->rtype),
                                       long_be(record->record->rsuffix->rttl),
                                       record->flags);
    
    /* Copy the claim ID too */
    copy->claim_id = record->claim_id;
    
    /* Free memory */
    PICO_FREE(url);
    
    return copy;
}

/* ****************************************************************************
 *  Deletes & free's the memory for all the records contained in an mDNS record-
 *  list.
 * ****************************************************************************/
int
pico_mdns_res_record_list_delete ( pico_mdns_res_record_list **records )
{
    struct pico_mdns_res_record **iterator = NULL;
    struct pico_mdns_res_record **previous = NULL;
    
    /* Check params */
    if (!records || !(*records)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Iterate over list */
    iterator = records;
    while (*iterator) {
        /* Move to next record but keep previous */
        previous = iterator;
        iterator = &((*iterator)->next);
        
        /* Delete previous record */
        pico_mdns_res_record_delete(previous);
    }
    
    /* Make NULL-pointers */
    *records = NULL;
    records = NULL;
    
    return 0;
}

/* ****************************************************************************
 *  Deletes & free's the memory for all the record with a certain name contained 
 *  in an mDNS record-list.
 * ****************************************************************************/
int
pico_mdns_res_record_list_delete_name( char *rname,
                                       pico_mdns_res_record_list **records)
{
    pico_mdns_res_record_list_delete_record(rname,
                                            PICO_DNS_TYPE_A,
                                            records);
    pico_mdns_res_record_list_delete_record(rname,
                                            PICO_DNS_TYPE_AAAA,
                                            records);
    pico_mdns_res_record_list_delete_record(rname,
                                            PICO_DNS_TYPE_PTR,
                                            records);
    
    return 0;
}

/* ****************************************************************************
 *  Deletes & free's the memory for a specific record contained in an mDNS 
 *  record-list.
 * ****************************************************************************/
int
pico_mdns_res_record_list_delete_record( char *rname,
                                         uint16_t rtype,
                                         pico_mdns_res_record_list **records )
{
    struct pico_mdns_res_record **iterator = NULL;
    struct pico_mdns_res_record **previous = NULL;
    struct pico_mdns_res_record *temp = NULL;
    
    /* Check params */
    if (!rname || !records || !(*records)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Iterate over list */
    iterator = records;
    
    while (*iterator) {
        if (short_be((*iterator)->record->rsuffix->rtype) == rtype) {
            if (strcmp(rname, (*iterator)->record->rname) == 0) {
                if (previous) {
                    /* Don't allow a gap to arise if record is in middle */
                    (*previous)->next = (*iterator)->next;
                    
                    /* Delete current record */
                    if (pico_mdns_res_record_delete(iterator) < 0) {
                        mdns_dbg("Could not delete mDNS record form list!\n");
                        return -1;
                    }
                } else {
                    /* Keep the next pointer */
                    temp = (*records)->next;
                    
                    /* Delete current record */
                    if (pico_mdns_res_record_delete(iterator) < 0) {
                        mdns_dbg("Could not delete mDNS record form list!\n");
                        return -1;
                    }
                    
                    /* Update records list if record is in front */
                    *records = temp;
                }
                break;
            }
        }
        
        /* Move to next record but keep previous */
        previous = iterator;
        iterator = &((*iterator)->next);
    }
    
    return 0;
}

/* ****************************************************************************
 *  Just appends an mDNS resource record to the end of a list
 * ****************************************************************************/
int
pico_mdns_res_record_list_append( struct pico_mdns_res_record *record,
                                  pico_mdns_res_record_list **records )
{
    struct pico_mdns_res_record **iterator = NULL; // Iterator for the list
    
    /* Check params */
    if (!records) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Initialise iterator */
    iterator = records;
    
    /* Move to end of list */
    while (*iterator) {
        iterator = &((*iterator)->next);
    }
    
    /* Append */
    *iterator = record;
    
    return 0;
}

/* ****************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority from an already existing mDNS resource record, and adds it to
 *  the end of the [records] list. If a NULL- pointer is provided a new list
 *  will be created.
 * ****************************************************************************/
int
pico_mdns_res_record_list_append_copy( struct pico_mdns_res_record *record,
                                       pico_mdns_res_record_list **records )
{
    return pico_mdns_res_record_list_append(pico_mdns_res_record_copy(record),
                                            records);
}

/* ****************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority and adds it to the end of a records list
 * ****************************************************************************/
int
pico_mdns_res_record_list_append_create( const char *url,
                                         void *_rdata,
                                         uint16_t rtype,
                                         uint32_t rttl,
                                         uint8_t flags,
                                         pico_mdns_res_record_list **records )
{
    struct pico_mdns_res_record *record = NULL; // New to create record
    
    /* Create the new record */
    record = pico_mdns_res_record_create(url,
                                         _rdata,
                                         rtype,
                                         rttl,
                                         flags);
    if (!record) {
        DEBUG("Could not create new mDNS resource record!\n");
        return 0;
    }
    
    return pico_mdns_res_record_list_append(record, records);
}

/* ****************************************************************************
 *  Finds a certain mDNS resource record in mDNS resource record list.
 * ****************************************************************************/
static struct pico_mdns_res_record *
pico_mdns_res_record_list_find( struct pico_mdns_res_record *record,
                                pico_mdns_res_record_list *records )
{
    struct pico_mdns_res_record *iterator = NULL; // To iterate over my records
    uint8_t eq_rtype = 0, eq_rname = 0;           // Store equality
    uint32_t ha = 0, hb = 0;                      // Hashes
    
    /* Check params */
    if (!record || !records) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Initialise the iterator */
    iterator = records;
    
    while (iterator) {
        /* Compare record with iterator */
        if (iterator->record->rsuffix->rtype == record->record->rsuffix->rtype)
            eq_rtype = 1;
        else
            eq_rtype = 0;
        
        /* Hash strings to compare */
        ha = pico_hash(iterator->record->rname,
                       (uint32_t)strlen(iterator->record->rname));
        hb = pico_hash(record->record->rname,
                       (uint32_t)strlen(record->record->rname));
        
        if (ha == hb)
            eq_rname = 1;
        else
            eq_rname = 0;
        
        if (eq_rname && eq_rtype)
            return iterator;
        else
            iterator = iterator->next;
    }
    
    mdns_dbg("Res_record_list_find succeeded\n");
    
    return NULL;
}

/* ****************************************************************************
 *  Finds a certain mDNS resource record in mDNS resource record list with
 *  given rname and rtype and returns only already claimed records
 * ****************************************************************************/
static struct pico_mdns_res_record *
pico_mdns_res_record_list_find_name_type( char *rname,
                                          uint16_t rtype,
                                          pico_mdns_res_record_list *records )
{
    struct pico_mdns_res_record test_record;
    struct pico_mdns_res_record *found;
    
    /* Provide space for the DNS record in the mDNS res record */
    test_record.record = (struct pico_dns_res_record *)
                         PICO_ZALLOC(sizeof(struct pico_dns_res_record));
    if (!(test_record.record)) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }
    
    /* Fill in the fields */
    test_record.record->rname = rname;
    test_record.record->rsuffix->rclass = short_be(PICO_DNS_CLASS_IN);
    test_record.record->rsuffix->rtype = short_be(rtype);
    
    /* Try to find the record in the record list */
    found = pico_mdns_res_record_list_find(&test_record, records);
    if (!found) {
        return NULL;
    } else {
        if (!IS_RES_RECORD_FLAG_PROBED_SET(found->flags))
            return NULL;
    }
    
    /* Free the DNS record in the mDNS res record */
    PICO_FREE(test_record.record);
    
    mdns_dbg("Res_record_list_find_name_type succeeded\n");
    
    return found;
}

/* ****************************************************************************
 *  Finds all the records in a mDNS record list for a given name, and generates
 *  a list of copies of those records.
 * ****************************************************************************/
static pico_mdns_res_record_list *
pico_mdns_res_record_list_find_copy_name( const char *rname,
                                          pico_mdns_res_record_list *records )
{
    pico_mdns_res_record_list *found_records = NULL; // records to return
    struct pico_mdns_res_record *iterator = NULL;    // To iterate over records
    uint32_t ha = 0, hb = 0;                         // Hashes
    
    /* Check params */
    if (!rname) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Iterate */
    iterator = records;
    while (iterator) {
        /* Hash strings to compare */
        ha = pico_hash(iterator->record->rname,
                       (uint32_t)strlen(iterator->record->rname));
        hb = pico_hash(rname, (uint32_t)strlen(rname));
        
        /* If names are the same append copy of record */
        if (ha == hb && IS_RES_RECORD_FLAG_PROBED_SET(iterator->flags)) {
            mdns_dbg("Found a claimed record '%s'\n", iterator->record->rname);
            pico_mdns_res_record_list_append_copy(iterator, &found_records);
        }
        
        iterator = iterator->next;
    }
    
    return found_records;
}

static void
pico_mdns_res_record_list_print( pico_mdns_res_record_list *records )
{
    struct pico_mdns_res_record *iterator = NULL;
    char *url = NULL;
    
    
    /* Check params */
    if (!records) {
        pico_err = PICO_ERR_EINVAL;
        return;
    }
    
mdns_dbg(
"                                                    C P ? U A ? ? T   ID \n");
mdns_dbg(
"+--------------------------------------------------+-+-+-+-+-+-+-+-+----+\n");
    
    iterator = records;
    while (iterator) {
        url = pico_dns_qname_to_url(iterator->record->rname);
mdns_dbg("|%-50s|%c|%c|%c|%c|%c|%c|%c|%c|%4d|\n",
         url,
         (((iterator->flags >> 7) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 6) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 5) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 4) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 3) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 2) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 1) & 0x01) ? 'V' : 'X'),
         (((iterator->flags >> 0) & 0x01) ? 'S' : 'U'),
         iterator->claim_id
        );
mdns_dbg(
"+--------------------------------------------------+-+-+-+-+-+-+-+-+----+\n");
        iterator = iterator->next;
    }
    
    mdns_dbg("\n");
}

static int
pico_mdns_res_record_am_i_lexi_later( struct pico_mdns_res_record *my_record,
                                      struct pico_mdns_res_record *peer_record)
{
    /* Hashes */
    uint16_t i = 0;
    uint16_t longest_rdlength = 0;
    
    /* Check params */
    if (!my_record || !peer_record) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* First, check class */
    if (short_be(my_record->record->rsuffix->rclass) >
        short_be(peer_record->record->rsuffix->rclass))
        return 1;
    
    /* Then, check type */
    if (short_be(my_record->record->rsuffix->rtype) >
        short_be(peer_record->record->rsuffix->rtype))
        return 1;
    
    if (short_be(my_record->record->rsuffix->rdlength) >=
        short_be(peer_record->record->rsuffix->rdlength))
        longest_rdlength = my_record->record->rsuffix->rdlength;
    else
        longest_rdlength = peer_record->record->rsuffix->rdlength;
    
    for (i = 0; i < longest_rdlength; i++) {
        if (i < my_record->record->rsuffix->rdlength &&
            i < peer_record->record->rsuffix->rdlength) {
            if ((uint8_t)my_record->record->rdata[i] >
                (uint8_t)peer_record->record->rdata[i]) {
                return 1;
            } else if ((uint8_t)my_record->record->rdata[i] <
                       (uint8_t)peer_record->record->rdata[i])
                return 0;
        } else {
            if (my_record->record->rsuffix->rdlength ==
                peer_record->record->rsuffix->rdlength)
                return -1;
            else if (my_record->record->rsuffix->rdlength == longest_rdlength)
                return 1;
            else
                return 0;
        }
    }
    
    return 0;
}

/* ****************************************************************************
 *  Create a resource record for the mDNS resource record format, that is
 *  with the MSB of the rclass field being set accordingly.
 * ****************************************************************************/
static struct pico_dns_res_record *
pico_mdns_dns_res_record_create( const char *url,
                                 void *_rdata,
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
    return pico_dns_rr_create(url, _rdata, len, rtype, rclass, rttl);
}


/* ****************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority, and adds it to the end of the [records] list. If a NULL-
 *  pointer is provided a new list will be created. Fills up len with the
 *  size of the DNS record
 * ****************************************************************************/
struct pico_mdns_res_record *
pico_mdns_res_record_create( const char *url,
                             void *_rdata,
                             uint16_t rtype,
                             uint32_t rttl,
                             uint8_t flags )
{
    struct pico_mdns_res_record *record = NULL;  // Address to set afterwards
    uint16_t len = 0;
    
    /* Check params */
    if (!url || !_rdata) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    /* Provide space for the new mDNS resource record */
    record = PICO_ZALLOC(sizeof(struct pico_mdns_res_record));
    if (!record) {
        mdns_dbg("Could not provide space for the mDNS resource record");
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Create a new record at the end of the list */
    record->record = pico_mdns_dns_res_record_create(url, _rdata, &len, rtype, rttl, flags);
    if (!((record)->record)) {
        mdns_dbg("Creating mDNS resource record failed!\n");
        return NULL;
    }
    
    /* Initialise fields */
    record->timer = NULL;
    record->next = NULL;
    record->flags = flags;
    record->claim_id = 0;
    
    return record;
}


/* ****************************************************************************
 *  Deletes a mDNS resource records. Does not take linked lists into account,
 *  So a gap will most likely arise, if you use this function for a res
 *  record which is in the middle of a list.
 * ****************************************************************************/
int
pico_mdns_res_record_delete( struct pico_mdns_res_record **record )
{
    /* Check params */
    if (!record || !(*record)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Delete DNS record contained */
    if ((*record)->record)
        pico_dns_rr_delete(&((*record)->record));
    
    /* Cancel and delete timer */
    if ((*record)->timer) {
        pico_timer_cancel((*record)->timer);
        PICO_FREE((*record)->timer);
        (*record)->timer = NULL;
    }
    
    /* Delet the record itself */
    PICO_FREE(*record);
    *record = NULL;
    record = NULL;
    
    return 0;
}

// MARK: ANSWER UTILITIES

/* ****************************************************************************
 *  Create a resource record for the mDNS answer message format, that is
 *  with the identifier of the DNS packet being 0.
 * ****************************************************************************/
static pico_dns_packet *
pico_mdns_answer_create( pico_dns_res_record_list *answer_list,
                         pico_dns_res_record_list *authority_list,
                         pico_dns_res_record_list *additional_list,
                         uint16_t *len )
{
    pico_dns_packet *packet = NULL;
    
    /* Create an answer as you would with plain DNS */
    packet = pico_dns_answer_create(answer_list,
                                    authority_list,
                                    additional_list,
                                    len);
    if (!packet) {
        mdns_dbg("Could not create DNS answer!\n");
        return NULL;
    }
    
    /* Set the id of the DNS packet to 0 */
    packet->id = 0;
    
    return packet;
}

// MARK: MY RECORDS UTILS

/* ****************************************************************************
 *  Generates a list of all my records for which the probe flag already has
 *  been set and for which the claimed flag hasn't been set yet. Copies the
 *  records from my records, so you have to manually delete them.
 * ****************************************************************************/
static pico_mdns_res_record_list *
pico_mdns_my_records_find_probed( void )
{
    pico_mdns_res_record_list *announcement_list = NULL; // To announce records
    struct pico_mdns_res_record *iterator = NULL;
    
    /* Initialise iterator to iterate over my resource records */
    iterator = MyRecords;
    
    /* Iterate over all my resource records */
    while (iterator) {
        /* Check if probed flag is set of a record */
        if (IS_RES_RECORD_FLAG_PROBED_SET(iterator->flags) &&
            !IS_RES_RECORD_FLAG_CLAIMED_SET(iterator->flags)) {
            if (pico_mdns_res_record_list_append_copy(iterator,
                                                      &announcement_list) < 0)
            {
                DEBUG("Could not append a copy of mDNS resource record\n");
                return NULL;
            }
        }
        /* Move to next record */
        iterator = iterator->next;
    }
    
    /* Return the beginning of the list */
    return announcement_list;
}

/* ****************************************************************************
 *  Generates a list of all my records for which the probe flag and the
 *  the claimed flag has not yet been set. Copies the records from my records, 
 *  so you have to manually delete them.
 * ****************************************************************************/
static pico_mdns_res_record_list *
pico_mdns_my_records_find_to_probe( void )
{
    pico_mdns_res_record_list *probe_list = NULL; // Resource records to probe
    struct pico_mdns_res_record *iterator = NULL; // To iterate over my records
    
    /* Initialise iterator to iterate over my resource records */
    iterator = MyRecords;
    
    /* Iterate over all my resource records */
    while (iterator) {
        /* Check if probed flag is not set of a record */
        if (!IS_RES_RECORD_FLAG_PROBED_SET(iterator->flags) &&
            !IS_RES_RECORD_FLAG_CLAIMED_SET(iterator->flags) &&
            IS_RES_RECORD_FLAG_CLAIM_UNIQUE_SET(iterator->flags)) {
            if (pico_mdns_res_record_list_append_copy(iterator,
                                                      &probe_list) < 0)
            {
                DEBUG("Could not append a copy of mDNS resource record\n");
                return NULL;
            }
        }
        /* Move to next record */
        iterator = iterator->next;
    }
    
    /* Return the beginning of the list */
    return probe_list;
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
pico_mdns_my_records_claimed( pico_mdns_res_record_list *records,
                              void (*cb_claimed)(char *str, void *arg),
                              void *arg )
{
    struct pico_mdns_res_record *iterator = NULL; // To iterate over my records
    struct pico_mdns_res_record *found = NULL;    // To store found my records
    char msg[1024] = { 0 };                       // String to pass to callback
    uint16_t msg_i = 0;                           // MSG index
    uint8_t all_claimed = 1;                      // Status of claim ID
    uint8_t claim_id = 0;                         // To store the claim ID
    
    /* Initialise the iterator */
    iterator = records;
    
    /* Get the claim ID of the first claimed record */
    if (iterator) {
        claim_id = iterator->claim_id;
    } else {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Iterate over records and set the CLAIMED flag */
    while (iterator) {
        /* Find the corresponding record in my records */
        found = pico_mdns_res_record_list_find(iterator, MyRecords);
        if (found) {
            PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RES_RECORD_CLAIMED);
            PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RES_RECORD_PROBED);
        }
        iterator = iterator->next;
    }
    
    /* Initialise the iterator for iterating over my records */
    iterator = MyRecords;
    while (iterator) {
        if (iterator->claim_id == claim_id) {
            /* Check if records are claimed for a certain claim ID */
            if (!IS_RES_RECORD_FLAG_CLAIMED_SET(iterator->flags)) {
                mdns_dbg("Claim flag of record '%s' has not yet been set!\n",
                         iterator->record->rname);
                all_claimed = 0;
                /* No need to look further */
                return 0;
            } else {
                strcpy(msg + msg_i, iterator->record->rname);
                msg_i += (uint16_t)strlen(iterator->record->rname);
                strcpy(msg + msg_i, ",");
                msg_i++;
            }
        }
        iterator = iterator->next;
    }
    
    /* If all_claimed is still true */
    if (all_claimed) {
        mdns_dbg("All records with claim ID '%d' are claimed!\n", claim_id);
        cb_claimed(msg, arg);
    }
    
    /* Debugging purposes */
//    mdns_dbg("\nMY RECORDS:\n");
//    pico_mdns_res_record_list_print(MyRecords);
    
    return 0;
}

// MARK: CACHE UTILITIES

static int pico_mdns_cache_del_rr(char *url, uint16_t qtype, char *rdata)
{
    IGNORE_PARAMETER(url);
    IGNORE_PARAMETER(qtype);
    IGNORE_PARAMETER(rdata);
    
//     struct pico_mdns_cache_rr test, *found = NULL;
//    
//    test.suf = PICO_ZALLOC(sizeof(struct pico_dns_res_record_suffix));
//    if(!test.suf)
//        return -1;
//    
//    test.url = url;
//    test.suf->rclass = PICO_DNS_CLASS_IN; /* We only support IN */
//    test.suf->rtype = qtype;
//    test.rdata = rdata;
//    
//    found = pico_tree_findKey(&CacheTable, &test);
//    PICO_FREE(test.suf);
//    
//    if(!found) {
//        mdns_dbg("Couldn't find cache RR to delete\n");
//        return -1;
//    }
//    
//    mdns_dbg("Removing RR: qtype '%d' url '%s'\n", qtype, url);
//    
//    pico_tree_delete(&CacheTable, found);
//    PICO_FREE(found->url);
//    PICO_FREE(found->suf);
//    PICO_FREE(found->rdata);
//    PICO_FREE(found);
    return 0;
}

static void pico_mdns_cache_tick(pico_time now, void *_arg)
{
    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(_arg);
//    struct pico_mdns_cache_rr *rr = (struct pico_mdns_cache_rr *)_arg;
//    IGNORE_PARAMETER(now);
//    
//    rr->suf->rttl--;
//    mdns_dbg("TTL UPDATE: '%s' - qtype: %d - TTL: %d\n", rr->url, rr->suf->rtype, rr->suf->rttl);
//    if(rr->suf->rttl < 1)
//        pico_mdns_cache_del_rr(rr->url, rr->suf->rtype, rr->rdata);
//    else
//        rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);
    
    /* TODO: continuous querying: cache refresh at 80 or 85/90/95/100 % of TTL + 2% rnd */
}

/* Look for a RR in cache matching hostname and qtype */
static struct pico_mdns_cache_rr *pico_mdns_cache_find_rr(const char *url, uint16_t rtype)
{
    IGNORE_PARAMETER(url);
    IGNORE_PARAMETER(rtype);
    struct pico_mdns_cache_rr test;                 /* Create a test-rr for the tree_findKey-function */
    struct pico_mdns_cache_rr *found = NULL;        /* Resource Record pointer to return */
//    struct pico_dns_res_record_suffix *suf = NULL;  /* Create a test rsuffix for the test-rr */
//    
//    /* Provide space for the test-suffix */
//    suf = PICO_ZALLOC(sizeof(struct pico_dns_res_record_suffix));
//    if(!suf)
//        return NULL;
//    
//    /* Set the rsuffix pointer of the test-rr */
//    test.suf = suf;
//    
//    /* Set the rtype of the rsuffix */
//    test.suf->rtype = rtype;
//    
//    /* Set the url of the test-rr in DNS name format */
//    test.url = pico_dns_url_to_qname(url);
//    
//    /* Find the Resource Record in the tree */
//    found = pico_tree_findKey(&CacheTable, &test);
//    
//    /* Free allocated space */
//    PICO_FREE(test.url);
//    PICO_FREE(suf);
    
    return found;
}

static int pico_mdns_cache_add_rr(char *url, struct pico_dns_res_record_suffix *suf, char *rdata)
{
    IGNORE_PARAMETER(url);
    IGNORE_PARAMETER(suf);
    IGNORE_PARAMETER(rdata);
//    struct pico_mdns_cache_rr *rr = NULL;
//    struct pico_mdns_cache_rr *found = NULL;
//    struct pico_dns_res_record_suffix *rr_suf = NULL;
//    char *rr_url = NULL;
//    char *rr_rdata = NULL;
//    
//    if(!url || !suf || !rdata)
//        return -1;
//    
//    /* Don't cache PTR answers */
//    if(short_be(suf->rtype) == PICO_DNS_TYPE_PTR ) {
//        mdns_dbg("Not caching PTR answer\n");
//        return 0;
//    }
//    
//    /* Provide space for the cache RR */
//    rr = PICO_ZALLOC(sizeof(struct pico_mdns_cache_rr));
//    rr_suf = PICO_ZALLOC(sizeof(struct pico_dns_res_record_suffix));
//    rr_url = pico_dns_url_to_qname(url);
//    rr_rdata = PICO_ZALLOC(short_be(suf->rdlength));
//    if(!rr || !rr_suf || !rr_url || !rr_rdata) {
//        PICO_FREE(rr);
//        PICO_FREE(rr_suf);
//        PICO_FREE(rr_url);
//        PICO_FREE(rr_rdata);
//        pico_err = PICO_ERR_ENOMEM;
//        return -1;
//    }
//    
//    /* Set the rname of the cache rr */
//    rr->url = rr_url;
//    
//    memcpy(rr_suf, suf, sizeof(struct pico_dns_res_record_suffix));
//    rr->suf = rr_suf;
//    rr->suf->rtype = short_be(rr->suf->rtype);
//    rr->suf->rclass = short_be(rr->suf->rclass);
//    rr->suf->rttl = long_be(suf->rttl);
//    rr->suf->rdlength = short_be(suf->rdlength);
//    memcpy(rr_rdata, rdata, rr->suf->rdlength);
//    rr->rdata = rr_rdata;
//    
//    found = pico_mdns_cache_find_rr(url, rr->suf->rtype);
//    if(found) {
//        if(rr->suf->rttl > 0) {
//            mdns_dbg("RR already in cache, updating TTL (was %ds now %ds)\n", found->suf->rttl, rr->suf->rttl);
//            found->suf->rttl = rr->suf->rttl;
//        }
//        else {
//            mdns_dbg("RR scheduled for deletion\n");
//            found->suf->rttl = 1;  /* TTL 0 means delete from cache but we need to wait one second */
//        }
//    }
//    else {
//        if(rr->suf->rttl > 0) {
//            pico_tree_insert(&CacheTable, rr);
//            mdns_dbg("RR cached. Starting TTL counter, TICK TACK TICK TACK..\n");
//            rr->timer = pico_timer_add(PICO_MDNS_RR_TTL_TICK, pico_mdns_cache_tick, rr);
//            return 0;
//        }
//        else {
//            mdns_dbg("RR not in cache but TTL = 0\n");
//        }
//    }
//    PICO_FREE(rr->suf);
//    PICO_FREE(rr->url);
//    PICO_FREE(rr->rdata);
//    PICO_FREE(rr);
    return 0;
}

/* Callback for the timeout timer of a query cookie */
static void pico_mdns_timeout(pico_time now, void *_arg)
{
    struct pico_mdns_cookie_old *ck = NULL;
    
    IGNORE_PARAMETER(now);
    
    /* Cast the _arg pointer to a cookie */
    ck = (struct pico_mdns_cookie_old *)_arg;

    /* Call the callback */
    if(ck->callback)
        ck->callback(NULL, ck->arg);
    
    /* Delete the cookie */
    //pico_mdns_del_cookie(ck->qname, ck->qtype);
    
    /* TODO: If the request was for a reconfirmation of a record, flush the corresponding record after the timeout */
}

// MARK: ASYNCHRONOUS MDNS RECEPTION

/* handle a single incoming answer */
static int pico_mdns_handle_answer(char *url, struct pico_dns_res_record_suffix *suf, char *data)
{
    struct pico_mdns_cookie_old *ck = NULL;     // Temporary storage of query cookie
    
    /* Remove cache flush bit if set MARK: But why? */
    suf->rclass &= short_be((uint16_t) ~0x8000);
    
    /* Print some context */
    mdns_dbg("Answer for record %s was received:\n", url);
    mdns_dbg("rrtype: %u, rrclass: %u, ttl: %lu, rdlen: %u\n", short_be(suf->rtype), short_be(suf->rclass), (unsigned long)long_be(suf->rttl), short_be(suf->rdlength));
    
    /* Add a resource record to cache */
    pico_mdns_cache_add_rr(url, suf, data);
    
    mdns_dbg("Searching for a corresponding query cookie for url: %s and qtype: %d...\n", url, short_be(suf->rtype));
    
    /* Check in the query tree whether a request was sent to elicit this answer */
    //ck = pico_mdns_find_cookie(url, short_be(suf->rtype));
    if(!ck) {
        /* MARK: Of course no cookie will be found if the responder doesn't sent the same qtype with probes*/
        mdns_dbg("Found NO corresponding cookie!\n");
        return 0;
    }
    
    mdns_dbg("Found a corresponding cookie!\n");
    
    /* if we are probing, set probe to zero so the probe timer stops the next time it goes off */
    if (IS_QUESTION_PROBE_FLAG_SET(ck->flags)) {
        mdns_dbg("Probe set to zero\n");
        ck->flags &= PICO_MDNS_QUESTION_FLAG_NO_PROBE;
        return 0;
    }
    
    /* If this was aan API request return answer passed in callback */
    if(short_be(suf->rtype) == PICO_DNS_TYPE_A) {
        uint32_t rdata = long_from(data);
        char peer_addr[46];
        pico_ipv4_to_string(peer_addr, long_from(&rdata));
        ck->callback(peer_addr, ck->arg);
    }
    
#ifdef PICO_SUPPORT_IPV6
    else if(short_be(suf->rtype) == PICO_DNS_TYPE_AAAA) {
        uint8_t *rdata = (uint8_t *) data;
        char peer_addr[46];
        pico_ipv6_to_string(peer_addr, rdata);
        ck->callback(peer_addr, ck->arg);
    }
#endif
    else if(short_be(suf->rtype) == PICO_DNS_TYPE_PTR) {
        pico_dns_notation_to_name(data);
        ck->callback(data + 1, ck->arg);    /* +1 to discard the beginning dot */
    } else {
        mdns_dbg("Unrecognised record type\n");
        ck->callback(NULL, ck->arg);
    }
    
    /* Remove the timer from the cookie and delete it */
    pico_timer_cancel(ck->timer);
    //pico_mdns_del_cookie(url, ck->qtype);
    
    return 0;
}

/* Create a query answer according to the qtype (ANY, A, AAAA or PTR) of a certain IP address */
//static struct pico_dns_header *pico_mdns_query_create_answer(union pico_address *local_addr, uint16_t qtype, uint16_t *len, char *name)
//{
//    // TODO: If type is ANY include all records corresponding to the name
//    // TODO: Include negative responses for records this hosts knows they don't exist
//
//    IGNORE_PARAMETER(local_addr);
//    IGNORE_PARAMETER(qtype);
//    IGNORE_PARAMETER(len);
//    IGNORE_PARAMETER(name);
//    
//    if(qtype == PICO_DNS_TYPE_A || qtype == PICO_DNS_TYPE_ANY) {
//        return pico_mdns_answer_create(mdns_global_host, len, PICO_DNS_TYPE_A, local_addr);
//    }
//#ifdef PICO_SUPPORT_IPV6
//    if(qtype == PICO_DNS_TYPE_AAAA || qtype == PICO_DNS_TYPE_ANY) {
//        struct pico_ip6 *ip6 = pico_get_ip6_from_ip4(&local_addr->ip4);
//        return pico_mdns_answer_create(mdns_global_host, len, PICO_DNS_TYPE_AAAA, ip6);
//    }
//#endif
//    /* reply to PTR records */
//    if(qtype == PICO_DNS_TYPE_PTR) {
//        char host_conv[255] = { 0 };
//        mdns_dbg("Replying on PTR query...\n");
//        strcpy(host_conv + 1, mdns_global_host);
//        pico_dns_name_to_dns_notation(host_conv);
//        return pico_mdns_answer_create(name, len, qtype, host_conv);
//    }
//    
//    mdns_dbg("Unknown qtype!\n");
//
//    return NULL;
//}

/* Reply on a single query */
static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer, char *name)
{
    IGNORE_PARAMETER(qtype);
    IGNORE_PARAMETER(peer);
    IGNORE_PARAMETER(name);
    
//    /* Pointer to DNS packet */
//    struct pico_dns_header *header = NULL;
//    
//    /* To store either an IPv4 or an IPv6 */
//    union pico_address *local_addr = NULL;
//    
//    uint16_t len; // Temporary storage of the length of the reply
//    
//    /* RFC:
//     *  If a responder receives a query addressed to the mDNS IPv4 link-local multicast address,
//     *  from a source address not apparently on the same subnet as the
//     *  responder, then, even if the query indicates that a unicast
//     *  response is preferred, the responder SHOULD elect to respond by multicast
//     *  anyway, since it can reasonably predict that a unicast response with
//     *  an apparently non-local source address will probably be ignored.
//     */
//    local_addr = (union pico_address *) pico_ipv4_source_find(&peer);
//    if (!local_addr) {
//        // TODO: Forced Response via multicast
//        pico_err = PICO_ERR_EHOSTUNREACH;
//        mdns_dbg("Peer not on same subnet!\n");
//        return -1;
//    }
//
//    /* Creates an answer for the host's IP, depending on the qtype */
//    header = pico_mdns_query_create_answer(local_addr, qtype, &len, name);
//    if (!header) {
//        mdns_dbg("Error occured while creating an answer (pico_err:%d)!\n", pico_err);
//        return -1;
//    }
//    
//    /* Send a response on the wire */
//    if(pico_mdns_send_packet(header, len) != (int)len) {
//        mdns_dbg("Send error occurred!\n");
//        return -1;
//    }
    
    return 0;
}

/* Compare if the received query name is the same as the name currently assigned to this host */
static int pico_check_query_name(char *url)
{
    IGNORE_PARAMETER(url);
//    char addr[29] = { 0 };
    
//    /* Check if query is a normal query for this hostname*/
//    if(strcmp(url, mdns_global_host) == 0)
//        return 1;
//    
//    /* Convert 192.168.1.1 decimal to '192.168.1.1'-string */
//    pico_ipv4_to_string(addr, mdns_sock_ipv4->local_addr.ip4.addr);
//    
//    /* Mirror 192.168.1.1 to 1.1.168.192 */
//    pico_dns_mirror_addr(addr);
//    
//    /* Add a arpa-suffix */
//    memcpy(addr + strlen(addr), ".in-addr.arpa", 13);
//    
//    /* Check if request name is reverse query for this hostname */
//    if(strcmp(url, addr) == 0)
//        return 1;
    
    return 0;
}

static struct pico_mdns_res_record *
pico_mdns_handle_single_question( struct pico_dns_question *question )
{
    struct pico_mdns_res_record *iterator = NULL;
    struct pico_mdns_res_record *found = NULL;
    
    if (!question) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    mdns_dbg("Question RCVD for '%s'\n", question->qname);
    
    switch (short_be(question->qsuffix->qtype)) {
        case PICO_DNS_TYPE_ANY:
            found = pico_mdns_res_record_list_find_copy_name(question->qname,
                                                             MyRecords);
            break;
        default:
            found = pico_mdns_res_record_copy(
                    pico_mdns_res_record_list_find_name_type(question->qname,
                                                    question->qsuffix->qtype,
                                                    MyRecords));
            
            
            if (!IS_RES_RECORD_FLAG_CLAIMED_SET(found->flags))
                pico_mdns_res_record_delete(&found);
            
            break;
    }
    
    if (PICO_MDNS_IS_MSB_SET(short_be(question->qsuffix->qclass))) {
        mdns_dbg("Question requests for Unicast response...\n");
        iterator = found;
        
        while (iterator) {
            PICO_MDNS_SET_FLAG(iterator->flags,
                               PICO_MDNS_RES_RECORD_SEND_UNICAST);
            iterator = iterator->next;
        }
    }
    
    return found;
}

int
pico_mdns_handle_single_answer( struct pico_dns_res_record *answer )
{
    struct pico_mdns_cookie *found = NULL;
    
    /* Find currently active query cookie */
    mdns_dbg("Finding query cookie for record...");
    found = pico_mdns_cookie_list_find_query_cookie(answer->rname,
                                                    &PacketCookies);
    mdns_dbg("done\n");
    
    if (found) {
        if (found->flags == PICO_MDNS_COOKIE_TYPE_PROBE &&
            found->status == PICO_MDNS_COOKIE_ACTIVE) {
            /* Found cookie is a probe cookie, apply conflict resolution */
            if (pico_mdns_cookie_resolve_conflict(found, answer->rname) < 0) {
                mdns_dbg("Could not resolve conflict correctly, maybe conflict \
                         is resolved already...\n");
            }
        } else if (found->flags == PICO_MDNS_COOKIE_TYPE_QUERY) {
            /* TODO: Found cookie is a plain cookie,
                     update cache and call callback */
            mdns_dbg("RCVD a response record on a plain query!\n");
        } else {
            mdns_dbg("Found a cookie which is probably not active...\n");
        }
    } else {
        /* Received unsollicited answer, update cache */
        mdns_dbg("RCVD an unsollicited record!\n");
    }
    
    return 0;
}

int
pico_mdns_handle_single_authority( struct pico_dns_res_record *answer )
{
    struct pico_mdns_cookie *found = NULL;
    
    /* Find currently active probe cookie */
    found = pico_mdns_cookie_list_find_query_cookie(answer->rname,
                                                    &PacketCookies);
    if (found) {
        if (found->flags == PICO_MDNS_COOKIE_TYPE_PROBE &&
            found->status == PICO_MDNS_COOKIE_ACTIVE) {
            /* Apply Simultaneous Probe Tiebreaking to cookie */
            mdns_dbg("Simultaneous Probing occured, went tiebreaking...\n");
            if (pico_mdns_cookie_apply_spt(found, answer) < 0) {
                mdns_dbg("Could not apply S.P.T. to cookie!\n");
                return -1;
            }
        } else {
            return -1;
        }
    } else {
        mdns_dbg("No query cookie found with name '%s'\n", answer->rname);
        return -1;
    }
    
    return 0;
}

int
pico_mdns_handle_single_additional( struct pico_dns_res_record *answer )
{
    /* Don't need this for now ... */
}

/* ****************************************************************************
 *  Handles a flat chunk of memory as if it were all questions in it.
 *  Generates res_record_list with responses if there are any questions for 
 *  records for which this module has the authority to answer.
 * ****************************************************************************/
static pico_mdns_res_record_list *
pico_mdns_handle_data_as_questions ( uint8_t **ptr,
                                     uint16_t qdcount )
{
    pico_mdns_res_record_list *answers = NULL; // Answer list to return
    struct pico_dns_question question;         // Temporary store question
    uint16_t i = 0;
    
    /* Check params */
    if (!ptr && !(*ptr)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    for (i = 0; i < qdcount; i++) {
        /* Set qname of the question to the correct location */
        question.qname = (char *)(*ptr);
        
        /* Set qsuffix of the question to the correct location */
        question.qsuffix = (struct pico_dns_question_suffix *)
                            ((*ptr) +
                             pico_dns_namelen_comp((char *)(*ptr)) +
                             1);
        
        /* Handle a single question and append an answer to the list
         * if there is one. */
        pico_mdns_res_record_list_append(
                            pico_mdns_handle_single_question(&question),
                            &answers);
        
        /* Move to next question */
        *ptr = (uint8_t *)question.qsuffix +
               sizeof(struct pico_dns_question_suffix);
    }
    
    return answers;
}

int
pico_mdns_handle_data_as_answers_generic( uint8_t **ptr,
                                          uint16_t count,
                                          uint8_t type )
{
    struct pico_dns_res_record answer;  // Temporary store record
    uint16_t i = 0;
    
    /* Check params */
    if (!ptr && !(*ptr)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    
    for (i = 0; i < count; i++) {
        /* Set rname of the record to the correct location */
        answer.rname = (char *)(*ptr);
        
        /* Set rsuffix of the record to the correct location */
        answer.rsuffix = (struct pico_dns_res_record_suffix *)
        ((*ptr) + pico_dns_namelen_comp((char *)(*ptr)) + 1u);
        
        /* Set rdata of the record to the correct location */
        answer.rdata = (uint8_t *) answer.rsuffix +
                       sizeof(struct pico_dns_res_record_suffix);
        
        /* Handle a single aswer */
        switch (type) {
            case 1:
                pico_mdns_handle_single_authority(&answer);
                break;
            case 2:
                pico_mdns_handle_single_additional(&answer);
                break;
            default:
                pico_mdns_handle_single_answer(&answer);
                break;
        }
        
        /* Move to next record */
        *ptr = (uint8_t *) answer.rdata + answer.rsuffix->rdlength + 1u;
    }

    return 0;
}

int
pico_mdns_handle_data_as_answers( uint8_t **ptr, uint16_t count )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, 0);
}

int
pico_mdns_handle_data_as_authorities( uint8_t **ptr, uint16_t count )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, 1);
}

int
pico_mdns_handle_data_as_additionals( uint8_t **ptr, uint16_t count )
{
    return pico_mdns_handle_data_as_answers_generic(ptr, count, 2);
}

/* ****************************************************************************
 *  Handle a single incoming query packet without Known Answer Suppression
 * ****************************************************************************/
static int
pico_mdns_handle_query_packet( pico_dns_packet *packet, struct pico_ip4 peer )
{
    /* DNS record lists to send either unicast or multicast */
    pico_mdns_res_record_list *answers = NULL; // Answer records
    pico_dns_res_record_list *dns_answers_m = NULL;
    pico_dns_res_record_list *dns_answers_u = NULL;
    
    struct pico_dns_res_record *known_answer = NULL;
    
    /* To iterate over the answer records */
    struct pico_mdns_res_record *iterator = NULL;
    
    /* Answer packets to send either unicast or multicast */
    pico_dns_packet *unicast_response = NULL;
    pico_dns_packet *multicast_response = NULL;
    
    uint8_t *data = NULL;
    uint16_t len = 0;
    uint8_t i = 0;
    
    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);
    
    /* Generate a list of answers */
    answers = pico_mdns_handle_data_as_questions(&data,
                                                 short_be(packet->qdcount));
    if (!answers) {
        mdns_dbg("No records found that correspond with this query!\n");
        return 0;
    }

    /* K.A.S.: Remove answers given in question Answer section already */
    for (i = 0; i < short_be(packet->ancount); i++) {
        known_answer = data;
        /* Delete known answer */
        if (pico_mdns_res_record_list_delete_record(known_answer->rname,
                                                known_answer->rsuffix->rtype,
                                                answers) < 0) {
            mdns_dbg("Could not delete known answer from answer list.\n");
            return -1;
        }
        
        /* Move to next known answer */
        data += (uint16_t) strlen(known_answer->rname) + 1u +
                (uint16_t) sizeof(struct pico_dns_res_record_suffix) +
                known_answer->rsuffix->rdlength;
    }
    
    iterator = answers;
    while (iterator) {
        /* Add the record either to the multicast or unicast list */
        if (IS_RES_RECORD_FLAG_SEND_UNICAST_SET(iterator->flags)) {
            pico_dns_rr_list_append(iterator->record, &dns_answers_u);
        } else {
            pico_dns_rr_list_append(iterator->record, &dns_answers_m);
        }
        
        iterator = iterator->next;
    }
    
    /* If there are any unicast records */
    if (dns_answers_u) {
        /* Create response DNS packet */
        unicast_response = pico_mdns_answer_create(dns_answers_u,
                                                   NULL,
                                                   NULL,
                                                   &len);
        if (!unicast_response || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        
        /* Send the packet via unicast */
        if (pico_mdns_send_packet_unicast(unicast_response, len, peer) < 0) {
            mdns_dbg("Could not send unicast response!\n");
            return -1;
        }
        
        mdns_dbg("Unicast response sent succesfully!\n");
    }
    
    /* If there are any unicast records */
    if (dns_answers_m) {
        /* Create response DNS packet */
        multicast_response = pico_mdns_answer_create(dns_answers_m,
                                                     NULL,
                                                     NULL,
                                                     &len);
        if (!multicast_response || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        
        /* Send the packet via unicast */
        if (pico_mdns_send_packet(multicast_response, len) < 0) {
            mdns_dbg("Could not send multicast response!\n");
            return -1;
        }
        
        mdns_dbg("Multicast response sent succesfully!\n");
    }
    
    return 0;
}

/* ****************************************************************************
 *  Handle a probe packet
 * ****************************************************************************/
static int
pico_mdns_handle_probe_packet( pico_dns_packet *packet, struct pico_ip4 peer )
{
    /* DNS record lists to send either unicast or multicast */
    pico_mdns_res_record_list *answers = NULL; // Answer records
    pico_dns_res_record_list *dns_answers_m = NULL;
    pico_dns_res_record_list *dns_answers_u = NULL;
    
    /* To iterate over the answer records */
    struct pico_mdns_res_record *iterator = NULL;
    
    /* Answer packets to send either unicast or multicast */
    pico_dns_packet *unicast_response = NULL;
    pico_dns_packet *multicast_response = NULL;
    
    char host[30];
    uint8_t *data = NULL;
    uint16_t len = 0;
    uint16_t i = 0;
    
    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);
    
    /* Generate a list of answers */
    answers = pico_mdns_handle_data_as_questions(&data,
                                                 short_be(packet->qdcount));
    if (!answers) {
        mdns_dbg("No records found that correspond with this query!\n");
        
//        mdns_dbg("\nRNAME: ");
//        for (i = 0; i < strlen((char *)data) + 1; i++) {
//            mdns_dbg("%X ", data[i]);
//        }
//        mdns_dbg("\n");
        
        /* Check if we need to tiebreak simultaneous probing */
        if (pico_mdns_handle_data_as_authorities(&data,
                                                 short_be(packet->nscount)) < 0)
            mdns_dbg("No Simultaneous Probe Tiebreaking needed!\n");
    }
    
    iterator = answers;
    while (iterator) {
        /* Add the record either to the multicast or unicast list */
        if (IS_RES_RECORD_FLAG_SEND_UNICAST_SET(iterator->flags)) {
            pico_dns_rr_list_append(iterator->record, &dns_answers_u);
        } else {
            pico_dns_rr_list_append(iterator->record, &dns_answers_m);
        }
        
        iterator = iterator->next;
    }
    
    /* If there are any unicast records */
    if (dns_answers_u) {
        /* Create response DNS packet */
        unicast_response = pico_mdns_answer_create(dns_answers_u,
                                                   NULL,
                                                   NULL,
                                                   &len);
        if (!unicast_response || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        
        /* Send the packet via unicast */
        if (pico_mdns_send_packet_unicast(unicast_response, len, peer) < 0) {
            mdns_dbg("Could not send unicast response!\n");
            return -1;
        }
        
        mdns_dbg("Defense sent succesfully via unicast!\n");
    }
    
    /* If there are any unicast records */
    if (dns_answers_m) {
        /* Create response DNS packet */
        multicast_response = pico_mdns_answer_create(dns_answers_m,
                                                     NULL,
                                                     NULL,
                                                     &len);
        if (!multicast_response || len == 0) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }
        
        /* Send the packet via unicast */
        if (pico_mdns_send_packet(multicast_response, len) < 0) {
            mdns_dbg("Could not send multicast response!\n");
            return -1;
        }
        
        mdns_dbg("Defense sent successfully via multicast!\n");
    }
    
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
    uint16_t len = 0;
    
    /* Move to the data section of the packet */
    data = (uint8_t *)packet + sizeof(struct pico_dns_header);
    
    /* Generate a list of answers */
    if (pico_mdns_handle_data_as_answers(&data,
                                         short_be(packet->ancount)) < 0)
    {
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
             qdcount,
             ancount,
             authcount,
             addcount);

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
    char recvbuf[PICO_MDNS_MTU] = { 0 }; // MTU of 1400
    struct pico_ip4 peer = { 0 };        // Peer who sent the data
    int pico_read = 0;                   // Count of readed bytes
    uint16_t port = 0;                   // Source port
    char host[30];                       // IP-address string
    
    /* process read event, data available */
    if (ev == PICO_SOCK_EV_RD) {
        mdns_dbg("___________________________________________________________\n\
READ EVENT!\n");
        /* Receive while data is available in socket buffer */
        while((pico_read = pico_socket_recvfrom(s,
                                                recvbuf,
                                                PICO_MDNS_MTU,
                                                &peer,
                                                &port)) > 0) {
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

// MARK: CACHE FUNCTIONS

int pico_mdns_flush_cache(void)
{
    
    return 0;
}

// MARK: ADDRESS RESOLUTION

static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto)
{
    struct pico_dns_header *header = NULL;
    uint16_t len = 0;
    
    IGNORE_PARAMETER(callback);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(proto);
    
    if (!url) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    if(!mdns_sock_ipv4) {
        mdns_dbg("mDNS socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }
    
    //header = pico_mdns_create_query(url, &len, proto, PICO_DNS_TYPE_PTR, PICO_MDNS_QUESTION_FLAG_NO_PROBE);
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
    
    IGNORE_PARAMETER(callback);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(proto);
    
    if (!ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    if(!mdns_sock_ipv4) {
        mdns_dbg("Mdns socket not yet populated. Did you call pico_mdns_init()?\n");
        return -1;
    }
    
    //header = pico_mdns_create_query(ip, &len, proto, PICO_DNS_TYPE_PTR, PICO_MDNS_QUESTION_FLAG_NO_PROBE);
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

int
pico_mdns_getname6(const char *ip,
                   void (*callback)(char *url, void *arg),
                   void *arg)
{
    return pico_mdns_getname_generic(ip, callback, arg, PICO_PROTO_IPV6);
}
#endif

// MARK: PROBING & ANNOUNCING

/* ****************************************************************************
 *  Utility function to create an announcement packet from an mDNS packet
 *  cookie passed in [arg] and send it on the wire.
 * ****************************************************************************/
static void
pico_mdns_send_announcement_packet( pico_time now, void *arg )
{
    pico_dns_packet *packet = NULL;                // DNS packet to create
    struct pico_mdns_cookie *packet_cookie = NULL; // To parse arg to
    struct pico_mdns_res_record *iterator = NULL;  // To iterate
    
    /* List of DNS records to announce */
    struct pico_dns_res_record *announcement_records = NULL;
    uint16_t len = 0;
    
    IGNORE_PARAMETER(now);
    
    /* Parse argument */
    packet_cookie = (struct pico_mdns_cookie *)arg;
    
    if (packet_cookie->count > 0) {
        /* Records are stored in contents of packet cookie */
        iterator = packet_cookie->contents->records;
        
        while (iterator) {
            /* Add DNS records to announcement records */
            if(pico_dns_rr_list_append(iterator->record, &announcement_records)
               < 0) {
                DEBUG("Could not append DNS resource record to list\n");
            }
            
            /* Move to next resource record in answer cookie */
            iterator = iterator->next;
        }
        
        /* Create an mDNS answer */
        packet = pico_mdns_answer_create(announcement_records,
                                         NULL,
                                         NULL,
                                         &len);
        if (!packet) {
            mdns_dbg("Could not create announcement packet!\n");
            return;
        }
        
        /* Reset all the next pointers of the DNS records */
        iterator = packet_cookie->contents->records;
        while (iterator) {
            iterator->record->next = NULL;
            /* Move to next resource record in answer cookie */
            iterator = iterator->next;
        }
        
        /* Send the mDNS answer unsollicited via multicast */
        if(pico_mdns_send_packet(packet, len) != (int)len) {
            mdns_dbg("Send error occured!\n");
            return;
        }
        
        /* Free memory */
        PICO_FREE(packet);
        packet = NULL;
        
        /* Decrement the count */
        packet_cookie->count--;
        
        mdns_dbg(" >>>> Announcement sent succesfully!\n");
        
        if (packet_cookie->count > 0) {
            /* Plan a next announcement */
            /* RFC:
             *  The Multicast DNS responder MUST send at least two unsolicited
             *  responses, one second apart.
             */
            packet_cookie->timer = pico_timer_add(1000,
                                        pico_mdns_send_announcement_packet,
                                        (void *)packet_cookie);
        } else {
            pico_mdns_send_announcement_packet(0, (void *)packet_cookie);
        }
    } else {
        mdns_dbg("DONE - Announcing.\n");
        
        packet_cookie->status = PICO_MDNS_COOKIE_INACTIVE;
        
        /* Update my records */
        pico_mdns_my_records_claimed(packet_cookie->contents->records,
                                     packet_cookie->callback,
                                     packet_cookie->arg);
        
        /* Delete records in cookie */
        if (pico_mdns_res_record_list_delete(
                                &(packet_cookie->contents->records)) < 0) {
            mdns_dbg("Could not delete records in cookie!\n");
            return;
        }
    }
}

/* ****************************************************************************
 *  Utility function to announce all 'my records' which passed the probed-
 *  state. When all the records are announced for a particular claim ID,
 *  the callback passed in this function will be called.
 * ****************************************************************************/
static int
pico_mdns_announce( void (*cb_claimed)(char *str, void *arg), void *arg )
{
    struct pico_mdns_cookie *announcement_packet = NULL; // Packet cookie
    struct pico_mdns_cookie_contents *announcement = NULL; // Answer content
    pico_mdns_res_record_list *announcement_list = NULL; // To announce rr's
    
    /* Check params */
    if (!cb_claimed) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    IGNORE_PARAMETER(arg);
    
    /* Find out which resource records can be announced */
    announcement_list = pico_mdns_my_records_find_probed();
    if (!announcement_list) {
        return -1;
    }
    
    /* Create an mDNS answer cookie with the to announce records */
    announcement = pico_mdns_answer_content_create(announcement_list);
    if (!announcement) {
        DEBUG("answer_content_create returned NULL!\n");
    }
    
    /* Create a mDNS packet cookie */
    announcement_packet = pico_mdns_cookie_create(
                                                  announcement,
                                                  2,
                                                  PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT,
                                                  cb_claimed,
                                                  arg);
    if (!announcement_packet) {
        DEBUG("packet_cookie_create returned NULL!\n");
        return -1;
    }
    
    /* Send a first unsollicited announcement */
    pico_mdns_send_announcement_packet(0, announcement_packet);
    
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
    struct pico_mdns_cookie *packet_cookie = NULL; // To parse argument in arg
    struct pico_mdns_res_record *record_iterator = NULL;
    struct pico_mdns_res_record *found = NULL;
    
    /* Questions & Authority records */
    struct pico_dns_res_record *authority_records = NULL; //
    uint16_t len = 0;
    
    /* Check params */
    if (!arg) {
        pico_err = PICO_ERR_EINVAL;
        return;
    }
    
    IGNORE_PARAMETER(now);
    
    /* Parse argument */
    packet_cookie = (struct pico_mdns_cookie *)arg;
    
    packet_cookie->status = PICO_MDNS_COOKIE_ACTIVE;
    
    if (packet_cookie->count > 0) {
        /* Initialise cookie iterator */
        if (!(packet_cookie->contents) ||
            !(packet_cookie->contents->records) ||
            !(packet_cookie->contents->questions)) {
            pico_err = PICO_ERR_EINVAL;
            return;
        }
        record_iterator = packet_cookie->contents->records;
        
        /* Iterate over cookies */
        while (record_iterator) {
            /* We don't want the cache flush bit set here */
            PICO_MDNS_CLR_MSB_BE(record_iterator->record->rsuffix->rclass);
            
            /* Append resource records contained mDNS record
             * to authority records */
            pico_dns_rr_list_append(record_iterator->record,
                                    &authority_records);
            
            /* Move to next cookie */
            record_iterator = record_iterator->next;
        }
        
        /* Create an mDNS answer */
        packet = pico_mdns_query_create(packet_cookie->contents->questions,
                                        NULL,
                                        authority_records,
                                        NULL,
                                        &len);
        if (!packet) {
            mdns_dbg("Could not create probe packet!\n");
        }
        
        /* Reset all the next pointers of the DNS records */
        record_iterator = packet_cookie->contents->records;
        while (record_iterator) {
            record_iterator->record->next = NULL;
            /* Move to next resource record in answer cookie */
            record_iterator = record_iterator->next;
        }
        
        /* Send the mDNS answer unsollicited via multicast */
        if(pico_mdns_send_packet(packet, len) != (int)len) {
            mdns_dbg("Send error occured!\n");
            return;
        }
        
        /* Decrement the count */
        packet_cookie->count--;
        
        mdns_dbg(" >>>> Probe sent succesfully!\n");
        
        /* RFC:
         *  250 ms after the first query, the host should send a second;
         *  then, 250 ms after that, a third.
         */
        packet_cookie->timer = pico_timer_add(250,
                                              pico_mdns_send_probe_packet,
                                              (void *)packet_cookie);
    } else {
        mdns_dbg("DONE - Probing.\n");
        
        /* Set all the cache flush bits */
        record_iterator = packet_cookie->contents->records;
        while (record_iterator) {
            /* We want the cache flush bit set here */
            PICO_MDNS_SET_MSB_BE(record_iterator->record->rsuffix->rclass);
            
            /* Set the probed flag of 'my records' */
            found = pico_mdns_res_record_list_find(record_iterator, MyRecords);
            if (found)
                PICO_MDNS_SET_FLAG(found->flags, PICO_MDNS_RES_RECORD_PROBED);
            
            /* Move to next resource record in answer cookie */
            record_iterator = record_iterator->next;
        }
        
        /* Delete all the question in the cookie */
        if (pico_dns_question_list_delete(
                                &(packet_cookie->contents->questions)) < 0) {
            DEBUG("Could not delete all probe questions!\n");
        }
        
        /* Start announcing the records */
        packet_cookie->count = 2;
        packet_cookie->flags = PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT;
        pico_mdns_send_announcement_packet(0, (void*) packet_cookie);
    }
    
    return;
}

/* ****************************************************************************
 *  Try to find any of my records that need to be probed, and probe them
 * ****************************************************************************/
static int pico_mdns_probe( void (*cb_claimed)(char *str, void *arg),
                            void *arg )
{
    struct pico_mdns_cookie *probe_packet = NULL;            // mDNS cookie
    struct pico_mdns_cookie_contents *probe_contents = NULL; // Cookie contents
    
    struct pico_mdns_res_record *probe_iterator = NULL; // To iterate mDNS rr's
    pico_mdns_res_record_list *probe_list = NULL;       // To probe mDNS rr's
    
    pico_dns_question_list *probe_questions = NULL;     // To send DNS questions
    struct pico_dns_question *new = NULL;               // New question
    struct pico_dns_question *found = NULL;             // Existing question
    char *url = NULL;
    uint16_t qlen = 0;
    
    /* Check params */
    if (!cb_claimed) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Find my records that need to pass the probing step first */
    probe_list = pico_mdns_my_records_find_to_probe();
    if (probe_list) {
        /* Initialise iterator */
        probe_iterator = probe_list;
        
        while (probe_iterator) {
            /* Find a corresponding probe question for that rname */
            found = pico_dns_question_list_find(probe_iterator->record->rname,
                                                probe_questions);
            
            /* If not found, create a new probe question for that name */
            if (!found) {
                url = pico_dns_qname_to_url(probe_iterator->record->rname);
                if (!url) {
                    mdns_dbg("Could not convert rname '%s' to url!\n",
                             probe_iterator->record->rname);
                    continue;
                }
                
                /* Create a new probe question */
                new = pico_mdns_question_create(
                                            url,
                                            &qlen,
                                            PICO_PROTO_IPV4,
                                            PICO_DNS_TYPE_ANY,
                                            (PICO_MDNS_QUESTION_FLAG_PROBE |
                                        PICO_MDNS_QUESTION_FLAG_UNICAST_RES));
                
                /* Free memory */
                PICO_FREE(url);
                url = NULL;
                
                /* Append probe question to question list */
                if (pico_dns_question_list_append(new, &probe_questions) < 0) {
                    DEBUG("Could not append question to probe questions!\n");
                    continue;
                }
            } else {
            }
            
            /* Move to next probe record */
            probe_iterator = probe_iterator->next;
        }
        
        /* Initialise probe cookie content */
        probe_contents = pico_mdns_probe_content_create(probe_questions,
                                                        probe_list);
        if (!probe_contents) {
            DEBUG("probe_content_create return NULL @ probe()!\n");
            return -1;
        }
        
        /* Create a mDNS packet to send */
        probe_packet = pico_mdns_cookie_create(probe_contents,
                                               3,
                                               PICO_MDNS_COOKIE_TYPE_PROBE,
                                               cb_claimed,
                                               arg);
        if (!probe_packet) {
            DEBUG("cookie_create returned NULL @ probe()!\n");
            return -1;
        }
        
        /* Add the Probe packet cookie to the end of PacketCookies
         to find it afterwards */
        if (pico_mdns_cookie_list_append(probe_packet, &PacketCookies) < 0) {
            DEBUG("Could not append cookie to PacketCookies!\n");
            return -1;
        }
        
        /* RFC:
         *  When the host is ready to send his probe query he SHOULD delay it's
         *  transmission with a randomly chosen time between 0 and 250 ms.
         */
        probe_packet->timer = pico_timer_add(pico_rand() % 250,
                              pico_mdns_send_probe_packet,
                              (void *)probe_packet);
        
        mdns_dbg("DONE - Started probing.\n");
    }
    
    return 0;
}

// MARK: API functions

/* ****************************************************************************
 *  Claim several mDNS resource records at once.
 * ****************************************************************************/
int
pico_mdns_claim( pico_mdns_res_record_list *records,
                 uint8_t reclaim,
                 void (*cb_claimed)(char *str, void *arg),
                 void *arg )
{
    struct pico_mdns_res_record *iterator = NULL;
    
    /* Initialise static claim ID number */
    static uint8_t claim_id_count = 0;
    
    /* Check if arguments are passed correctly */
    if (!records || !cb_claimed) {
        mdns_dbg("NULL pointers passed to 'pico_mdns_claim()'!\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* Check if module is initialised */
    if (!mdns_sock_ipv4) {
        mdns_dbg("mDNS socket not initialised, did you call 'pico_mdns_init()'?\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
    
    /* 1.) Appending records to 'my records' */
    
    /* Initialise iterator */
    iterator = MyRecords;
    
    /* Iterate to the end of my records */
    while (iterator) {
        iterator = iterator->next;
    }
    
    /* Append at the end */
    iterator = records;
    
    /* If MyRecords wasn't initialised yet, initialise it now */
    if (!MyRecords) {
        MyRecords = iterator;
    }
    
    /* Increment the claim_id */
    if (!reclaim)
        ++claim_id_count;
    
    while (iterator) {
        /* Set the probed flag of SHARED records */
        if (IS_RES_RECORD_FLAG_CLAIM_SHARED_SET(iterator->flags)) {
            PICO_MDNS_SET_FLAG(iterator->flags, PICO_MDNS_RES_RECORD_PROBED);
        }
        
        mdns_dbg("Adding record '%s' with flags: 0x%02X to my records...",
                 iterator->record->rname,
                 iterator->flags);
        if (!reclaim)
            iterator->claim_id = claim_id_count;
        iterator = iterator->next;
        mdns_dbg("done\n");
    }

    /* 2a.) Try to probe any records */
    pico_mdns_probe(cb_claimed, arg);
    
    /* 2b.) Try to announce any records */
    pico_mdns_announce(cb_claimed, arg);
    
    return 0;
}

/* ****************************************************************************
 *  Set the hostname for this machine. Claims it automatically as a unique
 *  A record for the local address of the bound socket.
 * ****************************************************************************/
int
pico_mdns_set_hostname( const char *url,
                        void (*cb_set)(char *str, void *arg),
                        void *arg )
{
    struct pico_mdns_res_record *record;
    
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
    
    hostname = PICO_ZALLOC(strlen(url) + 1);
    if (!hostname) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    strcpy(hostname, url);
    
    mdns_dbg("Hostname set to '%s'.\n", hostname);
    
    /* Create an A record for hostname */
    record = pico_mdns_res_record_create(hostname,
                            (void*)&(mdns_sock_ipv4->local_addr.ip4.addr),
                                         PICO_DNS_TYPE_A,
                                         120,
                                         PICO_MDNS_RES_RECORD_UNIQUE);
    
    /* TODO: Create a reverse resolution record */
    
    if (!record) {
        DEBUG("Could not create A record for hostname!\n");
        return -1;
    }
    
    /* Try to claim the record */
    if (pico_mdns_claim(record, 0, cb_set, arg) < 0) {
        mdns_dbg("Could not claim record for hostname %s!\n", url);
        return -1;
    }
    
    return 0;
}

/* ****************************************************************************
 *  Returns the hostname for this machine
 * ****************************************************************************/
inline const char *
pico_mdns_get_hostname( void )
{
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
                void (*cb_initialised)(char *str, void *arg),
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
    if(!cb_initialised || !_hostname) {
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
    
    /* Set the hostname for this machine */
    if (pico_mdns_set_hostname(_hostname, cb_initialised, arg) < 0) {
        DEBUG("Setting hostname returned error\n");
        return -1;
    }
    
    return 0;
}

#endif /* PICO_SUPPORT_MDNS */
