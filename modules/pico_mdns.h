/* ****************************************************************************
 *  PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 *  See LICENSE and COPYING for usage.
 *  .
 *  Author: Toon Stegen
 * ****************************************************************************/
#ifndef INCLUDE_PICO_MDNS
#define INCLUDE_PICO_MDNS

#include "pico_dns_common.h"
#include "pico_ipv4.h"

/* ********************************* CONFIG ***********************************/
#define PICO_MDNS_PROBE_UNICAST 0            /* Probe queries as QU-questions */
#define PICO_MDNS_DEFAULT_TTL 30             /* Default TTL of mDNS records   */
/* ****************************************************************************/

#define PICO_MDNS_DEST_ADDR4 "224.0.0.251"

#define PICO_MDNS_RES_RECORD_UNIQUE 0x00u
#define PICO_MDNS_RES_RECORD_SHARED 0x01u

/* MDNS resource record */
typedef struct pico_mdns_res_record
{
    struct pico_dns_res_record *record; // DNS Resource Record
    struct pico_timer *timer;           // Used For Timer events
    uint32_t current_ttl;               // Current TTL
    uint8_t flags;                      // Resource Record flags
    uint8_t claim_id;                   // Claim ID number
    struct pico_mdns_res_record *next;  // Possibility to create a list
} pico_mdns_res_record_list;

/* ****************************************************************************
 *  Creates a new mDNS resource record. The address of a mDNS res record-struct
 *  needs to be given in record_out to return the created record in. If passed
 *  in record is an element of a list, the record will be appended to the end
 *  of the list. So you will have to iterate until the end of the list to
 *  access the newly created record.
 * ****************************************************************************/
int
pico_mdns_res_record_create( const char *url,
                             void *_rdata,
                             uint16_t rtype,
                             uint32_t rttl,
                             uint8_t flags,
                             struct pico_mdns_res_record **record_out );

/* ****************************************************************************
 *  Deletes a mDNS resource records. Does not take linked lists into account,
 *  So a gap will most likely arise, if you use this function for a res
 *  record which is in the middle of a list.
 * ****************************************************************************/
int
pico_mdns_res_record_delete( struct pico_mdns_res_record **record );

/* ****************************************************************************
 *  API functions
 * ****************************************************************************/
int
pico_mdns_getrecord( const char *url,
                    uint16_t type,
                    void (*callback)(pico_mdns_res_record_list *data,
                                     void *arg),
                    void *arg );

/* ****************************************************************************
 *  Claim several mDNS resource records at once.
 * ****************************************************************************/
int
pico_mdns_claim( pico_mdns_res_record_list *records,
                 uint8_t reclaim,
                 void (*cb_claimed)(void *data, void *arg),
                 void *arg );

/* ****************************************************************************
 *  Set the hostname for this machine. Claims it automatically as a unique
 *  A record for the local address of the bound socket.
 * ****************************************************************************/
int
pico_mdns_set_hostname( const char *url,
                        void (*cb_set)(char *str, void *arg),
                        void *arg );

/* ****************************************************************************
 *  Returns the hostname for this machine
 * ****************************************************************************/
const char *
pico_mdns_get_hostname( void );

/* ****************************************************************************
 *  Initialises the global mDNS socket. Calls cb_initialised when succeeded.
 *  [flags] is for future use. f.e. Opening a IPv4 multicast socket or an 
 *  IPv6 one or both.
 * ****************************************************************************/
int
pico_mdns_init( const char *_hostname,
                struct pico_ipv4_link *link,
                uint8_t flags,
                void (*cb_initialised)(char *str, void *arg),
                void *arg );

#endif /* _INCLUDE_PICO_MDNS */
