/* ****************************************************************************
 *  PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 *  See LICENSE and COPYING for usage.
 *  .
 *  Author: Toon Stegen
 * ****************************************************************************/
#ifndef INCLUDE_PICO_MDNS
#define INCLUDE_PICO_MDNS

#include "pico_dns_common.h"

#define PICO_MDNS_DEST_ADDR4 "224.0.0.251"

#define PICO_MDNS_RES_RECORD_UNIQUE 0x00u
#define PICO_MDNS_RES_RECORD_SHARED 0x01u

/* MDNS resource record */
struct pico_mdns_res_record
{
    struct pico_dns_res_record *record; // DNS Resource Record
    struct pico_timer *timer;           // Used For Timer events
    uint8_t flags;                      // Resource Record flags
    uint8_t claim_id;                   // Claim ID number
    struct pico_mdns_res_record *next;  // Possibility to create a list
};

/* A list of them is just the same */
typedef struct pico_mdns_res_record pico_mdns_res_record_list;

/* ****************************************************************************
 *  Deletes & free's the memory for all the records contained in an mDNS record-
 *  list.
 * ****************************************************************************/
int
pico_mdns_res_record_list_delete ( pico_mdns_res_record_list **records );

/* ****************************************************************************
 *  Deletes & free's the memory for a specific record contained in an mDNS
 *  record-list.
 * ****************************************************************************/
int
pico_mdns_res_record_list_delete_record( char *rname,
                                         uint16_t rtype,
                                         pico_mdns_res_record_list **records );

/* ****************************************************************************
 *  Adds a mDNS resource record to the end of the [records] list. If a NULL-
 *  pointer is provided a new list will be created.
 * ****************************************************************************/
int
pico_mdns_res_record_list_append( struct pico_mdns_res_record *record,
                                  pico_mdns_res_record_list **records );

/* ****************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority from an already existing mDNS resource record, and adds it to
 *  the end of the [records] list. If a NULL-pointer is provided a new list
 *  will be created.
 * ****************************************************************************/
int
pico_mdns_res_record_append_list_copy( struct pico_mdns_res_record *record,
                                       pico_mdns_res_record_list **records );

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
                                         pico_mdns_res_record_list **records );

/* ****************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority.
 * ****************************************************************************/
struct pico_mdns_res_record *
pico_mdns_res_record_create( const char *url,
                             void *_rdata,
                             uint16_t rtype,
                             uint32_t rttl,
                             uint8_t flags );

/* ****************************************************************************
 *  Deletes a mDNS resource records. Does not take linked lists into account,
 *  So a gap will most likely arise, if you use this function for a res
 *  record which is in the middle of a list.
 * ****************************************************************************/
int
pico_mdns_res_record_delete( struct pico_mdns_res_record **record );

/* ****************************************************************************
 *  Claim several mDNS resource records at once.
 * ****************************************************************************/
int
pico_mdns_claim( pico_mdns_res_record_list *records,
                 void (*cb_claimed)(char *str, void *arg),
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

/* ****************************************************************************
 *  API functions
 * ****************************************************************************/
int
pico_mdns_getaddr( const char *url,
                   void (*callback)(char *ip, void *arg),
                   void *arg );
int
pico_mdns_getname( const char *ip,
                   void (*callback)(char *url, void *arg),
                   void *arg );

int
pico_mdns_flush_cache(void);

#ifdef PICO_SUPPORT_IPV6
#define PICO_MDNS_DEST_ADDR6 "FF02::FB"
int
pico_mdns_getaddr6( const char *url,
                    void (*callback)(char *ip, void *arg),
                    void *arg );
int
pico_mdns_getname6( const char *ip,
                    void (*callback)(char *url, void *arg),
                    void *arg);
#endif

#endif /* _INCLUDE_PICO_MDNS */
