/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.
   .
   Author: Toon Stegen
 *********************************************************************/
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
    struct pico_mdns_res_record *next;  // Possibility to create a list
    uint8_t flags;                      // Resource Record flags
};

/* A list of them is just the same */
typedef struct pico_mdns_res_record pico_mdns_res_record_list;

/* **************************************************************************
 *  Creates a new mDNS resource record for which you want to have the
 *  authority, and adds it to the end of the [records] list. If a NULL-
 *  pointer is provided a new list will be created. Fills up len with the 
 *  size of the DNS record
 * **************************************************************************/
int pico_mdns_res_record_create( pico_mdns_res_record_list **records,
                                 const char *url,
                                 void *_rdata,
                                 uint16_t rtype,
                                 uint16_t rttl,
                                 uint8_t flags );

/* **************************************************************************
 *  Claim several mDNS resource records at once.
 * **************************************************************************/
int pico_mdns_claim( pico_mdns_res_record_list *records,
                     void (*cb_claimed)(char *str, void *arg),
                     void *arg );

/* **************************************************************************
 *  Initialises the global mDNS socket. Calls cb_initialised when succeeded.
 *  [flags] is for future use. f.e. Opening a IPv4 multicast socket or an 
 *  IPv6 one or both.
 * **************************************************************************/
int pico_mdns_init( uint8_t flags,
                    void (*cb_initialised)(char *str, void *arg),
                    void *arg );

/* **************************************************************************
 *  API functions
 * **************************************************************************/
int pico_mdns_getaddr(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname(const char *ip, void (*callback)(char *url, void *arg), void *arg);
int pico_mdns_flush_cache(void);

#ifdef PICO_SUPPORT_IPV6
#define PICO_MDNS_DEST_ADDR6 "FF02::FB"
int pico_mdns_getaddr6(const char *url, void (*callback)(char *ip, void *arg), void *arg);
int pico_mdns_getname6(const char *ip, void (*callback)(char *url, void *arg), void *arg);
#endif

#endif /* _INCLUDE_PICO_MDNS */
