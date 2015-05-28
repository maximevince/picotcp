/* ****************************************************************************
 *  PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 *  See LICENSE and COPYING for usage.
 *  .
 *  Author: Toon Stegen, Jelle De Vleeschouwer
 * ****************************************************************************/
#ifndef INCLUDE_PICO_MDNS
#define INCLUDE_PICO_MDNS

#include "pico_dns_common.h"
#include "pico_ipv4.h"

/* ********************************* CONFIG ***********************************/
#define PICO_MDNS_PROBE_UNICAST 0		/* Probe queries as QU-questions      */
#define PICO_MDNS_DEFAULT_TTL 120		/* Default TTL of mDNS records        */
#define PICO_MDNS_SERVICE_TTL 4500		/* Default TTL of SRV/TXT/PTR/NSEC    */
#define PICO_MDNS_CONTINUOUS_REFRESH 0  /* Continuously update cache          */
#define PICO_MDNS_PROBE_COUNT 3			/* Amount of probes to send           */
#define PICO_MDNS_ANNOUNCEMENT_COUNT 2	/* Amount of announcements to send    */
/* ****************************************************************************/

#define PICO_MDNS_DEST_ADDR4 "224.0.0.251"

#define PICO_MDNS_RECORD_UNIQUE 0x00u
#define PICO_MDNS_RECORD_SHARED 0x01u

/* MDNS resource record */
struct pico_mdns_record
{
    struct pico_dns_record *record; // DNS Resource Record
    uint32_t current_ttl;           // Current TTL
    uint8_t flags;                  // Resource Record flags
    uint8_t claim_id;               // Claim ID number
};

/* MDNS resource record vector */
typedef struct
{
    struct pico_mdns_record **records;
    uint16_t count;
} pico_mdns_record_vector;

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
                         uint8_t flags );

/* ****************************************************************************
 *  Deletes a mDNS resource record.
 * ****************************************************************************/
int
pico_mdns_record_delete( struct pico_mdns_record **record );

/* ****************************************************************************
 *  Initialise an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_init( pico_mdns_record_vector *vector );

/* ****************************************************************************
 *  Returns the amount of records contained in an mDNS record vector
 * ****************************************************************************/
uint16_t
pico_mdns_record_vector_count( pico_mdns_record_vector *vector );

/* ****************************************************************************
 *  Adds an mDNS record to an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_add( pico_mdns_record_vector *vector,
                             struct pico_mdns_record *record );

/* ****************************************************************************
 *  Gets an mDNS record from an mDNS record vector at a certain index
 * ****************************************************************************/
struct pico_mdns_record *
pico_mdns_record_vector_get( pico_mdns_record_vector *vector,
                             uint16_t index );

/* ****************************************************************************
 *  Deletes every mDNS record from an mDNS record vector
 * ****************************************************************************/
int
pico_mdns_record_vector_destroy( pico_mdns_record_vector *vector );

/* ****************************************************************************
 *  API functions
 * ****************************************************************************/
int
pico_mdns_getrecord( const char *url, uint16_t type,
                     void (*callback)(pico_mdns_record_vector *,
                                      char *,
                                      void *),
                     void *arg );

/* ****************************************************************************
 *  Claim all the mDNS records contained in an mDNS record vector at once.
 * ****************************************************************************/
int
pico_mdns_claim( pico_mdns_record_vector record_vector,
                 void (*callback)(pico_mdns_record_vector *,
                                  char *,
                                  void *),
                 void *arg );

/* ****************************************************************************
 *  Set the hostname for this machine. Claims it automatically as a unique
 *  A record for the local address of the bound socket.
 * ****************************************************************************/
int
pico_mdns_set_hostname( const char *url, void *arg );

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
                struct pico_ip4 address,
                uint8_t flags,
                void (*callback)(pico_mdns_record_vector *,
                                 char *,
                                 void *),
                void *arg );

#endif /* _INCLUDE_PICO_MDNS */
