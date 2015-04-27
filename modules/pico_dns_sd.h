/* ****************************************************************************
 *  PicoTCP. Copyright (c) 2014 TASS Belgium NV. Some rights reserved.
 *  See LICENSE and COPYING for usage.
 *  .
 *  Author: Jelle De Vleeschouwer
 * ****************************************************************************/
#ifndef INCLUDE_PICO_DNS_SD
#define INCLUDE_PICO_DNS_SD

#include "pico_mdns.h"

typedef struct
{
    char *key;
    char *value;
} key_value_pair_t;

typedef struct
{
    key_value_pair_t **pairs;
    uint16_t count;
} kv_vector;

/* ****************************************************************************
 *  This function actually does exactly the same as pico_mdns_init();
 * ****************************************************************************/
int
pico_dns_sd_init( const char *_hostname,
                  struct pico_ipv4_link *link,
                  uint8_t flags,
                  void (*callback)(pico_mdns_record_vector *,
                                   char *,
                                   void *),
                  void *arg );

/* ****************************************************************************
 *  Register a service on in the '.local'-domain of a certain type. Port number
 *  Needs to be provided and can't be 0. The key-value pair vector should at
 *  at least contain 1 key-value pair with 'textvers'-key. Otherwise, the 
 *  service will not be registered.
 * ****************************************************************************/
int
pico_dns_sd_register_service( const char *name,
                              const char *type,
                              uint16_t port,
                              kv_vector txt_data,
                              uint16_t ttl );

/* ****************************************************************************
 *  Browse for a service of a certain type on the '.local' domain. Calls
 *  callback when any changes happen to found service, as in as they come and
 *  go.
 *
 *  MARK: Probably this function will be updated in the near future.
 * ****************************************************************************/
int
pico_dns_sd_browse_service( const char *type,
                            void (*callback)(pico_mdns_record_vector *,
                                             char *,
                                             void *),
                            void *arg );

/* ****************************************************************************
 *  Initialise a key-value pair vector
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_init( kv_vector *vector );

/* ****************************************************************************
 *  Get the count of key-value pairs contained in the vector
 * ****************************************************************************/
uint16_t
pico_dns_sd_kv_vector_count( kv_vector *vector );

/* ****************************************************************************
 *  Add a key-value pair to the key-value pair vector
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_add( kv_vector *vector, char *key, char *value );

/* ****************************************************************************
 *  Gets a key-value pair from the key-value pair vector
 * ****************************************************************************/
key_value_pair_t *
pico_dns_sd_kv_vector_get( kv_vector *vector, uint16_t index );

#endif /* _INCLUDE_PICO_DNS_SD */
