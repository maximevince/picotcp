#include "utils.h"
#include <pico_dns_common.h>
#include <pico_mdns.h>
#include <pico_ipv4.h>
#include <pico_addressing.h>

/*** START MDNS ***/

#ifdef PICO_SUPPORT_MDNS

void mdns_getrecord_callback( pico_mdns_record_vector *vector,
                              char *str,
                              void *arg )
{
    if (!vector) {
        printf("Returned NULL-ptr!\n");
        return;
    }
    if (pico_mdns_record_vector_count(vector) > 0) {
        printf("Get record succeeded!\n");
    } else {
        printf("No records found!\n");
    }
}

void mdns_claimed_callback( pico_mdns_record_vector *vector,
                            char *str,
                            void *arg )
{
    printf("Claimed records\n");
}

void mdns_init_callback( pico_mdns_record_vector *vector,
                         char *str,
                         void *arg )
{
    struct pico_mdns_record *hostname_record = NULL;
    char *hostname = NULL;

    /* Get the first record in the vector */
    hostname_record = pico_mdns_record_vector_get(vector, 0);

    /* Convert the rname to an URL */
    hostname = pico_dns_qname_to_url(hostname_record->record->rname);
    printf("Initialised with hostname: %s\n", hostname);
    PICO_FREE(hostname);
}

void app_mdns(char *arg, struct pico_ip4 address)
{
    char *hostname, *peername;
    char *nxt = arg;
    struct pico_ip6 ipaddr6 = {{0}};
    
    if (!nxt)
        exit(255);

    nxt = cpy_arg(&hostname, nxt);
    if(!hostname) {
        exit(255);
    }

    if(!nxt) {
        printf("Not enough args supplied!\n");
        exit(255);
    }

    nxt = cpy_arg(&peername, nxt);
    if(!peername) {
        exit(255);
    }
    
    printf("\nStarting mDNS module...\n");
    if (pico_mdns_init(hostname, address, 0, &mdns_init_callback, peername) != 0) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }
    printf("DONE - Initialising mDNS module.\n");
    
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
#endif
/*** END MDNS ***/
