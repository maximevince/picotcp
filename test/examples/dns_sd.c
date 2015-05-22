#include "utils.h"
#include <pico_dns_sd.h>
#include <pico_ipv4.h>
#include <pico_addressing.h>

/*** START DNS_SD ***/
#ifdef PICO_SUPPORT_DNS_SD

#define TTL 30

static char *service_name = NULL;

void dns_sd_claimed_callback( pico_mdns_record_vector *vector,
                              char *str,
                              void *arg )
{
    struct pico_mdns_record *record = NULL;
    char *service_url = NULL;
    char *service_name = NULL;

    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);

    /* Get the registered service name from the first claimed record */
    record = pico_mdns_record_vector_get(vector, 0);
    service_name= (char*)(record->record->rdata);

    /* Provide some space for the service instance name */
    service_url = PICO_ZALLOC((size_t)(*service_name + 1));
    if (!service_url) {
        pico_err = PICO_ERR_ENOMEM;
        return;
    }

    /* Copy the service instance name */
    memcpy(service_url, service_name + 1, (size_t) *service_name);

    /* Append zero byte */
    service_url[(int)*service_name] = '\0';

    printf("Service registered: %s\n", service_url);
}

void dns_sd_init_callback( pico_mdns_record_vector *vector,
                           char *str,
                           void *arg )
{
    kv_vector key_value_pair_vector = {0};

    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(vector);

    printf("DONE - Initialising DNS Service Discovery module.\n");

    pico_dns_sd_kv_vector_add(&key_value_pair_vector, "textvers", "1");
    pico_dns_sd_kv_vector_add(&key_value_pair_vector, "auth", NULL);
    pico_dns_sd_kv_vector_add(&key_value_pair_vector, "pass", "");

    if (pico_dns_sd_register_service(service_name,
                                     "_http._tcp", 80,
                                     &key_value_pair_vector,
                                     TTL, dns_sd_claimed_callback, NULL) < 0) {
        printf("Registering service failed!\n");
    }
}

void app_dns_sd(char *arg, struct pico_ip4 address)
{
    char *hostname, *service_type, *service_port;
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

    nxt = cpy_arg(&service_name, nxt);
    if(!service_name) {
        exit(255);
    }

    printf("\nStarting DNS Service Discovery module...\n");
    if (pico_dns_sd_init(hostname, address, 0, &dns_sd_init_callback, NULL) != 0) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }

    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}

#endif
/*** END DNS_SD ***/