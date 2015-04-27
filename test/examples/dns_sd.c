#include "utils.h"
#include <pico_dns_sd.h>
#include <pico_ipv4.h>
#include <pico_addressing.h>

/*** START DNS_SD ***/
#ifdef PICO_SUPPORT_DNS_SD

void dns_sd_claimed_callback( pico_mdns_record_vector *vector,
                            char *str,
                            void *arg )
{
    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(vector);

    printf("Claimed CB called!\n");
}

void dns_sd_init_callback( pico_mdns_record_vector *vector,
                          char *str,
                          void *arg )
{
    kv_vector key_value_pair_vector = {0};

    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    IGNORE_PARAMETER(vector);

    pico_dns_sd_kv_vector_add(&key_value_pair_vector, "textvers", "1");

    if (pico_dns_sd_register_service("Hello World!",
                                     "_http._tcp", 80,
                                     key_value_pair_vector,
                                     120) < 0) {
        printf("Registering service failed!\n");
    }
}

void app_dns_sd(char *arg, struct pico_ipv4_link *link)
{
    char *hostname, *service_name, *service_type, *service_port;
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

    if (!link) {
        printf("Link not found!\n");
        exit(255);
    }

    printf("\nStarting DNS Service Discovery module...\n");
    if (pico_dns_sd_init(hostname, link, 0, &dns_sd_init_callback, NULL) != 0) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }
    printf("DONE - Initialising DNS Service Discovery module.\n");

    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}

#endif
/*** END DNS_SD ***/