#include "utils.h"
#include <pico_mdns.h>
#include <pico_ipv4.h>
#include <pico_addressing.h>

/*** START MDNS ***/

#ifdef PICO_SUPPORT_MDNS

void mdns_getname6_callback(char *str, void *arg)
{
    (void) arg;
    if (!str)
        printf("Getname6: timeout occurred!\n");
    else
        printf("Getname6 callback called, str: %s\n", str);

    exit(0);
}

void mdns_getaddr6_callback(char *str, void *arg)
{
    (void) arg;
    if (!str)
        printf("Getaddr6: timeout occurred!\n");
    else
        printf("Getaddr6 callback called, str: %s\n", str);

    if(pico_mdns_getname6(str, &mdns_getname6_callback, NULL) != 0)
        printf("Getname6 returned with error!\n");
}

void mdns_getname_callback(char *str, void *arg)
{
    char *peername = (char *)arg;
    if(!peername) {
        printf("No system name supplied!\n");
        exit(-1);
    }

    if (!str)
        printf("Getname: timeout occurred!\n");
    else
        printf("Getname callback called, str: %s\n", str);

    if(pico_mdns_getaddr6(peername, &mdns_getaddr6_callback, NULL) != 0)
        printf("Getaddr6 returned with error!\n");
}

void mdns_getaddr_callback(char *str, void *arg)
{
    if (!str)
        printf("Getaddr: timeout occurred!\n");
    else
        printf("Getaddr callback called, str: %s\n", str);

    if(pico_mdns_getname(str, &mdns_getname_callback, arg) != 0)
        printf("Getname returned with error!\n");
}

void mdns_init_callback(char *str, void *arg)
{
//    char *peername = (char *)arg;
//    printf("Init callback called, str: %s\n", str);
//    if(!peername) {
//        printf("No system name supplied!\n");
//        exit(-1);
//    }
//
//    if(pico_mdns_getaddr(peername, &mdns_getaddr_callback, peername) != 0)
//        printf("Getaddr returned with error!\n");
}

void app_mdns(char *arg, struct pico_ipv4_link *link)
{
    char *hostname, *peername;
    char *nxt = arg;
    pico_mdns_res_record_list *records = NULL;
    
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
    
    if (!link) {
        printf("Link not found!\n");
        exit(255);
    }
    
    printf("Starting to claim name: %s, system name: %s\n", hostname, peername);
    
    if (pico_mdns_init(0, &mdns_init_callback, peername) != 0) {
        printf("Initialisation returned with Error!\n");
        exit(255);
    }
    printf("mDNS module initialised\n");
    
    /* Create a resource record you want to register */
    if (pico_mdns_res_record_create(&records, hostname, (void*)(&(link->address)), PICO_DNS_TYPE_A, 120, PICO_MDNS_RES_RECORD_UNIQUE) != 0) {
        printf("Could not create mDNS resource record!\n");
        exit(255);
    }
    
    /* Check if records is not still empty */
    if (!records) {
        printf("Creating a mDNS resource record returned NULL!\n");
    }
    
    /* Try to claim it */
    if (pico_mdns_claim(records, &mdns_init_callback, peername) != 0) {
        printf("Could not claim mDNS resource record!\n");
        exit(255);
    }
    printf("mDNS resource record claimed\n");
    
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}
#endif
/*** END MDNS ***/
