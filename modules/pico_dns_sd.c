/*********************************************************************
 PicoTCP. Copyright (c) 2014-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.
 .
 Author: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_dns_sd.h"

/* --- Debugging --- */
#define DEBUG 1

#if DEBUG == 0
#define dns_sd_dbg(...) do {} while(0)
#else
#define dns_sd_dbg dbg
#endif

/* --- PROTOTYPES --- */
key_value_pair_t *
pico_dns_sd_kv_vector_get( kv_vector *vector, uint16_t index );
int
pico_dns_sd_kv_vector_erase( kv_vector *vector );
/* ------------------- */

typedef PACKED_STRUCT_DEF pico_dns_srv_record_prefix
{
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
} pico_dns_srv_record;

struct register_argument {
    void (*callback)(pico_mdns_record_vector *,
                     char *,
                     void *);
    void *arg;
};

/* ****************************************************************************
 *  Determines resulting string length of a key-value pair vector
 * ****************************************************************************/
static uint16_t
pico_dns_sd_kv_vector_strlen( kv_vector *vector )
{
    key_value_pair_t *iterator = NULL;
    uint16_t i = 0, len = 0;

    /* Check params */
    if (!vector) {
        pico_err = PICO_ERR_EINVAL;
        return 0;
    }

    /* Iterate over the key-value pairs */
    for (i = 0; i < vector->count; i++) {
        iterator = pico_dns_sd_kv_vector_get(vector, i);
        len = (uint16_t) (len + 1u /* Length byte */ +
                          strlen(iterator->key) /* Length of the key */);
        if (iterator->value)
            len = (uint16_t) (len + 1u /* '=' char */ +
                              strlen(iterator->value) /* Lenght of value */);
    }

    return len;
}

/* ****************************************************************************
 *  Creates an mDNS record with the SRV record format
 * ****************************************************************************/
static struct pico_mdns_record *
pico_dns_sd_srv_record_create( const char *url,
                               uint16_t priority,
                               uint16_t weight,
                               uint16_t port,
                               const char *target_url,
                               uint32_t ttl,
                               uint8_t flags )
{
    struct pico_mdns_record *record = NULL;
    pico_dns_srv_record *srv_data = NULL;
    char *target_rname = NULL;
    uint16_t srv_length = 0;

    /* Check params */
    if (!url || !target_url) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Determine the length the rdata buf needs to be */
    srv_length = (uint16_t) (6u + strlen(target_url) + 2u);

    /* Provide space for the data-buf */
    srv_data = (pico_dns_srv_record *) PICO_ZALLOC(srv_length);
    if (!srv_data) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* TODO: Check for Endianess */
    srv_data->priority = short_be(priority);
    srv_data->weight = short_be(weight);
    srv_data->port = short_be(port);

    /* Copy in the URL and convert to DNS notation */
    target_rname = pico_dns_url_to_qname(target_url);
    if (!target_rname) {
        dns_sd_dbg("Could not convert URL to qname!\n");
        PICO_FREE(srv_data);
        return NULL;
    }
    strcpy((char *)srv_data + 6u, target_rname);
    PICO_FREE(target_rname);

    /* Create and return new mDNS record */
    record = pico_mdns_record_create(url, srv_data, srv_length,
                                     PICO_DNS_TYPE_SRV,
                                     ttl, flags);
    PICO_FREE(srv_data);

    return record;
}

/* ****************************************************************************
 *  Creates an mDNS record with the TXT record format
 * ****************************************************************************/
static struct pico_mdns_record *
pico_dns_sd_txt_record_create( const char *url,
                               kv_vector key_value_pairs,
                               uint32_t ttl,
                               uint8_t flags )
{
    struct pico_mdns_record *record = NULL;
    key_value_pair_t *iterator = NULL;
    char *txt = NULL;
    uint16_t i = 0, txt_i = 0, pair_len = 0, key_len = 0, value_len = 0;

    /* Determine the length of the string to fit in all pairs */
    uint16_t len = pico_dns_sd_kv_vector_strlen(&key_value_pairs);

    /* Provide space for the txt buf */
    txt = (char *)PICO_ZALLOC(len);
    if (!txt) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Iterate over all the key-value pairs */
    for (i = 0; i < key_value_pairs.count; i++) {
        iterator = pico_dns_sd_kv_vector_get(&key_value_pairs, i);

        /* Determine the length of the key */
        key_len = (uint16_t) strlen(iterator->key);
        pair_len = key_len;

        /* If value is not a NULL-ptr */
        if (iterator->value) {
            value_len = (uint16_t) strlen(iterator->value);
            pair_len = (uint16_t) (pair_len + 1u + value_len);
        }

        /* Set the pair length label */
        txt[txt_i] = (char)pair_len;

        /* Copy the key */
        strcpy(txt + txt_i + 1u, iterator->key);

        /* Copy the value if it is not a NULL-ptr */
        if (iterator->value) {
            strcpy(txt + txt_i + 1u + key_len, "=");
            strcpy(txt + txt_i + 2u + key_len, iterator->value);
            txt_i = (uint16_t) (txt_i + 2u + key_len + value_len);
        } else {
            txt_i = (uint16_t) (txt_i + 1u + key_len);
        }
    }

    record = pico_mdns_record_create(url, txt, len, PICO_DNS_TYPE_TXT,
                                     ttl, flags);
    PICO_FREE(txt);

    return record;
}

/* ****************************************************************************
 *  Creates a single key-value pair struct
 * ****************************************************************************/
static key_value_pair_t *
pico_dns_sd_kv_create( const char *key, const char *value )
{
    key_value_pair_t *kv_pair = NULL;

    /* Chekc params */
    if (!key) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Provide space for the new pair */
    kv_pair = (key_value_pair_t *)PICO_ZALLOC(sizeof(key_value_pair_t));
    if (!kv_pair) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Provide space to copy the values */
    kv_pair->key = (char *)PICO_ZALLOC((size_t)(strlen(key) + 1));
    if (!(kv_pair->key)) {
        pico_err = PICO_ERR_ENOMEM;
        PICO_FREE(kv_pair);
        return NULL;
    }
    strcpy(kv_pair->key, key);

    if (!value)
        kv_pair->value = NULL;
    else {
        kv_pair->value = (char *)PICO_ZALLOC((size_t)(strlen(value) + 1));
        if (!(kv_pair->value)) {
            pico_err = PICO_ERR_ENOMEM;
            PICO_FREE(kv_pair->key);
            PICO_FREE(kv_pair);
            return NULL;
        }
        strcpy(kv_pair->value, value);
    }

    return kv_pair;
}

/* ****************************************************************************
 *  Deletes a single key-value pair struct
 * ****************************************************************************/
static int
pico_dns_sd_kv_delete( key_value_pair_t **kv_pair )
{
    /* Check params */
    if (!kv_pair || !(*kv_pair)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Delete the fields */
    if ((*kv_pair)->key)
        PICO_FREE((*kv_pair)->key);
    if ((*kv_pair)->value)
        PICO_FREE((*kv_pair)->value);

    PICO_FREE(*kv_pair);
    *kv_pair = NULL;
    kv_pair = NULL;

    return 0;
}

/* ****************************************************************************
 *  Returns 0 when the type is correctly formatted and it's label lengths are
 *  in the allowed boundaries
 * ****************************************************************************/
static int
pico_dns_sd_check_type_format( const char *type )
{
    uint16_t first_lbl_length = 0;

    /* Check params */
    if (!type)
        return -1;

    /* Then check if the first label is larger than 17 bytes */
    first_lbl_length = pico_dns_first_label_length(type);

    /* Check if there is a subtype present */
    if (memcmp(type + first_lbl_length + 1, "_sub", 4) == 0) {
        /* Check the subtype's length */
        if (first_lbl_length > 63)
            return -1;

        /* Get the length of the service name */
        first_lbl_length = pico_dns_first_label_length(type +
                                                          first_lbl_length + 6);
    } else {
        /* Check if type is not greater then 21 bytes (22 - 1, since the length
           byte of the service name isn't included yet) */
        if (strlen(type) > (size_t) 21)
            return -1;
    }

    /* Check if the service name is not greater then 16 bytes (17 - 1) */
    if (first_lbl_length > (uint16_t) 16u)
        return -1;

    return 0;
}

/* ****************************************************************************
 *  Returns 0 when the instance name is of the correct length
 * ****************************************************************************/
static int
pico_dns_sd_check_instance_name_format( const char *name )
{
    /* First of all check if the total length is larger than 63 bytes */
    if (strlen(name) > 63)
        return -1;
    return 0;
}

/* ****************************************************************************
 *  Append the instance name and service type to create a .local service url.
 * ****************************************************************************/
static char *
pico_dns_sd_create_service_url( const char *name,
                                const char *type )
{
    char *url = NULL;
    uint16_t len = 0, namelen = 0, typelen = 0;

    /* Check params */
    if (!name || !type) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (pico_dns_sd_check_type_format(type)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (pico_dns_sd_check_instance_name_format(name)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    namelen = (uint16_t)strlen(name);
    typelen = (uint16_t)strlen(type);

    /* Determine the length that the URL needs to be */
    len = (uint16_t)(namelen + 1u /* for '.'*/ +
                     typelen + 7u /* for '.local\0' */ );
    url = (char *)PICO_ZALLOC(len);
    if (!url) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Append the parts together */
    strcpy(url, name);
    strcpy(url + namelen, ".");
    strcpy(url + namelen + 1, type);
    strcpy(url + namelen + 1 + typelen, ".local");
    
    return url;
}

static void
pico_dns_sd_claimed_callback( pico_mdns_record_vector *records,
                              char *str,
                              void *arg )
{
    struct register_argument *arguments = NULL;

    IGNORE_PARAMETER(str);

    /* Parse in the arguments */
    if (!arg || !records) {
        pico_err = PICO_ERR_EINVAL;
        return;
    }
	arguments = (struct register_argument *) arg;

	/* Call callback */
	arguments->callback(records, NULL, arguments->arg);

    PICO_FREE(arguments);
}

/* ****************************************************************************
 *  This function actually does exactly the same as pico_mdns_init();
 * ****************************************************************************/
int
pico_dns_sd_init( const char *_hostname,
                  struct pico_ip4 address,
                  uint8_t flags,
                  void (*callback)(pico_mdns_record_vector *,
                                   char *,
                                   void *),
                  void *arg )
{
    return pico_mdns_init(_hostname, address, flags, callback, arg);
}

/* ****************************************************************************
 *  Register a service on in the '.local'-domain of a certain type. Port number
 *  Needs to be provided and can't be 0.
 * ****************************************************************************/
int
pico_dns_sd_register_service( const char *name,
                              const char *type,
                              uint16_t port,
                              kv_vector *txt_data,
                              uint16_t ttl,
                              void (*callback)(pico_mdns_record_vector *,
                                               char *,
                                               void *),
                              void *arg)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *srv_record = NULL;
    struct pico_mdns_record *txt_record = NULL;
    struct register_argument *arguments = NULL;
    const char *hostname = pico_mdns_get_hostname();

    /* Try to create a service URL to create records with */
    char *url = pico_dns_sd_create_service_url(name, type);
    if (!url) {
        dns_sd_dbg("Could not create service URL!\n");
        return -1;
    }

    /* Check other params */
    if (!txt_data) {
        dns_sd_dbg("No key-value pair vector passed!\n");
        PICO_FREE(url);
        return -1;
    }

    printf("Target: %s\n", hostname);

    /* Create the SRV record */
    srv_record = pico_dns_sd_srv_record_create(url, 0, 0, port, hostname,
                                               ttl, PICO_MDNS_RECORD_UNIQUE);
	if (!srv_record) {
		PICO_FREE(url);
		return -1;
	}
    /* Create the TXT record */
    txt_record = pico_dns_sd_txt_record_create(url, *txt_data, ttl,
                                               PICO_MDNS_RECORD_UNIQUE);
	PICO_FREE(url);
    if (!txt_record) {
    	pico_mdns_record_delete(&srv_record);
    	return -1;
    }
    /* Erase the key-value pair vector, it's no longer needed */
    if (pico_dns_sd_kv_vector_erase(txt_data) < 0) {
        dns_sd_dbg("Could not erase key-value pair vector!\n");
        return -1;
    }

    pico_mdns_record_vector_add(&rvector, srv_record);
    pico_mdns_record_vector_add(&rvector, txt_record);

    /* Provide space for argument struct */
    arguments = PICO_ZALLOC(sizeof(struct register_argument));
    if (!arguments) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }
    arguments->callback = callback;
    arguments->arg = arg;

    if (pico_mdns_claim(rvector, pico_dns_sd_claimed_callback,
                        (void *)arguments) < 0) {
        dns_sd_dbg("Trying to claim SRV and TXT records failed!\n");
        return -1;
    }

    return 0;
}

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
                            void *arg )
{
    /* TODO: (Implement this) */
    IGNORE_PARAMETER(type);
    IGNORE_PARAMETER(callback);
    IGNORE_PARAMETER(arg);
    return 0;
}

/* ****************************************************************************
 *  Initialise a key-value pair vector
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_init( kv_vector *vector )
{
    /* Check params */
    if (!vector) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    vector->pairs = NULL;
    vector->count = 0;
    return 0;
}

/* ****************************************************************************
 *  Add a key-value pair to the key-value pair vector
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_add( kv_vector *vector, char *key, char *value )
{
    key_value_pair_t *kv_pair = NULL;
    key_value_pair_t **new_pairs = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!vector || !key) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Try to create a new key value pair */
    kv_pair = pico_dns_sd_kv_create(key, value);
    if (!kv_pair)
        return -1;

    /* Provide enough space for the new pair pointers */
    new_pairs = PICO_ZALLOC(sizeof(key_value_pair_t *) *
                            (vector->count +1u));
    if (!new_pairs) {
        pico_err = PICO_ERR_ENOMEM;
        pico_dns_sd_kv_delete(&kv_pair);
        return -1;
    }

    /* Copy previous pairs and add new one */
    for (i = 0; i < vector->count; i++)
        new_pairs[i] = vector->pairs[i];
    new_pairs[i] = kv_pair;

    /* Free the previous array */
    if (vector->pairs)
        PICO_FREE(vector->pairs);

    vector->pairs = new_pairs;
    vector->count++;

    return 0;
}

/* ****************************************************************************
 *  Gets a key-value pair from the key-value pair vector
 * ****************************************************************************/
key_value_pair_t *
pico_dns_sd_kv_vector_get( kv_vector *vector, uint16_t index )
{
    /* Check params */
    if (!vector)
        return NULL;

    /* Return record with conditioned index */
    if (index < vector->count)
        return vector->pairs[index];

    return NULL;
}

/* ****************************************************************************
 *  Erase all the contents of a key
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_erase( kv_vector *vector )
{
    uint16_t i = 0;

    /* Iterate over each key-value pair */
    for (i = 0; i < vector->count; i++) {
        if (pico_dns_sd_kv_delete(&(vector->pairs[i])) < 0) {
            dns_sd_dbg("Could not delete key-value pairs from vector");
            return -1;
        }
    }

    vector->pairs = NULL;
    vector->count = 0;

    return 0;
}
