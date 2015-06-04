#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_common.h"
#include "pico_tree.h"
#include "pico_dev_mock.c"
//#include "modules/pico_dns_sd.c"
#include "check.h"
//
//void callback( pico_mdns_record_vector *vector,
//               char *str,
//               void *arg )
//{
//    /* This doesn't even gets called, tests exit before possible callback */
//    IGNORE_PARAMETER(str);
//    IGNORE_PARAMETER(arg);
//    IGNORE_PARAMETER(vector);
//}
//
//int dns_sd_init()
//{
//    struct mock_device *mock = NULL;
//
//    struct pico_ip4 local = {.addr = long_be(0x0a280064)};
//    struct pico_ip4 netmask = {.addr = long_be(0xffffff00)};
//
//    mock = pico_mock_create(NULL);
//    if (!mock)
//        return -1;
//
//    pico_ipv4_link_add(mock->dev, local, netmask);
//
//    /* Try to initialise the mDNS module right */
//    return pico_dns_sd_init("host.local", local, 0,
//                            callback, NULL);
//}
//
//START_TEST(tc_dns_sd_kv_vector_strlen)
//{
//    kv_vector pairs = {0};
//
//    pico_dns_sd_kv_vector_add(&pairs, "textvers", "1");
//    pico_dns_sd_kv_vector_add(&pairs, "pass", NULL);
//    pico_dns_sd_kv_vector_add(&pairs, "color", "");
//
//    fail_unless(pico_dns_sd_kv_vector_strlen(&pairs) == 23,
//                "dns_sd_kv_vector_strlen returned wrong length!\n");
//
//    pico_dns_sd_kv_vector_erase(&pairs);
//}
//END_TEST
//START_TEST(tc_dns_sd_srv_record_create)
//{
//    struct pico_mdns_record *record = NULL;
//
//    uint8_t buf[19] = { 0,0, 0,0, 0,80,
//                        5,'h','i','t','e','x',
//                        5,'l','o','c','a','l',
//                        0 };
//
//    record = pico_dns_sd_srv_record_create("test.local", 0, 0, 80,
//                                           "hitex.local", 10,
//                                           PICO_MDNS_RECORD_UNIQUE);
//
//    fail_unless(strcmp(record->record->rname, "\4test\5local") == 0,
//                "Name of SRV record not correct!\n");
//    fail_unless(short_be(record->record->rsuffix->rtype) == 33,
//                "Type of SRV record not correctly set!\n");
//    fail_unless(short_be(record->record->rsuffix->rclass) == 0x8001,
//                "Class of SRV record not correctly set!\n");
//    fail_unless(short_be(record->record->rsuffix->rdlength) == 19,
//                "rdlength of SRV record not correctly set!\n");
//    fail_unless(long_be(record->record->rsuffix->rttl) == 10,
//                "TTL of SRV record not correctly set!\n");
//    fail_unless(memcmp(record->record->rdata, buf, 19) == 0,
//                "Rdata of TXT record not correctly set!\n");
//    pico_mdns_record_delete(&record);
//}
//END_TEST
//START_TEST(tc_dns_sd_txt_record_create)
//{
//    struct pico_mdns_record *record = NULL;
//    kv_vector pairs = {0};
//
//    uint8_t buf[23] = { 10,'t','e','x','t','v','e','r','s','=','1',
//                        4,'p','a','s','s',
//                        6,'c','o','l','o','r','=' };
//
//    pico_dns_sd_kv_vector_add(&pairs, "textvers", "1");
//    pico_dns_sd_kv_vector_add(&pairs, "pass", NULL);
//    pico_dns_sd_kv_vector_add(&pairs, "color", "");
//
//    record = pico_dns_sd_txt_record_create("test.local", pairs, 10,
//                                           PICO_MDNS_RECORD_UNIQUE);
//
//    fail_unless(strcmp(record->record->rname, "\4test\5local") == 0,
//                "Name of TXT record not correct!\n");
//    fail_unless(short_be(record->record->rsuffix->rtype) == 16,
//                "Type of TXT record not correctly set!\n");
//    fail_unless(short_be(record->record->rsuffix->rclass) == 0x8001,
//                "Class of TXT record not correctly set!\n");
//    fail_unless(short_be(record->record->rsuffix->rdlength) == 23,
//                "rdlength of TXT record not correctly set!\n");
//    fail_unless(long_be(record->record->rsuffix->rttl) == 10,
//                "TTL of TXT record not correctly set!\n");
//    fail_unless(memcmp(record->record->rdata, buf, 23) == 0,
//                "Rdata of TXT record not correctly set!\n");
//    pico_mdns_record_delete(&record);
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_create)
//{
//    key_value_pair_t *pair = NULL;
//
//    pair = pico_dns_sd_kv_create("textvers", "1");
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(strcmp(pair->value, "1") == 0,
//                "dns_sd_kv_create failed!\n");
//    PICO_FREE(pair->key);
//    PICO_FREE(pair->value);
//    PICO_FREE(pair);
//
//    pair = pico_dns_sd_kv_create("textvers", NULL);
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(pair->value == NULL,
//                "dns_sd_kv_create failed!\n");
//    PICO_FREE(pair->key);
//    PICO_FREE(pair);
//
//    pair = pico_dns_sd_kv_create("textvers", "");
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(strcmp(pair->value, "") == 0,
//                "dns_sd_kv_create failed!\n");
//    PICO_FREE(pair->key);
//    PICO_FREE(pair->value);
//    PICO_FREE(pair);
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_delete)
//{
//    key_value_pair_t *pair = NULL;
//
//    pair = pico_dns_sd_kv_create("textvers", "1");
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(strcmp(pair->value, "1") == 0,
//                "dns_sd_kv_create failed!\n");
//    pico_dns_sd_kv_delete(&pair);
//    fail_unless(pair == NULL,
//                "dns_sd_kv_delete failed!\n");
//
//    pair = pico_dns_sd_kv_create("textvers", NULL);
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(pair->value == NULL,
//                "dns_sd_kv_create failed!\n");
//    pico_dns_sd_kv_delete(&pair);
//    fail_unless(pair == NULL,
//                "dns_sd_kv_delete failed!\n");
//
//    pair = pico_dns_sd_kv_create("textvers", "");
//    fail_unless(strcmp(pair->key, "textvers") == 0,
//                "dns_sd_kv_create failed!\n");
//    fail_unless(strcmp(pair->value, "") == 0,
//                "dns_sd_kv_create failed!\n");
//    pico_dns_sd_kv_delete(&pair);
//    fail_unless(pair == NULL,
//                "dns_sd_kv_delete failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_check_type_format)
//{
//    fail_unless(pico_dns_sd_check_type_format("_http._tcp") == 0,
//                "dns_sd_check_type_format failed with correct format!\n");
//    fail_unless(pico_dns_sd_check_type_format("_printer._sub._http._tcp")
//                == 0,
//                "dns_sd_check_type_format failed with subtype!\n");
//
//    /* Test too long subtype */
//    fail_unless(pico_dns_sd_check_type_format(
//"1234567891123456789212345678931234567894123456789512345678961234._sub._http._tcp"), "dns_sd_check_type_format failed with too big subtype!\n");
//
//    /* Test too long service type with subtype */
//    fail_unless(pico_dns_sd_check_type_format(
//                                        "printer._sub.0123456789112345678._tcp"),
//                "dns_sd_check_type_format failed with too big sn w/ sub!\n");
//
//    /* Test too long service type with subtype */
//    fail_unless(pico_dns_sd_check_type_format("0123456789112345678._tcp"),
//                "dns_sd_check_type_format failed with too big sn!\n");
//
//}
//END_TEST
//START_TEST(tc_dns_sd_check_instance_name_format)
//{
//    /* Test too long name */
//    fail_unless(pico_dns_sd_check_instance_name_format(
//"1234567891123456789212345678931234567894123456789512345678961234"),
//                "dns_sd_check_instance_name_format failed with too big name!\n");
//
//    fail_unless(pico_dns_sd_check_instance_name_format("Hello World!") == 0,
//                "dns_sd_check_instance_name_format failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_create_service_url)
//{
//    char *service_url = NULL;
//
//    service_url = pico_dns_sd_create_service_url("Hello World!", "_http._tcp");
//
//    fail_unless(strcmp(service_url, "Hello World!._http._tcp.local") == 0,
//                "dns_sd_create_service_url failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_claimed_callback)
//{
//    pico_mdns_record_vector vector = {0};
//    struct register_argument *test = NULL;
//    struct pico_mdns_record *srv_record = NULL;
//    char *name = "Hello World!";
//    char *url = "Hello World!._http._tcp.local";
//
//    pico_stack_init();
//    dns_sd_init();
//
//    /* Create a SRV record to pass in */
//    srv_record = pico_dns_sd_srv_record_create(url, 0, 0, 80, "host.local",
//                                               120, PICO_MDNS_RECORD_UNIQUE);
//    pico_mdns_record_vector_add(&vector, srv_record);
//
//    test = PICO_ZALLOC(sizeof(struct register_argument));
//    test->callback = callback;
//    test->arg = NULL;
//
//    /* Check if no errors occur */
//    pico_dns_sd_claimed_callback(NULL, NULL, NULL);
//    pico_dns_sd_claimed_callback(NULL, NULL, test);
//    pico_dns_sd_claimed_callback(&vector, NULL, test);
//}
//END_TEST
//START_TEST(tc_dns_sd_init)
//{
//    pico_stack_init();
//    fail_unless(dns_sd_init() == 0,
//                "dns_sd_init failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_register_service)
//{
//    kv_vector vector = {0};
//
//    pico_stack_init();
//    dns_sd_init();
//
//    fail_unless(pico_dns_sd_register_service("Hello World!",
//                                             "_kerberos._udp",
//                                             88, &vector, 120,
//                                             callback, NULL) == 0,
//                "dns_sd_register_service failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_browse_service)
//{
//    /* Not implemented in code */
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_vector_init)
//{
//    kv_vector test;
//
//    pico_dns_sd_kv_vector_init(&test);
//
//    fail_unless(test.pairs == NULL,
//                "dns_sd_kv_vector_init failed!\n");
//    fail_unless(test.count == 0,
//                "dns_sd_kv_vector_init failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_vector_add)
//{
//    kv_vector pairs = {0};
//    char *key = NULL;
//
//    pico_dns_sd_kv_vector_add(&pairs, "textvers", "1");
//    pico_dns_sd_kv_vector_add(&pairs, "pass", NULL);
//    pico_dns_sd_kv_vector_add(&pairs, "color", "");
//
//    key = pico_dns_sd_kv_vector_get(&pairs, 2)->key;
//    fail_unless(strcmp("color", key) == 0,
//                "dns_sd_kv_vector_add failed!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_vector_get)
//{
//    kv_vector pairs = {0};
//    char *key = NULL;
//
//    pico_dns_sd_kv_vector_add(&pairs, "textvers", "1");
//    pico_dns_sd_kv_vector_add(&pairs, "pass", NULL);
//    pico_dns_sd_kv_vector_add(&pairs, "color", "");
//
//    key = pico_dns_sd_kv_vector_get(&pairs, 2)->key;
//    fail_unless(strcmp("color", key) == 0,
//                "dns_sd_kv_vector_get failed!\n");
//
//    fail_unless(pico_dns_sd_kv_vector_get(&pairs, 3) == NULL,
//                "dns_sd_kv_vector_get failed @ OOB!\n");
//}
//END_TEST
//START_TEST(tc_dns_sd_kv_vector_erase)
//{
//    kv_vector pairs = {0};
//
//    pico_dns_sd_kv_vector_add(&pairs, "textvers", "1");
//    pico_dns_sd_kv_vector_add(&pairs, "pass", NULL);
//    pico_dns_sd_kv_vector_add(&pairs, "color", "");
//
//    pico_dns_sd_kv_vector_erase(&pairs);
//
//    fail_unless(pairs.pairs == NULL,
//                "dns_sd_kv_vector_erase failed!\n");
//    fail_unless(pairs.count == 0,
//                "dns_sd_kv_vector_erase failed!\n");
//}
//END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");
//
//    /* Key-Value pair vector plain creation function */
//    TCase *TCase_dns_sd_kv_vector_strlen = tcase_create("Unit test for dns_sd_kv_vector_strlen");
//
//    /* DNS utility functions */
//    TCase *TCase_dns_sd_srv_record_create = tcase_create("Unit test for dns_sd_srv_record_create");
//    TCase *TCase_dns_sd_txt_record_create = tcase_create("Unit test for dns_sd_txt_record_create");
//
//    /* Key-Value pair creation */
//    TCase *TCase_dns_sd_kv_create = tcase_create("Unit test for dns_sd_kv_create");
//    TCase *TCase_dns_sd_kv_delete = tcase_create("Unit test for dns_sd_kv_delete");
//
//    /* Utility functions */
//    TCase *TCase_dns_sd_check_type_format = tcase_create("Unit test for dns_sd_check_type_format");
//    TCase *TCase_dns_sd_check_instance_name_format = tcase_create("Unit test for dns_sd_check_instance_name_format");
//    TCase *TCase_dns_sd_create_service_url = tcase_create("Unit test for dns_sd_create_service_url");
//    TCase *TCase_dns_sd_claimed_callback = tcase_create("Unit test for dns_sd_claimed_callback");
//
//    /* DNS SD API functions */
//    TCase *TCase_dns_sd_init = tcase_create("Unit test for dns_sd_init");
//    TCase *TCase_dns_sd_register_service = tcase_create("Unit test for dns_sd_register_service");
//    TCase *TCase_dns_sd_browse_service = tcase_create("Unit test for dns_sd_browse_service");
//
//    /* Key-Value vector functions */
//    TCase *TCase_dns_sd_kv_vector_init = tcase_create("Unit test for dns_sd_kv_vector_init");
//    TCase *TCase_dns_sd_kv_vector_add = tcase_create("Unit test for dns_sd_kv_vector_add");
//    TCase *TCase_dns_sd_kv_vector_get = tcase_create("Unit test for dns_sd_kv_vector_get");
//    TCase *TCase_dns_sd_kv_vector_erase = tcase_create("Unit test for dns_sd_kv_vector_erase");
//
//    /* Key-Value pair vector plain creation function */
//    tcase_add_test(TCase_dns_sd_kv_vector_strlen, tc_dns_sd_kv_vector_strlen);
//    suite_add_tcase(s, TCase_dns_sd_kv_vector_strlen);
//
//    /* DNS utility functions */
//    tcase_add_test(TCase_dns_sd_srv_record_create, tc_dns_sd_srv_record_create);
//    suite_add_tcase(s, TCase_dns_sd_srv_record_create);
//    tcase_add_test(TCase_dns_sd_txt_record_create, tc_dns_sd_txt_record_create);
//    suite_add_tcase(s, TCase_dns_sd_txt_record_create);
//
//    /* Key-Value pair creation */
//    tcase_add_test(TCase_dns_sd_kv_create, tc_dns_sd_kv_create);
//    suite_add_tcase(s, TCase_dns_sd_kv_create);
//    tcase_add_test(TCase_dns_sd_kv_delete, tc_dns_sd_kv_delete);
//    suite_add_tcase(s, TCase_dns_sd_kv_delete);
//
//    /* Utility functions */
//    tcase_add_test(TCase_dns_sd_check_type_format, tc_dns_sd_check_type_format);
//    suite_add_tcase(s, TCase_dns_sd_check_type_format);
//    tcase_add_test(TCase_dns_sd_check_instance_name_format, tc_dns_sd_check_instance_name_format);
//    suite_add_tcase(s, TCase_dns_sd_check_instance_name_format);
//    tcase_add_test(TCase_dns_sd_create_service_url, tc_dns_sd_create_service_url);
//    suite_add_tcase(s, TCase_dns_sd_create_service_url);
//    tcase_add_test(TCase_dns_sd_claimed_callback, tc_dns_sd_claimed_callback);
//    suite_add_tcase(s, TCase_dns_sd_claimed_callback);
//
//    /* DNS SD API functions */
//    tcase_add_test(TCase_dns_sd_init, tc_dns_sd_init);
//    suite_add_tcase(s, TCase_dns_sd_init);
//    tcase_add_test(TCase_dns_sd_register_service, tc_dns_sd_register_service);
//    suite_add_tcase(s, TCase_dns_sd_register_service);
//    tcase_add_test(TCase_dns_sd_browse_service, tc_dns_sd_browse_service);
//    suite_add_tcase(s, TCase_dns_sd_browse_service);
//
//    /* Key-Value vector functions */
//    tcase_add_test(TCase_dns_sd_kv_vector_init, tc_dns_sd_kv_vector_init);
//    suite_add_tcase(s, TCase_dns_sd_kv_vector_init);
//    tcase_add_test(TCase_dns_sd_kv_vector_add, tc_dns_sd_kv_vector_add);
//    suite_add_tcase(s, TCase_dns_sd_kv_vector_add);
//    tcase_add_test(TCase_dns_sd_kv_vector_get, tc_dns_sd_kv_vector_get);
//    suite_add_tcase(s, TCase_dns_sd_kv_vector_get);
//    tcase_add_test(TCase_dns_sd_kv_vector_erase, tc_dns_sd_kv_vector_erase);
//    suite_add_tcase(s, TCase_dns_sd_kv_vector_erase);
//
    return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}