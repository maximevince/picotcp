#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_dns_common.h"
#include "pico_tree.h"
#include "pico_dev_mock.c"
#include "modules/pico_mdns.c"
#include "check.h"

void callback( pico_mdns_record_vector *vector,
               char *str,
               void *arg )
{
    IGNORE_PARAMETER(vector);
    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    /* Do nothing, because fail_unless and fail_if don't work here */
}

int mdns_init()
{
    struct mock_device *mock = NULL;

    struct pico_ip4 local = {.addr = long_be(0x0a280064)};
    struct pico_ip4 netmask = {.addr = long_be(0xffffff00)};

    mock = pico_mock_create(NULL);
    if (!mock)
        return -1;

    pico_ipv4_link_add(mock->dev, local, netmask);

    /* Try to initialise the mDNS module right */
    return pico_mdns_init("host.local", pico_ipv4_link_by_dev(mock->dev), 0,
                          callback, NULL);
}

START_TEST(tc_mdns_init)
{
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    pico_stack_init();

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(NULL, NULL, 0, callback, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(hostname, NULL, 0, callback, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(hostname, NULL, 0, NULL, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    ret = mdns_init();
    fail_unless(0 == ret, "mdns_init failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Comparing functions */
START_TEST(tc_mdns_rdata_cmp)
{
    uint8_t rdata1[10] = { 1,2,3,4,5,6,7,8,9,10 };
    uint8_t rdata2[10] = { 1,2,3,3,5,6,7,8,9,10 };
    uint8_t rdata3[1] = { 2 };
    uint8_t rdata4[1] = { 1 };
    uint8_t rdata5[11] = { 1,2,3,4,5,6,7,8,9,10,9 };
    uint8_t rdata6[12] = { 1,2,3,4,5,6,7,8,9,10,11 };
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Check equal data and size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata1, 10, 10);
    fail_unless(0 == ret, "mdns_rdata_cmp failed with equal data and size!\n");

    /* Check smaller data and equal size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata2, 10, 10);
    fail_unless(1 == ret, "mdns_rdata_cmp failed with smaller data and equal size!\n");

    /* Check larger data and smaller size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata3, 10, 1);
    fail_unless(-1 == ret, "mdns_rdata_cmp failed with larger data and smaller size!\n");

    /* Check equal data and smaller size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata4, 10, 1);
    fail_unless(1 == ret, "mdns_rdata_cmp failed with equal data and smaller size!\n");

    /* Check smaller data and larger size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata5, 10, 11);
    fail_unless(-1 == ret, "mdns_rdata_cmp failed with smaller data and larger size!\n");

    /* Check larger data and larger size */
    ret = pico_mdns_rdata_cmp(rdata1, rdata6, 10, 11);
    fail_unless(-1 == ret, "mdns_rdata_cmp failed with larger data and larger size!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cmp)
{
    struct pico_mdns_record a = {0};
    struct pico_mdns_record b = {0};
    const char *url1 = "foo.local";
    const char *url3 = "a.local";
    struct pico_ip4 rdata = {0};
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create test records */
    a.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare equal records */
    ret = pico_mdns_cmp((void *) &a, (void *) &b);
    fail_unless(0 == ret, "mdns_cmp failed with equal records!\n");
    pico_dns_record_delete(&(a.record));
    pico_dns_record_delete(&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_PTR,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_mdns_cmp((void *) &a, (void *) &b);
    fail_unless(1 == ret, "mdns_cmp failed with same name, different types!\n");
    pico_dns_record_delete(&(a.record));
    pico_dns_record_delete(&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url3, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_mdns_cmp((void *) &a, (void *) &b);
    fail_unless(-1 == ret, "mdns_cmp failed with different name, same types!\n");
    pico_dns_record_delete(&(a.record));
    pico_dns_record_delete(&(b.record));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cmp_name_type)
{
    struct pico_mdns_record a = {0};
    struct pico_mdns_record b = {0};
    const char *url1 = "foo.local";
    const char *url3 = "a.local";
    struct pico_ip4 rdata = {0};
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create different test records */
    a.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_PTR,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_mdns_cmp_name_type((void *) &a, (void *) &b);
    fail_unless(1 == ret, "mdns_cmp_name_type failed with different types!\n");
    pico_dns_record_delete(&(a.record));
    pico_dns_record_delete(&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url3, url1, strlen(url1), &len,
                                      PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url3, url1, strlen(url1), &len,
                                      PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_mdns_cmp_name_type((void *) &a, (void *) &b);
    fail_unless(0 == ret, "mdns_cmp_name_type failed!\n");
    pico_dns_record_delete(&(a.record));
    pico_dns_record_delete(&(b.record));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_cmp)
{
    struct pico_mdns_cookie a;
    struct pico_mdns_cookie b;
    struct pico_dns_question *question1 = NULL;
    struct pico_dns_question *question2 = NULL;
    struct pico_dns_question *question3 = NULL;
    struct pico_dns_question *question4 = NULL;
    struct pico_dns_question *question5 = NULL;
    struct pico_mdns_record record1 = {0}, record2 = {0}, record3 = {0},
                            record4 = {0};
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    const char *url3 = "pi.local";
    const char *url4 = "ab.local";
    struct pico_ip4 rdata = {0};
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create some questions */
    question1 = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question1, "Could not create question 1!\n");
    question2 = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_PTR,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 2!\n");
    question3 = pico_dns_question_create(url3, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 3!\n");
    question4 = pico_dns_question_create(url4, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_AAAA,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 4!\n");
    question5 = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_TYPE_AAAA, 0);
    fail_if(!question2, "Could not create question 5!\n");

    /* Create test records */
    record1.record = pico_dns_record_create(url1, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record1.record, "Record 1 could not be created!\n");
    record2.record = pico_dns_record_create(url1, &rdata, 4, &len,
                                            PICO_DNS_TYPE_PTR,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record2.record, "Record 2 could not be created!\n");
    record3.record = pico_dns_record_create(url2, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record3.record, "Record 3 could not be created!\n");
    record4.record = pico_dns_record_create(url4, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record4.record, "Record 3 could not be created!\n");

    /* Create 2 exactly the same cookies */
    pico_dns_question_vector_init(&(a.qvector));
    pico_dns_question_vector_add(&(a.qvector), question1);
    pico_dns_question_vector_add(&(a.qvector), question2);
    pico_dns_question_vector_add(&(a.qvector), question3);
    pico_dns_question_vector_add(&(a.qvector), question4);
    pico_dns_question_vector_add(&(a.qvector), question5);
    pico_mdns_record_vector_init(&(a.rvector));
    pico_mdns_record_vector_add(&(a.rvector), &record1);
    pico_mdns_record_vector_add(&(a.rvector), &record2);
    pico_mdns_record_vector_add(&(a.rvector), &record3);
    pico_mdns_record_vector_add(&(a.rvector), &record4);

    pico_dns_question_vector_init(&(b.qvector));
    pico_dns_question_vector_add(&(b.qvector), question1);
    pico_dns_question_vector_add(&(b.qvector), question2);
    pico_dns_question_vector_add(&(b.qvector), question3);
    pico_dns_question_vector_add(&(b.qvector), question4);
    pico_dns_question_vector_add(&(b.qvector), question5);
    pico_mdns_record_vector_init(&(b.rvector));
    pico_mdns_record_vector_add(&(b.rvector), &record1);
    pico_mdns_record_vector_add(&(b.rvector), &record2);
    pico_mdns_record_vector_add(&(b.rvector), &record3);
    pico_mdns_record_vector_add(&(b.rvector), &record4);

    /* Try to compare exactly the same cookies*/
    ret = pico_mdns_cookie_cmp((void *) &a, (void *) &b);
    fail_unless(0 == ret, "mdns_cookie_cmp failed with equal cookies!\n");

    /* Try to compare the same cookies but with A more records than B */
    pico_mdns_record_vector_remove(&(b.rvector), 3);
    ret = pico_mdns_cookie_cmp((void *) &a, (void *) &b);
    fail_unless(1 == ret, "mdns_cookie_cmp failed with different N records!\n");

    /* Try to compare cookies but B a larger question than A*/
    pico_dns_question_vector_remove(&(a.qvector), 1);
    ret = pico_mdns_cookie_cmp((void *) &a, (void *) &b);
    fail_unless(-1 == ret, "mdns_cookie_cmp failed with larger question B!\n");

    /* Insert more possibilities here.. */

    pico_dns_record_delete(&(record1.record));
    pico_dns_record_delete(&(record2.record));
    pico_dns_record_delete(&(record3.record));
    pico_dns_record_delete(&(record4.record));

    pico_dns_question_delete(&question1);
    pico_dns_question_delete(&question2);
    pico_dns_question_delete(&question3);
    pico_dns_question_delete(&question4);
    pico_dns_question_delete(&question5);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Cookie functions */
START_TEST(tc_mdns_cookie_delete)
{
    struct pico_mdns_cookie *a = NULL;
    pico_dns_question_vector qvector = {0};
    pico_mdns_record_vector rvector = {0};

    printf("*********************** starting %s * \n", __func__);

    fail_unless(pico_mdns_cookie_delete(&a) == -1,
                "mdns_cookie_delete failed checking params!\n");
    a = pico_mdns_cookie_create(qvector, rvector, 0, 0, NULL, NULL);
    fail_unless(pico_mdns_cookie_delete(&a) == 0,
                "mdns_cookie_delete failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_create)
{
    struct pico_mdns_cookie *a = NULL;
    pico_dns_question_vector qvector = {0};
    pico_mdns_record_vector rvector = {0};

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_cookie_create(qvector, rvector, 0, 0, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");

    pico_mdns_cookie_delete(&a);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_tree_find_query_cookie)
{
    struct pico_mdns_cookie *a = NULL, *b = NULL;
    pico_dns_question_vector qvector_a = {0}, qvector_b = {0};
    pico_mdns_record_vector rvector = {0};
    struct pico_dns_question *question1 = NULL;
    struct pico_dns_question *question2 = NULL;
    struct pico_dns_question *question3 = NULL;
    struct pico_dns_question *question4 = NULL;
    struct pico_dns_question *question5 = NULL;
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    const char *url3 = "pi.local";
    const char *url4 = "ab.local";
    const char *url5 = "t.local";
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create some questions */
    question1 = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question1, "Could not create question 1!\n");
    question2 = pico_dns_question_create(url5, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_PTR,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 2!\n");
    question3 = pico_dns_question_create(url3, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question3, "Could not create question 3!\n");
    question4 = pico_dns_question_create(url4, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_AAAA,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question4, "Could not create question 4!\n");
    question5 = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question5, "Could not create question 5!\n");

    pico_dns_question_vector_add(&qvector_a, question3);
    pico_dns_question_vector_add(&qvector_a, question4);

    pico_dns_question_vector_add(&qvector_b, question1);
    pico_dns_question_vector_add(&qvector_b, question2);
    pico_dns_question_vector_add(&qvector_b, question5);

    a = pico_mdns_cookie_create(qvector_a, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");
    b = pico_mdns_cookie_create(qvector_b, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!b, "mdns_cookie_create failed!\n");

    pico_mdns_cookie_tree_add_cookie(a);
    pico_mdns_cookie_tree_add_cookie(b);

    fail_unless(b == pico_mdns_cookie_tree_find_query_cookie("\3foo\5local"),
                "mdns_cookie_tree_find_query_cookie failed with foo.local\n");

    fail_unless(a == pico_mdns_cookie_tree_find_query_cookie("\2pi\5local"),
                "mdns_cookie_tree_find_query_cookie failed with pi.local\n");

    fail_unless(NULL == pico_mdns_cookie_tree_find_query_cookie("bla.local"),
                "mdns_cookie_tree_find_query_cookie failed with foo.local\n");

    pico_mdns_cookie_tree_del_cookie(a);
    pico_mdns_cookie_tree_del_cookie(b);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_tree_del_cookie)
{
    struct pico_mdns_cookie *a = NULL, *b = NULL;
    pico_dns_question_vector qvector_a = {0}, qvector_b = {0};
    pico_mdns_record_vector rvector = {0};
    struct pico_dns_question *question1 = NULL;
    struct pico_dns_question *question2 = NULL;
    struct pico_dns_question *question3 = NULL;
    struct pico_dns_question *question4 = NULL;
    struct pico_dns_question *question5 = NULL;
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    const char *url3 = "pi.local";
    const char *url4 = "ab.local";
    const char *url5 = "t.local";
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create some questions */
    question1 = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question1, "Could not create question 1!\n");
    question2 = pico_dns_question_create(url5, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_PTR,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 2!\n");
    question3 = pico_dns_question_create(url3, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question3, "Could not create question 3!\n");
    question4 = pico_dns_question_create(url4, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_AAAA,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question4, "Could not create question 4!\n");
    question5 = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question5, "Could not create question 5!\n");

    pico_dns_question_vector_add(&qvector_a, question3);
    pico_dns_question_vector_add(&qvector_a, question4);

    pico_dns_question_vector_add(&qvector_b, question1);
    pico_dns_question_vector_add(&qvector_b, question2);
    pico_dns_question_vector_add(&qvector_b, question5);

    a = pico_mdns_cookie_create(qvector_a, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");
    b = pico_mdns_cookie_create(qvector_b, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!b, "mdns_cookie_create failed!\n");

    pico_mdns_cookie_tree_add_cookie(a);
    pico_mdns_cookie_tree_add_cookie(b);

    fail_unless(0 == pico_mdns_cookie_tree_del_cookie(b),
                "mdns_cookie_tree_del_cookie failed deleting B!\n");

    fail_unless(NULL == pico_mdns_cookie_tree_find_query_cookie("\3foo\5local"),
                "mdns_cookie_tree_del_cookie failed deleting B correctly!\n");

    fail_unless(a == pico_mdns_cookie_tree_find_query_cookie("\2pi\5local"),
                "mdns_cookie_tree_del_cookie delete the wrong cookie!\n");

    fail_unless(0 == pico_mdns_cookie_tree_del_cookie(a),
                "mdns_cookie_tree_del_cookie failed deleting A!\n");

    fail_unless(NULL == pico_mdns_cookie_tree_find_query_cookie("\2pi\5local"),
                "mdns_cookie_tree_del_cookie failed deleting A correctly!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_tree_add_cookie)
{
    struct pico_mdns_cookie *a = NULL, *b = NULL;
    pico_dns_question_vector qvector_a = {0}, qvector_b = {0};
    pico_mdns_record_vector rvector = {0};
    struct pico_dns_question *question1 = NULL;
    struct pico_dns_question *question2 = NULL;
    struct pico_dns_question *question3 = NULL;
    struct pico_dns_question *question4 = NULL;
    struct pico_dns_question *question5 = NULL;
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    const char *url3 = "pi.local";
    const char *url4 = "ab.local";
    const char *url5 = "t.local";
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create some questions */
    question1 = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question1, "Could not create question 1!\n");
    question2 = pico_dns_question_create(url5, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_PTR,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question2, "Could not create question 2!\n");
    question3 = pico_dns_question_create(url3, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question3, "Could not create question 3!\n");
    question4 = pico_dns_question_create(url4, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_AAAA,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question4, "Could not create question 4!\n");
    question5 = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_DNS_CLASS_IN, 0);
    fail_if(!question5, "Could not create question 5!\n");

    pico_dns_question_vector_add(&qvector_a, question3);
    pico_dns_question_vector_add(&qvector_a, question4);

    pico_dns_question_vector_add(&qvector_b, question1);
    pico_dns_question_vector_add(&qvector_b, question2);
    pico_dns_question_vector_add(&qvector_b, question5);

    a = pico_mdns_cookie_create(qvector_a, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");
    b = pico_mdns_cookie_create(qvector_b, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_QUERY, NULL, NULL);
    fail_if(!b, "mdns_cookie_create failed!\n");

    pico_mdns_cookie_tree_add_cookie(a);
    pico_mdns_cookie_tree_add_cookie(b);

    fail_unless(b == pico_mdns_cookie_tree_find_query_cookie("\3foo\5local"),
                "mdns_cookie_tree_del_cookie failed adding B to tree!\n");

    fail_unless(a == pico_mdns_cookie_tree_find_query_cookie("\2pi\5local"),
                "mdns_cookie_tree_del_cookie failed adding A to tree!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_find_record)
{
    pico_mdns_record_vector rvector = {0};
    pico_dns_question_vector qvector = {0};
    struct pico_mdns_cookie *cookie = NULL;
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    printf("*********************** starting %s * \n", __func__);

    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    record2 = pico_mdns_record_create(url1, &rdata, 4, PICO_DNS_TYPE_AAAA, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Some test vectors */
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);
    pico_mdns_record_vector_add(&rvector, record2);

    cookie = pico_mdns_cookie_create(qvector, rvector, 2,
                                     PICO_MDNS_COOKIE_TYPE_PROBE,
                                     NULL, NULL);
    fail_if(!cookie, "Cookie could not be created!\n");

    fail_unless(record == pico_mdns_cookie_find_record(cookie,record->record),
                "mdns_cookie_find_record failed!\n");
    fail_unless(record1 == pico_mdns_cookie_find_record(cookie,record1->record),
                "mdns_cookie_find_record failed!\n");
    fail_unless(record2 == pico_mdns_cookie_find_record(cookie,record2->record),
                "mdns_cookie_find_record failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_apply_spt)
{
    struct pico_mdns_cookie a;
    struct pico_mdns_record record1 = {0}, record2 = {0}, record3 = {0},
    record4 = {0};
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata2 = {long_be(0xFFFFFFFF)};
    int ret = 0;
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create test records */
    record1.record = pico_dns_record_create(url1, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record1.record, "Record 1 could not be created!\n");
    record2.record = pico_dns_record_create(url2, &rdata2, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record2.record, "Record 2 could not be created!\n");
    record3.record = pico_dns_record_create(url1, &rdata2, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record3.record, "Record 3 could not be created!\n");
    record4.record = pico_dns_record_create(url2, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record4.record, "Record 4 could not be created!\n");

    /* Create 2 exactly the same cookies */
    pico_mdns_record_vector_init(&(a.rvector));
    pico_mdns_record_vector_add(&(a.rvector), &record1);
    pico_mdns_record_vector_add(&(a.rvector), &record2);

    /* Make it a probe cookie otherwise it will just return -1 */
    a.type = PICO_MDNS_COOKIE_TYPE_PROBE;

    /* Need to initialise the stack to allow timer scheduling IMPORTANT! */
    pico_stack_init();

    /* Check with peer record which is lexicographically later */
    ret = pico_mdns_cookie_apply_spt(&a, record3.record);
    fail_unless(0 == ret, "mdns_cookie_apply_spt failed!\n");

    /* Check with peer record which is lexicographically earlier */
    ret = pico_mdns_cookie_apply_spt(&a, record4.record);
    fail_unless(0 == ret, "mdns_cookie_apply_spt failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_is_suffix_present)
{
    char name1[13] = {5,'v','l','e','e','s',5,'l','o','c','a','l',0};
    char name2[17] = {9,'v','l','e','e','s',' ','(','2',')',5,'l','o','c','a','l','\0'};
    char name6[17] = {12,'v','l','e','e','s',' ','(','a',')','(','2',')',5,'l','o','c','a','l','\0'};
    char name7[18] = {10,'v','l','e','e','s',' ','(','9','a',')',5,'l','o','c','a','l','\0'};
    char *o_index = NULL;
    char *c_index = NULL;
    char suffix[5] = {0};
    char new_suffix[5] = {0};
    uint8_t present = 0;

    printf("*********************** starting %s * \n", __func__);
    present = pico_mdns_is_suffix_present(name1, &o_index, &c_index, &suffix);
    fail_unless(0 == present,
                "There is no suffix present!\n");
    fail_unless(NULL == o_index && NULL == c_index,
                "There should be no indexes!\n");
    fail_unless(strcmp(suffix, "") == 0, "The should be no suffix!\n");

    present = pico_mdns_is_suffix_present(name2, &o_index, &c_index, &suffix);
    fail_unless(1 == present,
                "is_suffix_present failed with suffix!\n");
    fail_unless((name2 + 7) == o_index && (name2 + 9) == c_index,
                "is_suffix_pressent failed!\n");
    fail_unless(strcmp(suffix, "2") == 0, "Suffix should be 2!\n");

    o_index = NULL;
    c_index = NULL;
    suffix[0] = '\0';

    present = pico_mdns_is_suffix_present(name7, &o_index, &c_index, &suffix);
    fail_unless(0 == present,
                "There is no suffix present!\n");
    fail_unless(NULL == o_index && NULL == c_index,
                "There should be no indexes!\n");
    fail_unless(strcmp(suffix, "") == 0, "The should be no suffix!\n");

    present = pico_mdns_is_suffix_present(name6, &o_index, &c_index, &suffix);
    fail_unless(1 == present,
                "is_suffix_present failed with suffix!\n");
    fail_unless((name6 + 10) == o_index && (name6 + 12) == c_index,
                "is_suffix_present failed!\n");
    fail_unless(strcmp(suffix, "2") == 0, "Suffix should be 2!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_resolve_name_conflict)
{
    char name1[13] = {5,'v','l','e','e','s',5,'l','o','c','a','l',0};
    char name2[17] = {9,'v','l','e','e','s',' ','(','2',')',5,'l','o','c','a','l','\0'};
    char name3[18] = {10,'v','l','e','e','s',' ','(','1','0',')',5,'l','o','c','a','l','\0'};
    char name4[17] = {9,'v','l','e','e','s',' ','(','9',')',5,'l','o','c','a','l','\0'};
    char name5[16] = {8,'v','l','e','e','s',' ','(',')',5,'l','o','c','a','l','\0'};
    char name6[17] = {9,'v','l','e','e','s',' ','(','a',')',5,'l','o','c','a','l','\0'};
    char name7[18] = {10,'v','l','e','e','s',' ','(','9','a',')',5,'l','o','c','a','l','\0'};
    char *ret = NULL;

    printf("*********************** starting %s * \n", __func__);

    ret = pico_mdns_resolve_name_conflict(name1);
    fail_unless(0 == strcmp(ret, "\x9vlees (2)\5local"),
                "mdns_conflict_resolve_name failed 'vlees.local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name2);
    fail_unless(0 == strcmp(ret, "\x9vlees (3)\5local"),
                "mdns_conflict_resolve_name failed 'vlees (2).local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name3);
    fail_unless(0 == strcmp(ret, "\xavlees (11)\5local"),
                "mdns_conflict_resolve_name failed 'vlees (10).local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name4);
    fail_unless(0 == strcmp(ret, "\xavlees (10)\5local"),
                "mdns_conflict_resolve_name failed 'vlees (9).local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name5);
    fail_unless(0 == strcmp(ret, "\x9vlees (2)\5local"),
                "mdns_conflict_resolve_name failed 'vlees ().local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name6);
    fail_unless(0 == strcmp(ret, "\xdvlees (a) (2)\5local"),
                "mdns_conflict_resolve_name failed 'vlees (a) (2).local' to %s!\n",
                ret);
    PICO_FREE(ret);
    ret = pico_mdns_resolve_name_conflict(name7);
    fail_unless(0 == strcmp(ret, "\xevlees (9a) (2)\5local"),
                "mdns_conflict_resolve_name failed 'vlees (9a).local' to %s!\n",
                ret);
    PICO_FREE(ret);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_generate_new_records)
{
    pico_mdns_record_vector conlfict_vector = {0};
    pico_mdns_record_vector new_vector = {0};
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");
    pico_mdns_record_vector_add(&conlfict_vector, record);

    ret = pico_mdns_generate_new_records(&conlfict_vector, "\3foo\5local",
                                         &new_vector, "\7foo (2)\5local");
    fail_unless(0 == ret, "generate_new_records failed!\n");
    fail_unless(1 == new_vector.count, "new_vector has count of 0!\n");
    fail_unless(strcmp(new_vector.records[0]->record->rname, "\7foo (2)\5local") == 0,
                "New name isn't correctly copied!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_resolve_conflict)
{
    struct pico_mdns_cookie *a = NULL;
    pico_mdns_record_vector rvector = {0};
    pico_dns_question_vector qvector = {0};
    struct pico_dns_question *question = NULL;
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    question = pico_dns_question_create(url, &len, PICO_PROTO_IPV4,
                                        PICO_DNS_TYPE_A,
                                        PICO_DNS_CLASS_IN, 0);
    fail_if(!question, "Question could not be created!\n");
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");

    /* Create 2 exactly the same cookies */
    pico_mdns_record_vector_add(&rvector, record);
    pico_dns_question_vector_add(&qvector, question);

    /* Make it a probe cookie otherwise it will just return -1 */
    a = pico_mdns_cookie_create(qvector, rvector, 1,
                                PICO_MDNS_COOKIE_TYPE_PROBE,
                                callback, NULL);

    /* Need to initialise the stack to allow timer scheduling IMPORTANT! */
    pico_stack_init();
    ret = mdns_init();
    fail_unless(0 == ret, "mdns_init failed!\n");

    /* Cookie needs to be removed from cookie tree so we need to add it first */
    pico_mdns_cookie_tree_add_cookie(a);

    ret = pico_mdns_cookie_resolve_conflict(a, "\3foo\5local");
    fail_unless(0 == ret, "mdns_cookie_resolve_conflict failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Question functions */
START_TEST(tc_mdns_question_create)
{
    struct pico_dns_question *question = NULL;
    const char *url = "1.2.3.4";
    char cmpbuf[22] = { 0x01u, '4',
                        0x01u, '3',
                        0x01u, '2',
                        0x01u, '1',
                        0x07u, 'i','n','-','a','d','d','r',
                        0x04u, 'a','r','p','a',
                        0x00u };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    question = pico_mdns_question_create("foo.local",
                                         &len,
                                         PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_MDNS_QUESTION_FLAG_UNICAST_RES,
                                         0);
    fail_if(!question, "mdns_question_create returned NULL!\n");
    fail_unless(0 == strcmp(question->qname, "\3foo\5local"),
                "mdns_question_create failed!\n");
    fail_unless(0x8001 == short_be(question->qsuffix->qclass),
                "mdns_quesiton_create failed setting QU bit!\n");
    pico_dns_question_delete(&question);

    question = pico_mdns_question_create("foo.local",
                                         &len,
                                         PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_A,
                                         PICO_MDNS_QUESTION_FLAG_PROBE,
                                         0);
    fail_if(!question, "mdns_question_create returned NULL!\n");
    fail_unless(0 == strcmp(question->qname, "\3foo\5local"),
                "mdns_question_create failed!\n");
    fail_unless(PICO_DNS_TYPE_ANY == short_be(question->qsuffix->qtype),
                "mdns_quesiton_create failed setting type to ANY!\n");
    pico_dns_question_delete(&question);

    question = pico_mdns_question_create(url,
                                         &len,
                                         PICO_PROTO_IPV4,
                                         PICO_DNS_TYPE_PTR,
                                         0, 1);
    fail_if(!question, "mdns_question_create returned NULL!\n");
    fail_unless(0 == strcmp(question->qname, cmpbuf),
                "mdns_question_create failed!\n");
    pico_dns_question_delete(&question);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Record functions */
START_TEST(tc_mdns_dns_record_create)
{
    struct pico_dns_record *a = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);
    a = pico_mdns_dns_record_create(url,
                                    (void *)rdata, 4,
                                    &len,
                                    PICO_DNS_TYPE_A,
                                    120,
                                    PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "mdns_dns_record_create returned NULL!\n");
    fail_unless(strcmp(a->rname, "\x7picotcp\x3com"),
                "mdns_dns_record_create didn't convert url %s properly!\n",
                a->rname);
    fail_unless(a->rsuffix->rtype == short_be(PICO_DNS_TYPE_A),
                "mdns_dns_record_create failed setting rtype!\n");
    fail_unless(0x8001 == short_be(a->rsuffix->rclass),
                "mdns_dns_record_create failed setting rclass!\n");
    fail_unless(a->rsuffix->rttl == long_be(120),
                "mdns_dns_record_create failed setting rttl!\n");
    fail_unless(a->rsuffix->rdlength == short_be(4),
                "mdns_dns_record_create failed setting rdlenth!\n");
    fail_unless(memcmp(a->rdata, rdata, 4) == 0,
                "mdns_dns_record_create failed setting rdata!\n");

    pico_dns_record_delete(&a);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_resolve_conflict)
{
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");
    /* Need to initialise the stack to allow timer scheduling IMPORTANT! */
    pico_stack_init();

    ret = mdns_init();
    fail_unless(0 == ret, "mdns_init failed!\n");

    ret = pico_mdns_record_resolve_conflict(record, "\3foo\5local");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_am_i_lexi_later)
{
    struct pico_mdns_record record1 = {0}, record2 = {0}, record3 = {0},
    record4 = {0};
    const char *url1 = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata2 = {long_be(0xFFFFFFFF)};
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create test records */
    record1.record = pico_dns_record_create(url1, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record1.record, "Record 1 could not be created!\n");
    record2.record = pico_dns_record_create(url2, &rdata2, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record2.record, "Record 2 could not be created!\n");
    record3.record = pico_dns_record_create(url1, &rdata2, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record3.record, "Record 3 could not be created!\n");
    record4.record = pico_dns_record_create(url2, &rdata, 4, &len,
                                            PICO_DNS_TYPE_A,
                                            PICO_DNS_CLASS_IN, 0);
    fail_if(!record4.record, "Record 4 could not be created!\n");

    ret = pico_mdns_record_am_i_lexi_later(&record1, &record3);
    fail_if(-2 == ret, "mdns_record_am_i_lexi_later return error!\n");
    fail_unless(-1 == ret, "mdns_record_am_i_lexi_later failed!\n");

    ret = pico_mdns_record_am_i_lexi_later(&record2, &record4);
    fail_if(-2 == ret, "mdns_record_am_i_lexi_later return error!\n");
    fail_unless(1 == ret, "mdns_record_am_i_lexi_later failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_create_from_dns)
{
    struct pico_mdns_record *record = NULL;
    struct pico_dns_record *a = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);
    a = pico_mdns_dns_record_create(url,
                                    (void *)rdata, 4,
                                    &len,
                                    PICO_DNS_TYPE_A,
                                    120,
                                    PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "mdns_dns_record_create returned NULL!\n");

    /* Try to create an mDNS record from a DNS record */
    record = pico_mdns_record_create_from_dns(a);
    fail_if(!record, "mdns_record_create_from_dns returned NULL!\n");
    fail_unless(strcmp(record->record->rname, "\x7picotcp\x3com"),
                "mdns_record_create_from_dns failed!\n");
    fail_unless(record->record->rsuffix->rtype == short_be(PICO_DNS_TYPE_A),
                "mdns_record_create_from_dns failed setting rtype!\n");
    fail_unless(0x8001 == short_be(record->record->rsuffix->rclass),
                "mdns_record_create_from_dns failed setting rclass!\n");
    fail_unless(record->record->rsuffix->rttl == long_be(120),
                "mdns_record_create_from_dns failed setting rttl!\n");
    fail_unless(record->record->rsuffix->rdlength == short_be(4),
                "mdns_record_create_from_dns failed setting rdlenth!\n");
    fail_unless(memcmp(record->record->rdata, rdata, 4) == 0,
                "mdns_record_create_from_dns failed setting rdata!\n");

    pico_mdns_record_delete(&record);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_copy_with_new_name)
{
    struct pico_mdns_record *record = NULL, *copy = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");

    /* Try to create a copy with a new name */
    copy = pico_mdns_record_copy_with_new_name(record, "\4test\5local");
    fail_if(!copy, "mdns_record_copy_with_new_name returned NULL!\n");
    fail_unless(0 == strcmp(copy->record->rname, "\4test\5local"),
                "mdns_record_copy_with_new_name didn't copy name right!\n");
    fail_unless(strlen("\4test\5local") + 1 == copy->record->rname_length,
                "mdns_record_copy_with_new_name didn't update namelength!\n");

    pico_mdns_record_delete(&record);
    pico_mdns_record_delete(&copy);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_copy)
{
    struct pico_mdns_record *record = NULL, *copy = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");

    /* Try to copy */
    copy = pico_mdns_record_copy(record);
    fail_if(!copy, "mdns_record_copy returned NULL!\n");
    fail_if(record == copy, "Pointers point to same struct!\n");
    fail_unless(0 == strcmp(copy->record->rname, record->record->rname),
                "mdns_record_copy didn't copy names right!\n");
    fail_unless(copy->claim_id == record->claim_id,
                "mdns_record_copy didn't copy claim_id right!\n");
    fail_unless(copy->current_ttl == record->current_ttl,
                "mdns_record_copy didn't copy current_ttl right!\n");
    fail_unless(copy->flags == record->flags,
                "mdns_record_copy didn't copy flags right!\n");

    pico_mdns_record_delete(&record);
    pico_mdns_record_delete(&copy);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_create)
{
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");
    fail_unless(0 == strcmp(record->record->rname, "\3foo\5local"),
                "mdns_record_create didn't convert rname properly!\n");
    fail_unless(0x8001 == short_be(record->record->rsuffix->rclass),
                "mdns_record_create didn't set QU flag correctly!\n");
    pico_mdns_record_delete(&record);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_delete)
{
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");

    /* Try to delete the record */
    ret = pico_mdns_record_delete(&record);
    fail_unless(0 == ret, "mdns_record_delete returned error!\n");
    fail_unless(!record, "mdns_record_delete didn't delete properly");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Record Vector Functions */
START_TEST(tc_mdns_record_vector_init)
{
    pico_mdns_record_vector rvector;

    printf("*********************** starting %s * \n", __func__);
    rvector.count = 243;
    rvector.records = (struct pico_mdns_record **)5;

    /* Try to init the vector */
    pico_mdns_record_vector_init(&rvector);

    fail_unless(0 == rvector.count && NULL == rvector.records,
                "mdns_record_vector_init failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_count)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    fail_unless(0 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_add(&rvector, record);
    fail_unless(1 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_add(&rvector, record1);
    fail_unless(2 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_delete(&rvector, 0);
    fail_unless(1 == pico_mdns_record_vector_count(&rvector));

    pico_mdns_record_vector_destroy(&rvector);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_add)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url2, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    fail_unless(0 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_add(&rvector, record);
    fail_unless(1 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_add(&rvector, record1);
    fail_unless(2 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_delete(&rvector, 0);
    fail_unless(1 == pico_mdns_record_vector_count(&rvector));

    pico_mdns_record_vector_destroy(&rvector);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_get)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL, *ret = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    fail_unless(0 == pico_mdns_record_vector_count(&rvector));
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);
    ret = pico_mdns_record_vector_get(&rvector, 0);
    fail_unless(ret == record, "mdns_record_vector_get failed!\n");
    ret = pico_mdns_record_vector_get(&rvector, 1);
    fail_unless(ret == record1, "mdns_record_vector_get failed!\n");
    ret = pico_mdns_record_vector_get(&rvector, 2);
    fail_unless(NULL == ret, "mdns_record_vector_get failed OOB!\n");

    pico_mdns_record_vector_destroy(&rvector);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_delete)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);
    ret = pico_mdns_record_vector_delete(&rvector, 0);
    fail_unless(0 == ret, "mdns_record_vector_delete failed!\n");
    ret = pico_mdns_record_vector_delete(&rvector, 1);
    fail_unless(0 == ret, "mdns_record_vector_delete failed OOB!\n");
    ret = pico_mdns_record_vector_delete(&rvector, 0);
    fail_unless(0 == ret, "mdns_record_vector_delete failed!\n");
    ret = pico_mdns_record_vector_delete(&rvector, 2);
    fail_unless(0 == ret, "mdns_record_vector_delete failed OOB!\n");
    fail_unless(0 ==  pico_mdns_record_vector_count(&rvector),
                "mdns_record_vector_delete failed!\n");

    pico_mdns_record_vector_destroy(&rvector);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_destroy)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);

    /* Try to destroy the vector */
    pico_mdns_record_vector_destroy(&rvector);
    fail_unless(NULL == rvector.records,
                "Records not NULL!\n");
    fail_unless(0 == pico_mdns_record_vector_count(&rvector),
                "mdns_record_vector_delete failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_vector_append)
{
    pico_mdns_record_vector rvector = {0}, rvector_b = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some test vectors */
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector_b, record1);

    ret = pico_mdns_record_vector_append(&rvector, &rvector_b);
    fail_unless(0 == ret, "pico_mdns_record_vector_append returned NULL");
    fail_unless(0 == pico_mdns_record_vector_count(&rvector_b),
                "pico_mdns_record_vector_append didn't remove vector B!\n");
    fail_unless(record1 == pico_mdns_record_vector_get(&rvector, 1),
                "pico_mdns_record_vector_append failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Record tree functions */
void add_records( void )
{
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Simulate that this record is probed */
    record1->flags |= PICO_MDNS_RECORD_PROBED;

    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);
}
START_TEST(tc_mdns_record_tree_find_url)
{
    pico_mdns_record_vector hits = {0};
    int found = 1, i = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_record_tree_find_url("foo.local", &MyRecords);
    fail_unless(3 == hits.count,
                "mdns_record_tree_find_url should find 3 records here!\n");
    for (i = 0; i < hits.count; i++) {
        if (strcmp(pico_mdns_record_vector_get(&hits,
                                               (uint16_t)i)->record->rname,
                   "\3foo\5local"))
            found = 0;
    }
    fail_unless(1 == found,
                "mdns_record_tree_find_url returned records with other name!\n");

    hits = pico_mdns_record_tree_find_url("bar.local", &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_find_url should find 1 record here!\n");
    fail_unless(0 == strcmp(pico_mdns_record_vector_get(&hits,
                                                        0)->record->rname,
                            "\3bar\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_find_url_type)
{
    pico_mdns_record_vector hits = {0};
    int found = 1, i = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    /* Try to find the first A record */
    hits = pico_mdns_record_tree_find_url_type("foo.local", PICO_DNS_TYPE_A,
                                               &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_find_url should find 1 record here!\n");
    fail_unless(0 == strcmp(pico_mdns_record_vector_get(&hits,
                                                        0)->record->rname,
                            "\3foo\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    /* Try to find the 2 PTR records */
    hits = pico_mdns_record_tree_find_url_type("foo.local", PICO_DNS_TYPE_PTR,
                                               &MyRecords);
    for (i = 0; i < hits.count; i++) {
        if (strcmp(pico_mdns_record_vector_get(&hits,
                                               (uint16_t)i)->record->rname,
                   "\3foo\5local"))
            found = 0;
    }
    fail_unless(1 == found,
            "mdns_record_tree_find_url returned records with other name!\n");

    /* Try to find the last A record */
    hits = pico_mdns_record_tree_find_url_type("bar.local", PICO_DNS_TYPE_A,
                                               &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_find_url should find 1 record here!\n");
    fail_unless(0 == strcmp(pico_mdns_record_vector_get(&hits,
                                                        0)->record->rname,
                            "\3bar\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_find_record)
{
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);

    /* Try to find the first A record */
    node_record = pico_mdns_record_tree_find_record(record2, &MyRecords);
    fail_unless(record2 == node_record,
                "mdns_record_tree_find_record failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_del_url)
{
    pico_mdns_record_vector hits = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);

    /* Try to del the first tree records */
    ret = pico_mdns_record_tree_del_url(url, &MyRecords);
    fail_unless(0 == ret,
                "mdns_record_tree_del_url failed!\n");
    hits = pico_mdns_record_tree_find_url(url, &MyRecords);
    fail_unless(0 == hits.count,
                "mdns_record_tree_find_url should find 3 records here!\n");

    hits = pico_mdns_record_tree_find_url(url1, &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_find_url should find 1 record here!\n");
    fail_unless(0 == strcmp(pico_mdns_record_vector_get(&hits,
                                                        0)->record->rname,
                            "\3bar\5local"),
                "mdns_record_tree_del_url failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_del_url_type)
{
    pico_mdns_record_vector hits = {0};
    const char *url = "foo.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    /* Try to del the two PTR records */
    ret = pico_mdns_record_tree_del_url_type(url, PICO_DNS_TYPE_PTR,
                                             &MyRecords);
    fail_unless(0 == ret, "mdns_record_tree_del_url_type returned error!\n");

    /* Try to find the 2 PTR records */
    hits = pico_mdns_record_tree_find_url_type(url, PICO_DNS_TYPE_PTR,
                                               &MyRecords);
    fail_unless(0 == hits.count,
                "mdns_record_tree_find_url_type returned PTR records!\n");


    /* Try to find the first A record */
    hits = pico_mdns_record_tree_find_url_type(url, PICO_DNS_TYPE_A,
                                               &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_del_url_type failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_del_record)
{
    struct pico_mdns_record *node_record = NULL;
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4,
                                      PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);

    /* Try to find the first A record */
    ret = pico_mdns_record_tree_del_record(record2, &MyRecords);
    fail_unless(0 == ret,
                "mdns_record_tree_del_record returned NULL!\n");
    node_record = pico_mdns_record_tree_find_record(record2, &MyRecords);
    fail_unless(NULL == node_record,
                "mdns_record_tree_del_record failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_add_record)
{
    pico_mdns_record_vector hits = {0};
    int found = 1, i = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_record_tree_find_url("foo.local", &MyRecords);
    fail_unless(3 == hits.count,
                "mdns_record_tree_find_url should find 3 records here!\n");
    for (i = 0; i < hits.count; i++) {
        if (strcmp(pico_mdns_record_vector_get(&hits,
                                               (uint16_t)i)->record->rname,
                   "\3foo\5local"))
            found = 0;
    }
    fail_unless(1 == found,
                "mdns_record_tree_find_url returned records with other name!\n");

    hits = pico_mdns_record_tree_find_url("bar.local", &MyRecords);
    fail_unless(1 == hits.count,
                "mdns_record_tree_find_url should find 1 record here!\n");
    fail_unless(0 == strcmp(pico_mdns_record_vector_get(&hits,
                                                        0)->record->rname,
                            "\3bar\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: My records functions */
START_TEST(tc_mdns_my_records_find_url_type)
{
    struct pico_mdns_record *hit = NULL;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    /* Try to find the first A record */
    hit = pico_mdns_my_records_find_url_type("foo.local", PICO_DNS_TYPE_A);
    fail_unless(0 == strcmp(hit->record->rname, "\3foo\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    /* Try to find the first PTR records */
    hit = pico_mdns_my_records_find_url_type("foo.local", PICO_DNS_TYPE_PTR);
    fail_unless(0 == strcmp(hit->record->rname, "\3foo\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    /* Try to find the last A record */
    hit = pico_mdns_my_records_find_url_type("bar.local", PICO_DNS_TYPE_A);
    fail_unless(0 == strcmp(hit->record->rname, "\3bar\5local"),
                "mdns_record_tree_find_url returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_add)
{
    pico_mdns_record_vector vector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    printf("*********************** starting %s * \n", __func__);
    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Simulate that this record is not added again */
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_vector_add(&vector, record);
    pico_mdns_record_vector_add(&vector, record1);
    pico_mdns_record_vector_add(&vector, record2);
    pico_mdns_record_vector_add(&vector, record3);

    vector = pico_mdns_my_records_add(vector, 0);
    fail_unless(3 == vector.count, "mdns_my_records_add failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_find_probed)
{
    pico_mdns_record_vector hits = {0};

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_my_records_find_probed();
    fail_unless(1 == hits.count,
                "mdns_my_records_find_probed failed!\n");


    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_find_to_probe)
{
    pico_mdns_record_vector hits = {0};

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_my_records_find_to_probe();
    fail_unless(3 == hits.count,
                "mdns_my_records_find_to_probe failed! %d\n", hits.count);


    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_claimed_id)
{
    pico_mdns_record_vector hits = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    printf("*********************** starting %s * \n", __func__);
    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    record->claim_id = 1;
    record->flags |= PICO_MDNS_RECORD_CLAIMED;
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    record1->claim_id = 1;
    record1->flags |= PICO_MDNS_RECORD_CLAIMED;
    fail_if(!record1, "Record could not be created!\n");

    /* Simulate that this record is not added again */
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);

    fail_unless(1 == pico_mdns_my_records_claimed_id(1, &hits),
                "mdns_my_records_claimed_id_failed!\n");
    fail_unless(2 == hits.count,
                "Vector count should be 2!\n");

    fail_unless(0 == pico_mdns_my_records_claimed_id(0, &hits),
                "Claim ID '0' isn't claimed yet..");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_claimed)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");
    record2 = pico_mdns_record_create(url, url1, strlen(url1),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Create a totally different record */
    record3 = pico_mdns_record_create(url1, &rdata1, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "Record could not be created!\n");

    /* Add the records to the tree */
    pico_mdns_record_tree_add_record(record, &MyRecords);
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);
    pico_mdns_record_tree_add_record(record3, &MyRecords);

    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);
    pico_mdns_record_vector_add(&rvector, record2);
    pico_mdns_record_vector_add(&rvector, record3);

    ret = pico_mdns_my_records_claimed(rvector, callback, NULL);
    fail_unless(0 == ret, "mdns_my_records_claimed failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Query functions */
START_TEST(tc_mdns_query_create)
{
    pico_dns_packet *packet = NULL;
    pico_dns_question_vector qvector = { 0 };
    const char *qurl = "picotcp.com";
    const char *qurl2 = "google.com";
    uint8_t buf[42] = { 0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x07u, 'p','i','c','o','t','c','p',
        0x03u, 'c','o','m',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x06u, 'g','o','o','g','l','e',
        0xc0u, 0x14u,
        0x00u, 0x01u,
        0x00u, 0x01u };
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = NULL, *b = NULL;

    printf("*********************** starting %s * \n", __func__);

    a = pico_dns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    b = pico_dns_question_create(qurl2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, b);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");

    packet = pico_dns_query_create(&qvector, NULL, NULL, NULL, &len);
    fail_if(packet == NULL, "mdns_query_create returned NULL!\n");
    fail_unless(0 == memcmp(buf, (void *)packet, 42),
                "mdns_query_create failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Answer functions*/
START_TEST(tc_mdns_answer_create)
{
    pico_dns_packet *packet = NULL;
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;
    int ret = 0;
    uint8_t buf[62] = { 0x00u, 0x00u,
        0x84u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x07u, 'p','i','c','o','t','c','p',
        0x03u, 'c','o','m',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x78u,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x00u, 0x01u,
        0x06u, 'g','o','o','g','l','e',
        0xc0u, 0x14u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x78u,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x00u, 0x01u};

    printf("*********************** starting %s * \n", __func__);

    a = pico_dns_record_create(url, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_dns_record_create(url2, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    /* Try to create an answer packet */
    packet = pico_mdns_answer_create(&rvector, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");
    fail_unless(memcmp((void *)packet, (void *)buf, 62) == 0,
                "mdns_answer_create failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Cache functions */
START_TEST(tc_mdns_cache_add_record)
{
    struct pico_mdns_record *record = NULL, *found = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    const char *url = "foo.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 80,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    ret = pico_mdns_cache_add_record(record);
    fail_unless(0 == ret,
                "mdns_cache_add_record returned error!\n");
    found = pico_mdns_record_tree_find_record(record, &Cache);
    fail_unless((int)found, "mdns_cache_add_record failed!\n");
    ret = pico_mdns_cache_add_record(record);
    fail_unless(1 == ret,
                "mdns_cache_add_record returned error!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cache_flush)
{
    struct pico_mdns_record *record = NULL, *found = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    const char *url = "foo.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 80,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    ret = pico_mdns_cache_add_record(record);
    fail_unless(0 == ret,
                "mdns_cache_add_record returned error!\n");
    ret = pico_mdns_flush_cache();
    fail_unless(0 == ret,
                "mdns_cache_flush returned error!\n");
    found = pico_mdns_record_tree_find_record(record, &Cache);
    fail_unless(!found, "mdns_cache_flush failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_populate_answer_vector)
{
    pico_mdns_record_vector vector = {0};

    printf("*********************** starting %s * \n", __func__);
    add_records();

    vector = pico_mdns_populate_answer_vector("foo.local",
                                              PICO_DNS_TYPE_A,
                                              PICO_DNS_CLASS_IN);

    fail_unless(1 == vector.count, "mdns_populate_answer_vector failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Handling receptions */
START_TEST(tc_mdns_handle_data_as_questions)
{
    pico_dns_packet *packet = NULL;
    pico_mdns_record_vector anvector = { 0 };
    pico_dns_question_vector qvector = { 0 };
    const char *qurl = "picotcp.com";
    const char *qurl2 = "google.com";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    uint16_t len = 0;
    uint8_t *ptr = NULL;
    int ret = 0;
    struct pico_dns_question *a = NULL, *b = NULL;
    struct pico_mdns_record *record1 = NULL, *record2 = NULL;

    printf("*********************** starting %s * \n", __func__);

    /* Create a DNS query packet */
    a = pico_mdns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                  PICO_MDNS_QUESTION_FLAG_UNICAST_RES, 0);
    fail_if(!a, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    b = pico_mdns_question_create(qurl2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                  0, 0);
    fail_if(!b, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, b);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    packet = pico_dns_query_create(&qvector, NULL, NULL, NULL, &len);
    fail_if(packet == NULL, "mdns_query_create returned NULL!\n");

    /* Create records for answers */
    record1 = pico_mdns_record_create(qurl, &rdata, 4, PICO_DNS_TYPE_A, 120,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "mdns_record_create returned NULL!\n");
    record1->flags |= 0xC0;
    record2 = pico_mdns_record_create(qurl2, &rdata1, 4, PICO_DNS_TYPE_A, 120,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record2, "mdns_record_created returned NULL!\n");
    record2->flags |= 0xC0;

    /* Add them to my records */
    pico_mdns_record_tree_add_record(record1, &MyRecords);
    pico_mdns_record_tree_add_record(record2, &MyRecords);

    ptr = ((uint8_t *)packet + 12);

    anvector = pico_mdns_handle_data_as_questions(&ptr, 2, packet);
    fail_unless(2 == anvector.count,
                "pico_mdns_handle_data_as_questions returned error!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_answers)
{
    pico_dns_packet *packet = NULL;
    pico_dns_record_vector rvector = { 0 };
    struct pico_mdns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint8_t *ptr = NULL;;
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_record_create(url, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_mdns_record_create(url2, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_SHARED);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    /* Try to create an answer packet */
    packet = pico_mdns_answer_create(&rvector, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

    ret = pico_mdns_handle_data_as_answers(&ptr, 2, packet);
    fail_unless(0 == ret, "mdns_handle_data_as_answers failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_authorities)
{
    pico_dns_packet *packet = NULL;
    pico_dns_record_vector rvector = { 0 };
    struct pico_mdns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint16_t len = 0;
    uint8_t *ptr = NULL;
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_record_create(url, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_mdns_record_create(url2, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_SHARED);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    /* Try to create an answer packet */
    packet = pico_mdns_answer_create(&rvector, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

    ret = pico_mdns_handle_data_as_authorities(&ptr, 2, packet);
    fail_unless(0 == ret, "mdns_handle_data_as_answers failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_additionals)
{
    printf("*********************** starting %s * \n", __func__);
    /* Insert code here... */
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_sort_unicast_multicast)
{
    pico_mdns_record_vector rvector = { 0 };
    pico_dns_record_vector u_vector = {0}, m_vector = {0};
    struct pico_mdns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint16_t len = 0;
    uint8_t *ptr = NULL;
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_record_create(url, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "mdns_record_create returned NULL!\n");
    b = pico_mdns_record_create(url2, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                (PICO_MDNS_RECORD_SHARED | PICO_MDNS_RECORD_SEND_UNICAST));
    fail_if(!a, "mdns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "mdns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b);
    fail_unless(ret == 0, "mdns_record_vector_add returned error!\n");

    ret = pico_mdns_sort_unicast_multicast(&rvector, &u_vector, &m_vector);
    fail_unless(0 == ret, "mdns_sort_unicast_multicast returned error!\n");
    fail_unless(1 == u_vector.count, "mdns_sort_unicast_multicast failed!\n");
    fail_unless(1 == m_vector.count, "mdns_sort_unicast_multicast failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_apply_known_answer_suppression)
{
    pico_dns_packet *packet = NULL;
    pico_dns_record_vector rvector = { 0 };
    pico_mdns_record_vector vector = {0};
    struct pico_mdns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint8_t *ptr = NULL;;
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_record_create(url, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_UNIQUE);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_mdns_record_create(url2, (void *)rdata, 4, PICO_DNS_TYPE_A, 120,
                                PICO_MDNS_RECORD_SHARED);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b->record);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_mdns_record_vector_add(&vector, a);
    fail_unless(ret == 0, "mdns_record_vector_add returned error!\n");
    ret = pico_mdns_record_vector_add(&vector, b);
    fail_unless(ret == 0, "mdns_record_vector_add returned error!\n");

    /* Try to create an answer packet */
    packet = pico_mdns_answer_create(&rvector, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

    ret = pico_mdns_apply_known_answer_suppression(&vector, packet, 1, &ptr);
    fail_unless(0 == ret, "mdns_apply_known_answer_suppression returned error!\n");

    fail_unless(1 == vector.count,
                "mdns_apply_known_answer_suppression failed %d!\n", rvector.count);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Address resolving functions */
START_TEST(tc_mdns_send_query_packet)
{
    struct pico_mdns_cookie cookie;

    printf("*********************** starting %s * \n", __func__);

    cookie.count = 2;

    pico_stack_init();
    mdns_init();

    pico_mdns_send_query_packet(0, &cookie);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_getrecord)
{
    struct pico_mdns_record *record = NULL, *found = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    const char *url = "foo.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 80,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");

    ret = pico_mdns_cache_add_record(record);
    fail_unless(0 == ret,
                "mdns_cache_add_record returned error!\n");
    found = pico_mdns_record_tree_find_record(record, &Cache);
    fail_unless((int)found, "mdns_cache_add_record failed!\n");
    ret = pico_mdns_cache_add_record(record);
    fail_unless(1 == ret,
                "mdns_cache_add_record returned error!\n");

    /* Init */
    pico_stack_init();
    mdns_init();

    ret = pico_mdns_getrecord("foo.local", PICO_DNS_TYPE_A, callback, NULL);
    fail_unless(0 == ret, "mdns_getrecord failed!\n");

    ret = pico_mdns_getrecord("bar.local", PICO_DNS_TYPE_A, callback, NULL);
    fail_unless(0 == ret, "mdns_getrecord failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Probe & Announcement functions */
START_TEST(tc_mdns_send_announcement_packet)
{
    struct pico_mdns_cookie *cookie = NULL;
    pico_dns_question_vector qvector = {0};
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url2, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    cookie = pico_mdns_cookie_create(qvector, rvector, 2,
                                     PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT,
                                     callback, NULL);

    pico_stack_init();
    mdns_init();

    pico_mdns_send_announcement_packet(0, cookie);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_announce)
{
    printf("*********************** starting %s * \n", __func__);
    add_records();
    pico_stack_init();
    mdns_init();

    fail_unless(0 == pico_mdns_announce(callback, NULL),
                "mdns_announce failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_send_probe_packet)
{
    struct pico_mdns_cookie *cookie = NULL;
    pico_dns_question_vector qvector = {0};
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url2, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    cookie = pico_mdns_cookie_create(qvector, rvector, 2,
                                     PICO_MDNS_COOKIE_TYPE_ANNOUNCEMENT,
                                     callback, NULL);

    pico_stack_init();
    mdns_init();

    pico_mdns_send_probe_packet(0, cookie);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_add_probe_question)
{
    pico_dns_question_vector vector = {0};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    ret = pico_mdns_add_probe_question(&vector, "\5vlees\5local");
    fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
    fail_unless(1 == vector.count,
                "New probe question didn't create!\n");
    ret = pico_mdns_add_probe_question(&vector, "\5vlees\5local");
    fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
    fail_unless(1 == vector.count,
                "mdns_add_probe_question failed!\n");

    ret = pico_mdns_add_probe_question(&vector, "\4test\5local");
    fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
    fail_unless(2 == vector.count,
                "mdns_add_probe_question failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_probe)
{
    printf("*********************** starting %s * \n", __func__);
    add_records();
    pico_stack_init();
    mdns_init();

    fail_unless(0 == pico_mdns_probe(callback, NULL),
                "mdns_announce failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* MARK: Claiming functions */
START_TEST(tc_mdns_claim)
{
    pico_mdns_record_vector rvector = {0};
    struct pico_mdns_record *record = NULL, *record1 = NULL;
    const char *url = "foo.local";
    const char *url2 = "bar.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    /* Create a record */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record, "Record could not be created!\n");
    record1 = pico_mdns_record_create(url2, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    fail_if(!record1, "Record could not be created!\n");

    /* Some tests */
    pico_mdns_record_vector_add(&rvector, record);
    pico_mdns_record_vector_add(&rvector, record1);

    pico_stack_init();
    mdns_init();

    ret = pico_mdns_claim(rvector, callback, NULL);
    fail_unless(0 == ret, "mdns_claimed failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
/* API functions */
START_TEST(tc_mdns_set_hostname)
{
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    pico_stack_init();
    mdns_init();

    ret = pico_mdns_set_hostname("test.local", NULL);
    fail_unless(0 == ret, "mdns_set_hostname failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_get_hostname)
{
    char *_hostname = NULL;

    printf("*********************** starting %s * \n", __func__);
    pico_stack_init();
    mdns_init();

    _hostname = pico_mdns_get_hostname();
    fail_unless(0 == strcmp(_hostname, "host.local"),
                "mdns_get_hostname failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_mdns_init = tcase_create("Unit test for mdns_init");

    /* Comparing functions */
    TCase *TCase_mdns_rdata_cmp = tcase_create("Unit test for mdns_rdata_cmp");
    TCase *TCase_mdns_cmp = tcase_create("Unit test for mdns_cmp");
    TCase *TCase_mdns_cmp_name_type = tcase_create("Unit test for mdns_cmp_name_type");
    TCase *TCase_mdns_cookie_cmp = tcase_create("Unit test for mdns_cookie_cmp");

    /* Cookie functions */
    TCase *TCase_mdns_cookie_delete = tcase_create("Unit test for mdns_cookie_delete");
    TCase *TCase_mdns_cookie_create = tcase_create("Unit test for mdns_cookie_create");
    TCase *TCase_mdns_cookie_tree_find_query_cookie = tcase_create("Unit test for mdns_cookie_tree_find_query_cookie");
    TCase *TCase_mdns_cookie_tree_del_cookie = tcase_create("Unit test for mdns_cookie_tree_del_cookie");
    TCase *TCase_mdns_cookie_tree_add_cookie = tcase_create("Unit test for mdns_cookie_tree_add_cookie");
    TCase *TCase_mdns_cookie_find_record = tcase_create("Unit test for mdns_cookie_find_record");
    TCase *TCase_mdns_cookie_apply_spt = tcase_create("Unit test for mdns_cookie_apply_spt");
    TCase *TCase_mdns_is_suffix_present = tcase_create("Unit test for mdns_is_suffix_present");
    TCase *TCase_mdns_resolve_name_conflict = tcase_create("Unit test for mdns_resolve_name_conflict");
    TCase *TCase_mdns_generate_new_records = tcase_create("Unit test for mdns_generate_new_records");
    TCase *TCase_mdns_cookie_resolve_conflict = tcase_create("Unit test for mdns_cookie_resolve_conflict");

    /* Question functions */
    TCase *TCase_mdns_question_create = tcase_create("Unit test for mdns_question_create");

    /* Record functions */
    TCase *TCase_mdns_dns_record_create = tcase_create("Unit test for mdns_dns_record_create");
    TCase *TCase_mdns_record_resolve_conflict = tcase_create("Unit test for mdns_record_resolve_conflict");
    TCase *TCase_mdns_record_am_i_lexi_later = tcase_create("Unit test for mdns_record_am_i_lexi_later");
    TCase *TCase_mdns_record_create_from_dns = tcase_create("Unit test for mdns_recod_create_from_dns");
    TCase *TCase_mdns_record_copy_with_new_name = tcase_create("Unit test for mdns_record_copy");
    TCase *TCase_mdns_record_copy = tcase_create("Unit test for mdns_record_copy");
    TCase *TCase_mdns_record_create = tcase_create("Unit test for mdns_record_create");
    TCase *TCase_mdns_record_delete = tcase_create("Unit test for mdns_record_delete");

    /* Record vector functions */
    TCase *TCase_mdns_record_vector_init = tcase_create("Unit test for mdns_record_vector_init");
    TCase *TCase_mdns_record_vector_count = tcase_create("Unit test for mdns_record_vector_count");
    TCase *TCase_mdns_record_vector_add = tcase_create("Unit test for mdns_record_vector_add");
    TCase *TCase_mdns_record_vector_get = tcase_create("Unit test for mdns_record_vector_get");
    TCase *TCase_mdns_record_vector_delete = tcase_create("Unit test for mdns_record_vector_delete");
    TCase *TCase_mdns_record_vector_destroy = tcase_create("Unit test for mdns_record_vector_destroy");
    TCase *TCase_mdns_record_vector_append = tcase_create("Unit test for mdns_record_vector_append");

    /* Record tree functions */
    TCase *TCase_mdns_record_tree_find_url = tcase_create("Unit test for mdns_record_tree_find_url");
    TCase *TCase_mdns_record_tree_find_url_type = tcase_create("Unit test for mdns_record_tree_find_url_type");
    TCase *TCase_mdns_record_tree_find_record = tcase_create("Unit test for mdns_record_tree_find_record");
    TCase *TCase_mdns_record_tree_del_url = tcase_create("Unit test for mdns_record_tree_del_url");
    TCase *TCase_mdns_record_tree_del_url_type = tcase_create("Unit test for mdns_record_tree_del_url_type");
    TCase *TCase_mdns_record_tree_del_record = tcase_create("Unit test for mdns_record_tree_del_record");
    TCase *TCase_mdns_record_tree_add_record = tcase_create("Unit test for mdns_record_tree_add_record");

    /* My record functions */
    TCase *TCase_mdns_my_records_find_url_type = tcase_create("Unit test for mdns_my_records_find_url_type");
    TCase *TCase_mdns_my_records_add = tcase_create("Unit test for mdns_my_records_add");
    TCase *TCase_mdns_my_records_find_probed = tcase_create("Unit test for mdns_my_records_find_probed");
    TCase *TCase_mdns_my_records_find_to_probe = tcase_create("Unit test for mdns_my_records_find_to_probe");
    TCase *TCase_mdns_my_records_claimed_id = tcase_create("Unit test for mdns_my_records_claimed_id");
    TCase *TCase_mdns_my_records_claimed = tcase_create("Unit test for mdns_my_records_claimed");

    /* Query functions */
    TCase *TCase_mdns_query_create = tcase_create("Unit test for mdns_query_create");

    /* Answer functions */
    TCase *TCase_mdns_answer_create = tcase_create("Unit test for mdns_answer_create");

    /* Cache functions */
    TCase *TCase_mdns_cache_add_record = tcase_create("Unit test for mdns_cache_add_record");
    TCase *TCase_mdns_cache_flush = tcase_create("Unit test for mdns_cache_flush");
    TCase *TCase_mdns_populate_answer_vector = tcase_create("Unit test for mdns_populate_answer_vector");

    /* Handling receptions */
    TCase *TCase_mdns_handle_data_as_questions = tcase_create("Unit test for mdns_handle_data_as_questions");
    TCase *TCase_mdns_handle_data_as_answers = tcase_create("Unit test for mdns_handle_data_as_answers");
    TCase *TCase_mdns_handle_data_as_authorities = tcase_create("Unit test for mdns_handle_data_as_authorities");
    TCase *TCase_mdns_handle_data_as_additionals = tcase_create("Unit test for mdns_handle_data_as_additionals");

    /* Handling query packets */
    TCase *TCase_mdns_sort_unicast_multicast = tcase_create("Unit test for mdns_sort_unicast_multicast");
    TCase *TCase_mdns_apply_known_answer_suppression = tcase_create("Unit test for mdns_apply_known_answer_suppression");

    /* Address resolving functions */
    TCase *TCase_mdns_send_query_packet = tcase_create("Unit test for mdns_send_query_packet");
    TCase *TCase_mdns_getrecord = tcase_create("Unit test for mdns_getrecord");

    /* Probe & Announcement functions */
    TCase *TCase_mdns_send_announcement_packet = tcase_create("Unit test for mdns_send_announcement_packet");
    TCase *TCase_mdns_announce = tcase_create("Unit test for mdns_announce");
    TCase *TCase_mdns_send_probe_packet = tcase_create("Unit test for mdns_send_probe_packet");
    TCase *TCase_mdns_add_probe_question = tcase_create("Unit test for mdns_add_probe_question");
    TCase *TCase_mdns_probe = tcase_create("Unit test for mdns_probe");

    /* Claiming functions */
    TCase *TCase_mdns_claim = tcase_create("Unit test for mnds_claim");

    /* API functions */
    TCase *TCase_mdns_set_hostname = tcase_create("Unit test for mdns_set_hostname");
    TCase *TCase_mdns_get_hostname = tcase_create("Unit test for mdns_get_hostname");

    tcase_add_test(TCase_mdns_init, tc_mdns_init);
    suite_add_tcase(s, TCase_mdns_init);

    /* Comparing functions */
    tcase_add_test(TCase_mdns_rdata_cmp, tc_mdns_rdata_cmp);
    suite_add_tcase(s, TCase_mdns_rdata_cmp);
    tcase_add_test(TCase_mdns_cmp, tc_mdns_cmp);
    suite_add_tcase(s, TCase_mdns_cmp);
    tcase_add_test(TCase_mdns_cmp_name_type, tc_mdns_cmp_name_type);
    suite_add_tcase(s, TCase_mdns_cmp_name_type);
    tcase_add_test(TCase_mdns_cookie_cmp, tc_mdns_cookie_cmp);
    suite_add_tcase(s, TCase_mdns_cookie_cmp);

    /* Cookie functions */
    tcase_add_test(TCase_mdns_cookie_delete, tc_mdns_cookie_delete);
    suite_add_tcase(s, TCase_mdns_cookie_delete);
    tcase_add_test(TCase_mdns_cookie_create, tc_mdns_cookie_create);
    suite_add_tcase(s, TCase_mdns_cookie_create);
    tcase_add_test(TCase_mdns_cookie_tree_find_query_cookie, tc_mdns_cookie_tree_find_query_cookie);
    suite_add_tcase(s, TCase_mdns_cookie_tree_find_query_cookie);
    tcase_add_test(TCase_mdns_cookie_tree_del_cookie, tc_mdns_cookie_tree_del_cookie);
    suite_add_tcase(s, TCase_mdns_cookie_tree_del_cookie);
    tcase_add_test(TCase_mdns_cookie_tree_add_cookie, tc_mdns_cookie_tree_add_cookie);
    suite_add_tcase(s, TCase_mdns_cookie_tree_add_cookie);
    tcase_add_test(TCase_mdns_cookie_find_record, tc_mdns_cookie_find_record);
    suite_add_tcase(s, TCase_mdns_cookie_find_record);
    tcase_add_test(TCase_mdns_cookie_apply_spt, tc_mdns_cookie_apply_spt);
    suite_add_tcase(s, TCase_mdns_cookie_apply_spt);
    tcase_add_test(TCase_mdns_is_suffix_present, tc_mdns_is_suffix_present);
    suite_add_tcase(s, TCase_mdns_is_suffix_present);
    tcase_add_test(TCase_mdns_resolve_name_conflict, tc_mdns_resolve_name_conflict);
    suite_add_tcase(s, TCase_mdns_resolve_name_conflict);
    tcase_add_test(TCase_mdns_generate_new_records, tc_mdns_generate_new_records);
    suite_add_tcase(s, TCase_mdns_generate_new_records);
    tcase_add_test(TCase_mdns_cookie_resolve_conflict, tc_mdns_cookie_resolve_conflict);
    suite_add_tcase(s, TCase_mdns_cookie_resolve_conflict);

    /* Question functions */
    tcase_add_test(TCase_mdns_question_create, tc_mdns_question_create);
    suite_add_tcase(s, TCase_mdns_question_create);

    /* Record functions */
    tcase_add_test(TCase_mdns_dns_record_create, tc_mdns_dns_record_create);
    suite_add_tcase(s, TCase_mdns_dns_record_create);
    tcase_add_test(TCase_mdns_record_resolve_conflict, tc_mdns_record_resolve_conflict);
    suite_add_tcase(s, TCase_mdns_record_resolve_conflict);
    tcase_add_test(TCase_mdns_record_am_i_lexi_later, tc_mdns_record_am_i_lexi_later);
    suite_add_tcase(s, TCase_mdns_record_am_i_lexi_later);
    tcase_add_test(TCase_mdns_record_create_from_dns, tc_mdns_record_create_from_dns);
    suite_add_tcase(s, TCase_mdns_record_create_from_dns);
    tcase_add_test(TCase_mdns_record_copy_with_new_name, tc_mdns_record_copy_with_new_name);
    suite_add_tcase(s, TCase_mdns_record_copy_with_new_name);
    tcase_add_test(TCase_mdns_record_copy, tc_mdns_record_copy);
    suite_add_tcase(s, TCase_mdns_record_copy);
    tcase_add_test(TCase_mdns_record_create, tc_mdns_record_create);
    suite_add_tcase(s, TCase_mdns_record_create);
    tcase_add_test(TCase_mdns_record_delete, tc_mdns_record_delete);
    suite_add_tcase(s, TCase_mdns_record_delete);

    /* Record Vector functions */
    tcase_add_test(TCase_mdns_record_vector_init, tc_mdns_record_vector_init);
    suite_add_tcase(s, TCase_mdns_record_vector_init);
    tcase_add_test(TCase_mdns_record_vector_count, tc_mdns_record_vector_count);
    suite_add_tcase(s, TCase_mdns_record_vector_count);
    tcase_add_test(TCase_mdns_record_vector_add, tc_mdns_record_vector_add);
    suite_add_tcase(s, TCase_mdns_record_vector_add);
    tcase_add_test(TCase_mdns_record_vector_get, tc_mdns_record_vector_get);
    suite_add_tcase(s, TCase_mdns_record_vector_get);
    tcase_add_test(TCase_mdns_record_vector_delete, tc_mdns_record_vector_delete);
    suite_add_tcase(s, TCase_mdns_record_vector_delete);
    tcase_add_test(TCase_mdns_record_vector_destroy, tc_mdns_record_vector_destroy);
    suite_add_tcase(s, TCase_mdns_record_vector_destroy);
    tcase_add_test(TCase_mdns_record_vector_append, tc_mdns_record_vector_append);

    /* Record tree functions */
    tcase_add_test(TCase_mdns_record_tree_find_url, tc_mdns_record_tree_find_url);
    suite_add_tcase(s, TCase_mdns_record_tree_find_url);
    tcase_add_test(TCase_mdns_record_tree_find_url_type, tc_mdns_record_tree_find_url_type);
    suite_add_tcase(s, TCase_mdns_record_tree_find_url_type);
    tcase_add_test(TCase_mdns_record_tree_find_record, tc_mdns_record_tree_find_record);
    suite_add_tcase(s, TCase_mdns_record_tree_find_record);
    tcase_add_test(TCase_mdns_record_tree_del_url, tc_mdns_record_tree_del_url);
    suite_add_tcase(s, TCase_mdns_record_tree_del_url);
    tcase_add_test(TCase_mdns_record_tree_del_url_type, tc_mdns_record_tree_del_url_type);
    suite_add_tcase(s, TCase_mdns_record_tree_del_url_type);
    tcase_add_test(TCase_mdns_record_tree_del_record, tc_mdns_record_tree_del_record);
    suite_add_tcase(s, TCase_mdns_record_tree_del_record);
    tcase_add_test(TCase_mdns_record_tree_add_record, tc_mdns_record_tree_add_record);
    suite_add_tcase(s, TCase_mdns_record_tree_add_record);

    /* My records functions */
    tcase_add_test(TCase_mdns_my_records_find_url_type, tc_mdns_my_records_find_url_type);
    suite_add_tcase(s, TCase_mdns_my_records_find_url_type);
    tcase_add_test(TCase_mdns_my_records_add, tc_mdns_my_records_add);
    suite_add_tcase(s, TCase_mdns_my_records_add);
    tcase_add_test(TCase_mdns_my_records_find_probed, tc_mdns_my_records_find_probed);
    suite_add_tcase(s, TCase_mdns_my_records_find_probed);
    tcase_add_test(TCase_mdns_my_records_find_to_probe, tc_mdns_my_records_find_to_probe);
    suite_add_tcase(s, TCase_mdns_my_records_find_to_probe);
    tcase_add_test(TCase_mdns_my_records_claimed_id, tc_mdns_my_records_claimed_id);
    suite_add_tcase(s, TCase_mdns_my_records_claimed_id);
    tcase_add_test(TCase_mdns_my_records_claimed, tc_mdns_my_records_claimed);
    suite_add_tcase(s, TCase_mdns_my_records_claimed);

    /* Query functions */
    tcase_add_test(TCase_mdns_query_create, tc_mdns_query_create);
    suite_add_tcase(s, TCase_mdns_query_create);

    /* Answer functions */
    tcase_add_test(TCase_mdns_answer_create, tc_mdns_answer_create);
    suite_add_tcase(s, TCase_mdns_answer_create);

    /* Cache functions */
    tcase_add_test(TCase_mdns_cache_add_record, tc_mdns_cache_add_record);
    suite_add_tcase(s, TCase_mdns_cache_add_record);
    tcase_add_test(TCase_mdns_cache_flush, tc_mdns_cache_flush);
    suite_add_tcase(s, TCase_mdns_cache_flush);
    tcase_add_test(TCase_mdns_populate_answer_vector, tc_mdns_populate_answer_vector);
    suite_add_tcase(s, TCase_mdns_populate_answer_vector);

    /* Handling receptions */
    tcase_add_test(TCase_mdns_handle_data_as_questions, tc_mdns_handle_data_as_questions);
    suite_add_tcase(s, TCase_mdns_handle_data_as_questions);
    tcase_add_test(TCase_mdns_handle_data_as_answers, tc_mdns_handle_data_as_answers);
    suite_add_tcase(s, TCase_mdns_handle_data_as_answers);
    tcase_add_test(TCase_mdns_handle_data_as_authorities, tc_mdns_handle_data_as_authorities);
    suite_add_tcase(s, TCase_mdns_handle_data_as_authorities);
    tcase_add_test(TCase_mdns_handle_data_as_additionals, tc_mdns_handle_data_as_additionals);
    suite_add_tcase(s, TCase_mdns_handle_data_as_additionals);

    /* Handling query packets */
    tcase_add_test(TCase_mdns_sort_unicast_multicast, tc_mdns_sort_unicast_multicast);
    suite_add_tcase(s, TCase_mdns_sort_unicast_multicast);
    tcase_add_test(TCase_mdns_apply_known_answer_suppression, tc_mdns_apply_known_answer_suppression);
    suite_add_tcase(s, TCase_mdns_apply_known_answer_suppression);

    /* Address resolving functions */
    tcase_add_test(TCase_mdns_send_query_packet, tc_mdns_send_query_packet);
    suite_add_tcase(s, TCase_mdns_send_query_packet);
    tcase_add_test(TCase_mdns_getrecord, tc_mdns_getrecord);
    suite_add_tcase(s, TCase_mdns_getrecord);

    /* Probe & Announcement functions */
    tcase_add_test(TCase_mdns_send_announcement_packet, tc_mdns_send_announcement_packet);
    suite_add_tcase(s, TCase_mdns_send_announcement_packet);
    tcase_add_test(TCase_mdns_announce, tc_mdns_announce);
    suite_add_tcase(s, TCase_mdns_announce);
    tcase_add_test(TCase_mdns_send_probe_packet, tc_mdns_send_probe_packet);
    suite_add_tcase(s, TCase_mdns_send_probe_packet);
    tcase_add_test(TCase_mdns_add_probe_question, tc_mdns_add_probe_question);
    suite_add_tcase(s, TCase_mdns_add_probe_question);
    tcase_add_test(TCase_mdns_probe, tc_mdns_probe);
    suite_add_tcase(s, TCase_mdns_probe);

    /* Claiming functions */
    tcase_add_test(TCase_mdns_claim, tc_mdns_claim);
    suite_add_tcase(s, TCase_mdns_claim);

    /* API functions */
    tcase_add_test(TCase_mdns_set_hostname, tc_mdns_set_hostname);
    suite_add_tcase(s, TCase_mdns_set_hostname);
    tcase_add_test(TCase_mdns_get_hostname, tc_mdns_get_hostname);
    suite_add_tcase(s, TCase_mdns_get_hostname);

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

