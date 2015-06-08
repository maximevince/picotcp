#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_dns_common.h"
#include "pico_mdns.h"
#include "pico_tree.h"
#include "pico_dev_mock.c"
#include "modules/pico_mdns.c"
#include "check.h"

void callback( pico_mdns_rtree *tree,
               char *str,
               void *arg ) /* MARK: Generic callback */
{
    IGNORE_PARAMETER(tree);
    IGNORE_PARAMETER(str);
    IGNORE_PARAMETER(arg);
    /* Do nothing, because fail_unless and fail_if don't work here */
}

int mdns_init() /* MARK: Initialise mDNS module */
{
    struct mock_device *mock = NULL;

    struct pico_ip4 local = {.addr = long_be(0x0a280064)};
    struct pico_ip4 netmask = {.addr = long_be(0xffffff00)};

    mock = pico_mock_create(NULL);
    if (!mock)
        return -1;

    pico_ipv4_link_add(mock->dev, local, netmask);

    /* Try to initialise the mDNS module right */
    return pico_mdns_init("host.local", local, callback, NULL);
}

#define PICO_MDNS_COOKIE_DECLARE(name) \
		struct pico_mdns_cookie (name) = \
		{ \
			{&LEAF, pico_dns_question_cmp}, \
			{&LEAF, pico_mdns_record_cmp}, \
			{&LEAF, pico_mdns_record_cmp}, \
			0, 0, 0 ,0, NULL, NULL, NULL \
		};

START_TEST(tc_mdns_init) /* MARK: mdns_init */
{
    int ret = 0;
    struct pico_ip4 local = {0};
	char *hostname = "host.local";

    printf("*********************** starting %s * \n", __func__);

    pico_stack_init();

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(NULL, local, callback, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(hostname, local, callback, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    /* Try to initialise the mDNS module wrong */
    ret = pico_mdns_init(hostname, local, NULL, NULL);
    fail_unless(-1 == ret, "mdns_init failed checking params!\n");

    ret = mdns_init();
    fail_unless(0 == ret, "mdns_init failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_cmp) /* MARK: mdns_record_cmp */
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
    fail_if(!(a.record), "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!(b.record), "Record B could not be created!\n");

    /* Try to compare equal records */
    ret = pico_mdns_record_cmp((void *) &a, (void *) &b);
    fail_unless(!ret, "mdns_record_cmp failed with equal records!\n");
    pico_dns_record_delete((void **)&(a.record));
    pico_dns_record_delete((void **)&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_AAAA,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_mdns_record_cmp((void *) &a, (void *) &b);
    fail_unless(ret > 0, "mdns_record_cmp failed with same name, different types!\n");
    pico_dns_record_delete((void **)&(a.record));
    pico_dns_record_delete((void **)&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url3, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_mdns_record_cmp((void *) &a, (void *) &b);
    fail_unless(ret < 0, "mdns_record_cmp failed with different name, same types!\n");
    pico_dns_record_delete((void **)&(a.record));
    pico_dns_record_delete((void **)&(b.record));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_cmp_name_type) /* MARK: mdns_record_cmp_name_type*/
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
    a.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_AAAA,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_mdns_record_cmp_name_type((void *) &a, (void *) &b);
    fail_unless(ret > 0, "mdns_record_cmp_name_type failed with different types!\n");
    pico_dns_record_delete((void **)&(a.record));
    pico_dns_record_delete((void **)&(b.record));

    /* Create different test records */
    a.record = pico_dns_record_create(url3, (uint8_t *)url1, strlen(url1), &len,
                                      PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!a.record, "Record A could not be created!\n");
    b.record = pico_dns_record_create(url3, (uint8_t *)url1, strlen(url1), &len,
                                      PICO_DNS_TYPE_A,
                                      PICO_DNS_CLASS_IN, 0);
    fail_if(!b.record, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_mdns_record_cmp_name_type((void *) &a, (void *) &b);
    fail_unless(!ret, "mdns_record_cmp_name_type failed!\n");
    pico_dns_record_delete((void **)&(a.record));
    pico_dns_record_delete((void **)&(b.record));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_cmp) /* MARK: mdns_cookie_cmp */
{
	PICO_MDNS_COOKIE_DECLARE(a);
	PICO_MDNS_COOKIE_DECLARE(b);
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
                                            PICO_DNS_TYPE_AAAA,
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
	pico_tree_insert(&(a.qtree), question1);
	pico_tree_insert(&(a.qtree), question2);
	pico_tree_insert(&(a.qtree), question3);
	pico_tree_insert(&(a.qtree), question4);
	pico_tree_insert(&(a.qtree), question5);
	pico_tree_insert(&(a.antree), &record1);
	pico_tree_insert(&(a.antree), &record2);
	pico_tree_insert(&(a.antree), &record3);
	pico_tree_insert(&(a.antree), &record4);

	pico_tree_insert(&(b.qtree), question1);
	pico_tree_insert(&(b.qtree), question2);
	pico_tree_insert(&(b.qtree), question3);
	pico_tree_insert(&(b.qtree), question4);
	pico_tree_insert(&(b.qtree), question5);
	pico_tree_insert(&(b.antree), &record1);
	pico_tree_insert(&(b.antree), &record2);
	pico_tree_insert(&(b.antree), &record3);
	pico_tree_insert(&(b.antree), &record4);

    /* Try to compare exactly the same cookies*/
    ret = pico_mdns_cookie_cmp((void *) &a, (void *) &b);
    fail_unless(0 == ret, "mdns_cookie_cmp failed with equal cookies!\n");

    /* Try to compare cookies but B a larger question than A*/
	pico_tree_delete(&(a.qtree), question2);
    ret = pico_mdns_cookie_cmp((void *) &a, (void *) &b);
    fail_unless(ret > 0, "mdns_cookie_cmp failed with larger question A!\n");

    /* Insert more possibilities here.. */

	PICO_DNS_QTREE_DESTROY(&(b.qtree));
	pico_dns_record_delete((void **)&(record1.record));
	pico_dns_record_delete((void **)&(record2.record));
	pico_dns_record_delete((void **)&(record3.record));
	pico_dns_record_delete((void **)&(record4.record));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_delete) /* MARK: mdns_cookie_delete */
{
    struct pico_mdns_cookie *a = NULL;
	PICO_DNS_QTREE_DECLARE(qtree);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);

    printf("*********************** starting %s * \n", __func__);

    fail_unless(pico_mdns_cookie_delete(&a),
                "mdns_cookie_delete failed checking params!\n");
    a = pico_mdns_cookie_create(qtree, antree, artree, 0, 0, NULL, NULL);
    fail_unless(!pico_mdns_cookie_delete(&a),
                "mdns_cookie_delete failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_create) /* MARK: mdns_cookie_create */
{
    struct pico_mdns_cookie *a = NULL;
	PICO_DNS_QTREE_DECLARE(qtree);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);

    printf("*********************** starting %s * \n", __func__);

    a = pico_mdns_cookie_create(qtree, antree, artree, 0, 0, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");

    pico_mdns_cookie_delete(&a);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_tree_find_query_cookie) /* MARK: mdns_ctree_find_cookie */
{
    struct pico_mdns_cookie *a = NULL, *b = NULL;
	PICO_DNS_QTREE_DECLARE(qtree_a);
	PICO_DNS_QTREE_DECLARE(qtree_b);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);
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

	pico_tree_insert(&qtree_a, question3);
	pico_tree_insert(&qtree_a, question4);

    pico_tree_insert(&qtree_b, question1);
    pico_tree_insert(&qtree_b, question2);
    pico_tree_insert(&qtree_b, question5);

    a = pico_mdns_cookie_create(qtree_a, antree, artree, 1,
                                PICO_MDNS_PACKET_TYPE_QUERY, NULL, NULL);
    fail_if(!a, "mdns_cookie_create failed!\n");
    b = pico_mdns_cookie_create(qtree_b, antree, artree, 1,
                                PICO_MDNS_PACKET_TYPE_QUERY, NULL, NULL);
    fail_if(!b, "mdns_cookie_create failed!\n");

	pico_tree_insert(&Cookies, a);
	pico_tree_insert(&Cookies, b);

    fail_unless(b == pico_mdns_ctree_find_cookie("\3foo\5local", PICO_MDNS_PACKET_TYPE_QUERY),
                "mdns_cookie_tree_find_query_cookie failed with foo.local\n");

    fail_unless(a == pico_mdns_ctree_find_cookie("\2pi\5local", PICO_MDNS_PACKET_TYPE_QUERY),
                "mdns_cookie_tree_find_query_cookie failed with pi.local\n");

    fail_unless(NULL == pico_mdns_ctree_find_cookie("bla.local", PICO_MDNS_PACKET_TYPE_QUERY),
                "mdns_cookie_tree_find_query_cookie failed with foo.local\n");

	pico_tree_delete(&Cookies, a);
	pico_tree_delete(&Cookies, b);
	pico_mdns_cookie_delete(&a);
	pico_mdns_cookie_delete(&b);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_apply_spt) /* MARK: mdns_cookie_apply_spt */
{
	PICO_MDNS_COOKIE_DECLARE(a);
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

    /* Make it a probe cookie otherwise it will just return -1 */
    a.type = PICO_MDNS_PACKET_TYPE_PROBE;

    /* Need to initialise the stack to allow timer scheduling IMPORTANT! */
	pico_stack_init();

	/* Create 2 exactly the same cookies */
	pico_tree_insert(&(a.antree), &record1);
	pico_tree_insert(&(a.antree), &record2);
	pico_tree_insert(&MyRecords, &record1);
	pico_tree_insert(&MyRecords, &record2);

	ret = pico_mdns_cookie_apply_spt(&a, record3.record);
	fail_unless(ret, "mdns_cookie_apply_spt failed checking parms!\n");

	PICO_MDNS_SET_FLAG(record1.flags, PICO_MDNS_RECORD_CURRENTLY_PROBING);
	PICO_MDNS_SET_FLAG(record2.flags, PICO_MDNS_RECORD_CURRENTLY_PROBING);

    /* Check with peer record which is lexicographically later */
    ret = pico_mdns_cookie_apply_spt(&a, record3.record);
    fail_unless(0 == ret, "mdns_cookie_apply_spt failed!\n");

    /* Check with peer record which is lexicographically earlier */
    ret = pico_mdns_cookie_apply_spt(&a, record4.record);
    fail_unless(0 == ret, "mdns_cookie_apply_spt failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_is_suffix_present) /* MARK: mdns_is_suffix_present */
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
START_TEST(tc_pico_itoa) /* MARK: itoa */
{
	printf("*********************** starting %s * \n", __func__);
	char num[10] = {0};

	uint16_t t1 = 10;

	pico_itoa(t1, num);
	fail_unless(0 == strcmp(num, "10"), "ITOA with %d failed: %s\n", t1, num);

	printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_resolve_name_conflict) /* MARK: mdns_resolve_name_conflict */
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
START_TEST(tc_mdns_generate_new_records) /* MARK: mdns_generate_new_records */
{
	PICO_MDNS_RTREE_DECLARE(ctree);
	PICO_MDNS_RTREE_DECLARE(ntree);
    struct pico_mdns_record *record = NULL;
    const char *url = "foo.local";
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     PICO_MDNS_RECORD_UNIQUE);
    fail_if(!(record->record), "Record could not be created!\n");
	pico_tree_insert(&ctree, record);

    ntree = pico_mdns_generate_new_records(&ctree, "\3foo\5local",
										   "\7foo (2)\5local");

    fail_unless(1 == pico_tree_count(&ntree), "new_tree has wrong count!\n");
	record = pico_tree_firstNode(ntree.root)->keyValue;
    fail_unless(strcmp(record->record->rname, "\7foo (2)\5local") == 0,
                "New name isn't correctly copied %s!\n", record->record->rname);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cookie_resolve_conflict) /* MARK: mdns_cookie_resolve_conflict */
{
    struct pico_mdns_cookie *a = NULL;
	PICO_DNS_QTREE_DECLARE(qtree);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);
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
	pico_tree_insert(&antree, record);
	pico_tree_insert(&qtree, question);

    /* Make it a probe cookie otherwise it will just return -1 */
    a = pico_mdns_cookie_create(qtree, antree, artree, 1,
                                PICO_MDNS_PACKET_TYPE_PROBE,
                                callback, NULL);

    /* Need to initialise the stack to allow timer scheduling IMPORTANT! */
    pico_stack_init();
    ret = mdns_init();
    fail_unless(0 == ret, "mdns_init failed!\n");

    /* Cookie needs to be removed from cookie tree so we need to add it first */
    pico_tree_insert(&Cookies, a);

    ret = pico_mdns_cookie_resolve_conflict(a, "\3foo\5local");
    fail_unless(0 == ret, "mdns_cookie_resolve_conflict failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_question_create) /* MARK: mdns_question_create */
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
START_TEST(tc_mdns_record_resolve_conflict) /* MARK: mdns_record_resolve_conflict */
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
START_TEST(tc_mdns_record_am_i_lexi_later) /* MARK: mdns_record_am_i_lexi_later */
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
    fail_unless(ret < 0, "mdns_record_am_i_lexi_later failed!\n");

    ret = pico_mdns_record_am_i_lexi_later(&record2, &record4);
    fail_unless(ret > 0, "mdns_record_am_i_lexi_later failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_create_from_dns) /* MARK: mdns_record_create_from_dns */
{
    struct pico_mdns_record *record = NULL;
    struct pico_dns_record *a = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);
    a = pico_dns_record_create (url,
								(void *)rdata, 4,
								&len,
								PICO_DNS_TYPE_A,
								PICO_DNS_CLASS_IN,
                                    120);
    fail_if(!a, "mdns_dns_record_create returned NULL!\n");

    /* Try to create an mDNS record from a DNS record */
    record = pico_mdns_record_create_from_dns(a);
    fail_if(!record, "mdns_record_create_from_dns returned NULL!\n");
    fail_unless(strcmp(record->record->rname, "\x7picotcp\x3com"),
                "mdns_record_create_from_dns failed!\n");
    fail_unless(record->record->rsuffix->rtype == short_be(PICO_DNS_TYPE_A),
                "mdns_record_create_from_dns failed setting rtype!\n");
    fail_unless(0x0001 == short_be(record->record->rsuffix->rclass),
                "mdns_record_create_from_dns failed setting rclass!\n");
    fail_unless(record->record->rsuffix->rttl == long_be(120),
                "mdns_record_create_from_dns failed setting rttl!\n");
    fail_unless(record->record->rsuffix->rdlength == short_be(4),
                "mdns_record_create_from_dns failed setting rdlenth!\n");
    fail_unless(memcmp(record->record->rdata, rdata, 4) == 0,
                "mdns_record_create_from_dns failed setting rdata!\n");

    pico_mdns_record_delete((void **)&record);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_copy_with_new_name) /* MARK: copy_with_new_name */
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

    pico_mdns_record_delete((void **)&record);
    pico_mdns_record_delete((void **)&copy);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_copy) /* MARK: mdns_record_copy */
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

    pico_mdns_record_delete((void **)&record);
    pico_mdns_record_delete((void **)&copy);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_create) /* MARK: mdns_record_create */
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
    pico_mdns_record_delete((void **)&record);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_delete) /* MARK: mdns_record_delete */
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
    ret = pico_mdns_record_delete((void **)&record);
    fail_unless(0 == ret, "mdns_record_delete returned error!\n");
    fail_unless(!record, "mdns_record_delete didn't delete properly");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
void add_records( void ) /* MARK: helper to add records to MyRecords s*/
{
    struct pico_mdns_record *record = NULL, *record1 = NULL, *record2 = NULL,
    *record3 = NULL;
    struct pico_ip4 rdata = {long_be(0x00FFFFFF)};
    struct pico_ip4 rdata1 = {long_be(0xFFFFFFFF)};
    const char *url = "foo.local";
    const char *url1 = "bar.local";

    /* Create an A record with URL */
    record = pico_mdns_record_create(url, &rdata, 4, PICO_DNS_TYPE_A, 0,
                                     (PICO_MDNS_RECORD_UNIQUE |
									  PICO_MDNS_RECORD_PROBED |
									  PICO_MDNS_RECORD_HOSTNAME));
    fail_if(!record, "Record could not be created!\n");
	printf("Is hostname record: %d\n", IS_HOSTNAME_RECORD(record));

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
	pico_tree_insert(&MyRecords, record);
	pico_tree_insert(&MyRecords, record1);
	pico_tree_insert(&MyRecords, record2);
	pico_tree_insert(&MyRecords, record3);
}
START_TEST(tc_mdns_record_tree_find_name) /* MARK: mdns_record_find_name */
{
	PICO_MDNS_RTREE_DECLARE(hits);
	struct pico_tree_node *node = NULL;
	struct pico_mdns_record *record = NULL;
    int found = 1, i = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_rtree_find_name(&MyRecords, "\3foo\5local");
    fail_unless(2 == pico_tree_count(&hits),
                "mdns_record_tree_find_name should find 2 records here!\n");
	pico_tree_foreach(node, &hits) {
		if ((record = node->keyValue)) {
			if (strcmp(record->record->rname, "\3foo\5local"))
				found = 0;
		}
	}
    fail_unless(1 == found,
                "mdns_record_tree_find_name returned records with other name!\n");

    hits = pico_mdns_rtree_find_name(&MyRecords, "\3bar\5local");
    fail_unless(1 == pico_tree_count(&hits),
                "mdns_record_tree_find_name should find 1 record here!\n");
	record = pico_tree_firstNode(hits.root)->keyValue;
    fail_unless(0 == strcmp(record->record->rname,
                            "\3bar\5local"),
                "mdns_record_tree_find_name returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_find_name_type) /* MARK: mdns_record_find_name_type */
{
	PICO_MDNS_RTREE_DECLARE(hits);
	struct pico_tree_node *node = NULL;
	struct pico_mdns_record *record = NULL;
    int found = 1, i = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    /* Try to find the first A record */
    hits = pico_mdns_rtree_find_name_type(&MyRecords, "\3foo\5local", PICO_DNS_TYPE_A);
    fail_unless(1 == pico_tree_count(&hits),
                "mdns_record_tree_find_name should find 1 record here!\n");
	record = pico_tree_firstNode(hits.root)->keyValue;
    fail_unless(0 == strcmp(record->record->rname, "\3foo\5local"),
                "mdns_record_tree_find_name returned record with other name!\n");

    /* Try to find the 2 PTR records */
    hits = pico_mdns_rtree_find_name_type(&MyRecords, "\3foo\5local", PICO_DNS_TYPE_PTR);
	pico_tree_foreach(node, &hits) {
		if ((record = node->keyValue)) {
			if (strcmp(record->record->rname, "\3foo\5local"))
				found = 0;
		}
	}
    fail_unless(1 == found,
            "mdns_record_tree_find_name returned records with other name!\n");

    /* Try to find the last A record */
	hits = pico_mdns_rtree_find_name_type(&MyRecords, "\3bar\5local", PICO_DNS_TYPE_A);
	fail_unless(1 == pico_tree_count(&hits),
				"mdns_record_tree_find_name should find 1 record here!\n");
	record = pico_tree_firstNode(hits.root)->keyValue;
	fail_unless(0 == strcmp(record->record->rname, "\3bar\5local"),
				"mdns_record_tree_find_name returned record with other name!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_del_name) /* MARK: mdns_record_tree_del_name */
{
	PICO_MDNS_RTREE_DECLARE(hits);
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
	pico_tree_insert(&MyRecords, record);
	pico_tree_insert(&MyRecords, record1);
	pico_tree_insert(&MyRecords, record2);
	pico_tree_insert(&MyRecords, record3);

    /* Try to del the first tree records */
    ret = pico_mdns_rtree_del_name(&MyRecords, "\3foo\5local");
    fail_unless(0 == ret,
                "mdns_record_tree_del_name failed!\n");
    hits = pico_mdns_rtree_find_name(&MyRecords, "\3foo\5local");
    fail_unless(0 == pico_tree_count(&hits),
                "mdns_record_tree_find_name should find 3 records here!\n");

    hits = pico_mdns_rtree_find_name( &MyRecords, "\3bar\5local");
    fail_unless(1 == pico_tree_count(&hits),
                "mdns_record_tree_find_name should find 1 record here!\n");
	record = pico_tree_first(&hits);
    fail_unless(0 == strcmp(record->record->rname, "\3bar\5local"),
                "mdns_record_tree_del_name failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_record_tree_del_name_type) /* MARK: mdns_record_tree_del_name_type */
{
	PICO_MDNS_RTREE_DECLARE(hits);
    const char *url = "foo.local";
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    add_records();

    /* Try to del the two PTR records */
    ret = pico_mdns_rtree_del_name_type(&MyRecords, "\3foo\5local",
										PICO_DNS_TYPE_PTR);
    fail_unless(0 == ret, "mdns_record_tree_del_name_type returned error!\n");

    /* Try to find the 2 PTR records */
    hits = pico_mdns_rtree_find_name_type(&MyRecords, "\3foo\5local",
										  PICO_DNS_TYPE_PTR);
    fail_unless(0 == pico_tree_count(&hits),
                "mdns_record_tree_find_name_type returned PTR records!\n");


    /* Try to find the first A record */
    hits = pico_mdns_rtree_find_name_type(&MyRecords, "\3foo\5local",
										  PICO_DNS_TYPE_A);
    fail_unless(1 == pico_tree_count(&hits),
                "mdns_record_tree_del_name_type failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_add) /* MARK: mdns_my_records_add */
{
	PICO_MDNS_RTREE_DECLARE(rtree);
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
	pico_tree_insert(&rtree, record);
	pico_tree_insert(&rtree, record1);
	pico_tree_insert(&rtree, record2);
	pico_tree_insert(&rtree, record3);

    pico_mdns_my_records_add(&rtree, 0);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_find_probed) /* MARK: mdns_my_records_find_probed */
{
	PICO_MDNS_RTREE_DECLARE(hits);

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_my_records_find_probed();
    fail_unless(2 == pico_tree_count(&hits),
                "mdns_my_records_find_probed failed %d!\n",
				pico_tree_count(&hits));


    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_find_to_probe) /* MARK: mdns_my_records_find_to_probe */
{
    PICO_MDNS_RTREE_DECLARE(hits);

    printf("*********************** starting %s * \n", __func__);

    add_records();

    hits = pico_mdns_my_records_find_to_probe();
    fail_unless(1 == pico_tree_count(&hits),
                "mdns_my_records_find_to_probe failed! %d\n",  pico_tree_count(&hits));


    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_claimed_id) /* MARK: mnds_my_records_claimed_id */
{
	PICO_MDNS_RTREE_DECLARE(hits);
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
	record->flags |= PICO_MDNS_RECORD_PROBED;
    fail_if(!record, "Record could not be created!\n");

    /* Create 2 PTR records to URL */
    record1 = pico_mdns_record_create(url, url, strlen(url),
                                      PICO_DNS_TYPE_PTR, 0,
                                      PICO_MDNS_RECORD_UNIQUE);
    record1->claim_id = 1;
	record1->flags |= PICO_MDNS_RECORD_PROBED;
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
	pico_tree_insert(&MyRecords, record);
	pico_tree_insert(&MyRecords, record1);
	pico_tree_insert(&MyRecords, record2);
	pico_tree_insert(&MyRecords, record3);

    fail_unless(1 == pico_mdns_my_records_claimed_id(1, &hits),
                "mdns_my_records_claimed_id_failed!\n");
    fail_unless(2 == pico_tree_count(&hits),
                "Vector count should be 2!\n");

    fail_unless(0 == pico_mdns_my_records_claimed_id(0, &hits),
                "Claim ID '0' isn't claimed yet..");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_my_records_claimed) /* MARK: mdns_my_records_claimed */
{
	PICO_MDNS_RTREE_DECLARE(rtree);
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
	pico_tree_insert(&MyRecords, record);
	pico_tree_insert(&MyRecords, record1);
	pico_tree_insert(&MyRecords, record2);
	pico_tree_insert(&MyRecords, record3);

	pico_tree_insert(&rtree, record);
	pico_tree_insert(&rtree, record1);
	pico_tree_insert(&rtree, record2);
	pico_tree_insert(&rtree, record3);

    ret = pico_mdns_my_records_claimed(rtree, callback, NULL);
    fail_unless(0 == ret, "mdns_my_records_claimed failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cache_add_record) /* MARK: mdns_cache_add_record */
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
	found = pico_tree_findKey(&Cache, record);
    fail_unless((int)found, "mdns_cache_add_record failed!\n");
    ret = pico_mdns_cache_add_record(record);
    fail_unless(0 == ret,
                "mdns_cache_add_record returned error!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_cache_flush) /* MARK: mdns_cache_flush */
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
	found = pico_tree_findKey(&Cache, record);
    fail_unless(!found, "mdns_cache_flush failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_populate_answer_vector) /* MARK: mdns_popolate_antree */
{
	PICO_MDNS_RTREE_DECLARE(rtree);

    printf("*********************** starting %s * \n", __func__);
    add_records();

    rtree = pico_mdns_populate_antree("\3foo\5local", PICO_DNS_TYPE_A,
										PICO_DNS_CLASS_IN);

    fail_unless(1 == pico_tree_count(&rtree), "mdns_populate_answer_vector failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_questions) /* MARK: handle_data_as_questions */
{
    pico_dns_packet *packet = NULL;
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_DNS_QTREE_DECLARE(qtree);
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
	pico_tree_insert(&qtree, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    b = pico_mdns_question_create(qurl2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                  0, 0);
    fail_if(!b, "dns_question_create failed!\n");
	pico_tree_insert(&qtree, b);
    packet = pico_dns_query_create(&qtree, NULL, NULL, NULL, &len);
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
	pico_tree_insert(&MyRecords, record1);
	pico_tree_insert(&MyRecords, record2);

    ptr = ((uint8_t *)packet + 12);

    antree = pico_mdns_handle_data_as_questions(&ptr, 2, packet);
    fail_unless(2 == pico_tree_count(&antree),
                "pico_mdns_handle_data_as_questions returned error!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_answers) /* MARK: handle_data_as_answers */
{
    pico_dns_packet *packet = NULL;
	PICO_DNS_RTREE_DECLARE(rtree);
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
	pico_tree_insert(&rtree, a->record);
	pico_tree_insert(&rtree, b->record);

    /* Try to create an answer packet */
    packet = pico_dns_answer_create(&rtree, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

    ret = pico_mdns_handle_data_as_answers_generic(&ptr, 2, packet, 0);
    fail_unless(0 == ret, "mdns_handle_data_as_answers failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_authorities) /* MARK: handle_data_as_authorities */
{
    pico_dns_packet *packet = NULL;
	PICO_DNS_RTREE_DECLARE(rtree);
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
	pico_tree_insert(&rtree, a->record);
	pico_tree_insert(&rtree, b->record);

    /* Try to create an answer packet */
    packet = pico_dns_answer_create(&rtree, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

    ret = pico_mdns_handle_data_as_answers_generic(&ptr, 2, packet, 1);
    fail_unless(0 == ret, "mdns_handle_data_as_answers failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_handle_data_as_additionals) /* MARK: handle_data_as_additionals */
{
    printf("*********************** starting %s * \n", __func__);
    /* Insert code here... */
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_sort_unicast_multicast) /* MARK: sort_unicast_multicast */
{
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_DNS_RTREE_DECLARE(antree_u);
	PICO_DNS_RTREE_DECLARE(antree_m);
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
	pico_tree_insert(&antree, a);
	pico_tree_insert(&antree, b);

    ret = pico_mdns_sort_unicast_multicast(&antree, &antree_u, &antree_m);
    fail_unless(0 == ret, "mdns_sort_unicast_multicast returned error!\n");
    fail_unless(1 == pico_tree_count(&antree_u), "mdns_sort_unicast_multicast failed!\n");
    fail_unless(1 == pico_tree_count(&antree_m), "mdns_sort_unicast_multicast failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_gather_additionals) /* MARK: gather_additionals */
{
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);
	struct pico_mdns_record *srv_record = NULL, *record = NULL;
	struct pico_tree_node *node = NULL;
	int ret = 0;

	printf("*********************** starting %s * \n", __func__);

	add_records();

	srv_record = pico_mdns_record_create("test._http._tcp.local",
										 "\0\0\0\0\0\x50\4host\5local", 17,
										 PICO_DNS_TYPE_SRV, 120,
										 PICO_MDNS_RECORD_UNIQUE);
	fail_if(!srv_record, "Could not create SRV record!\n");
	pico_tree_insert(&antree, srv_record);

	ret = pico_mdns_gather_additionals(&antree, &artree);
	fail_if(ret, "Gather Additionals returned error!\n");
	fail_unless(pico_tree_count(&antree) == 3, "ANtree should contain 3: %d",
				pico_tree_count(&antree));

	printf("Answers: \n");
	pico_tree_foreach(node, &antree) {
		if ((record = node->keyValue)) {
			printf("%d - %s\n", short_be(record->record->rsuffix->rtype),
				   record->record->rname);
		}
	}

	printf("Additionals: \n");
	pico_tree_foreach(node, &artree) {
		if ((record = node->keyValue)) {
			printf("%d - %s\n", short_be(record->record->rsuffix->rtype),
				   record->record->rname);
		}
	}

	fail_unless(pico_tree_count(&artree) == 3, "ARtree should contine 3: %d",
				pico_tree_count(&artree));

	printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_apply_known_answer_suppression) /* MARK: apply_k_a_s */
{
    pico_dns_packet *packet = NULL;
	PICO_DNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(rtree);
	struct pico_mdns_record *a = NULL, *b = NULL, *c = NULL, *d = NULL;
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

	pico_tree_insert(&antree, a->record);
	pico_tree_insert(&antree, b->record);
	pico_tree_insert(&rtree, a);
	pico_tree_insert(&rtree, b);

    /* Try to create an answer packet */
    packet = pico_dns_answer_create(&antree, NULL, NULL, &len);
    fail_if (packet == NULL, "mdns_answer_create returned NULL!\n");

    ptr = ((uint8_t *)packet + 12);

	printf("Applying Known answer suppression...\n");

    ret = pico_mdns_apply_k_a_s(&rtree, packet, 1, &ptr);
    fail_unless(0 == ret, "mdns_apply_known_answer_suppression returned error!\n");

    fail_unless(1 == pico_tree_count(&rtree),
                "mdns_apply_known_answer_suppression failed %d!\n",pico_tree_count(&rtree));

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_send_query_packet) /* MARK: send_query_packet */
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
START_TEST(tc_mdns_getrecord) /* MARK: getrecord */
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
	found = pico_tree_findKey(&Cache, record);
    fail_unless((int)found, "mdns_cache_add_record failed!\n");

    /* Init */
    pico_stack_init();
    mdns_init();

    ret = pico_mdns_getrecord("foo.local", PICO_DNS_TYPE_A, callback, NULL);
    fail_unless(0 == ret, "mdns_getrecord failed with cache record!\n");

    ret = pico_mdns_getrecord("bar.local", PICO_DNS_TYPE_A, callback, NULL);
    fail_unless(0 == ret, "mdns_getrecord failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_send_announcement_packet) /* MARK: send_announcement_packet */
{
    struct pico_mdns_cookie *cookie = NULL;
	PICO_DNS_QTREE_DECLARE(qtree);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);

    printf("*********************** starting %s * \n", __func__);

    cookie = pico_mdns_cookie_create(qtree, antree, artree, 2,
                                     PICO_MDNS_PACKET_TYPE_ANNOUNCEMENT,
                                     callback, NULL);

    pico_stack_init();
    mdns_init();

    pico_mdns_send_announcement_packet(0, cookie);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_announce) /* MARK: annonce */
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
START_TEST(tc_mdns_send_probe_packet) /* MARK: send_probe_packet */
{
    struct pico_mdns_cookie *cookie = NULL;
	PICO_DNS_QTREE_DECLARE(qtree);
	PICO_MDNS_RTREE_DECLARE(antree);
	PICO_MDNS_RTREE_DECLARE(artree);

    printf("*********************** starting %s * \n", __func__);

    cookie = pico_mdns_cookie_create(qtree, antree, artree, 2,
                                     PICO_MDNS_PACKET_TYPE_PROBE,
                                     callback, NULL);

    pico_stack_init();
    mdns_init();

    pico_mdns_send_probe_packet(0, cookie);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_add_probe_question) /* MARK: add_probe_question */
{
	PICO_DNS_QTREE_DECLARE(qtree);
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);
    ret = pico_mdns_add_probe_question(&qtree, "\4host\5local");
    fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
    fail_unless(1 == pico_tree_count(&qtree),
				"New probe question didn't create!\n");
	ret = pico_mdns_add_probe_question(&qtree, "\4host\5local");
	fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
	fail_unless(1 == pico_tree_count(&qtree),
				"Count should be 1, is: %d!\n", pico_tree_count(&qtree));
	ret = pico_mdns_add_probe_question(&qtree, "\4tree\5local");
	fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
	fail_unless(2 == pico_tree_count(&qtree),
				"New probe question didn't create!\n");
	ret = pico_mdns_add_probe_question(&qtree, "\x8host (2)\5local");
	fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
	fail_unless(3 == pico_tree_count(&qtree),
				"New probe question didn't create!\n");
	PICO_DNS_QTREE_DESTROY(&qtree);
	fail_unless(0 == pico_tree_count(&qtree),
				"Tree isn't properly destroyed %d!\n", pico_tree_count(&qtree));
	ret = pico_mdns_add_probe_question(&qtree, "\x8host (2)\5local");
	fail_unless(0 == ret, "mdns_add_probe_question returned error!\n");
	fail_unless(1 == pico_tree_count(&qtree),
				"New probe question didn't create!\n");
	PICO_DNS_QTREE_DESTROY(&qtree);
	fail_unless(0 == pico_tree_count(&qtree),
				"Tree isn't properly destroyed the second time!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_probe) /* MARK: probe */
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
START_TEST(tc_mdns_claim) /* MARK: mdns_claim */
{
	PICO_MDNS_RTREE_DECLARE(rtree);
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
	pico_tree_insert(&rtree, record);
	pico_tree_insert(&rtree, record1);

    pico_stack_init();
    mdns_init();

    ret = pico_mdns_claim(rtree, callback, NULL);
    fail_unless(0 == ret, "mdns_claimed failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_mdns_set_hostname) /* MARK: set_hostname */
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
START_TEST(tc_mdns_get_hostname) /* MARK: get_hostname */
{
    char *_hostname = NULL;

    printf("*********************** starting %s * \n", __func__);
    pico_stack_init();
    mdns_init();

    _hostname = pico_mdns_get_hostname();
    printf("*********************** ending %s * \n", __func__);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_mdns_init = tcase_create("Unit test for mdns_init");

    /* Comparing functions */
    TCase *TCase_mdns_record_cmp = tcase_create("Unit test for mdns_record_cmp");
    TCase *TCase_mdns_record_cmp_name_type = tcase_create("Unit test for mdns_record_cmp_name_type");
    TCase *TCase_mdns_cookie_cmp = tcase_create("Unit test for mdns_cookie_cmp");

    /* Cookie functions */
    TCase *TCase_mdns_cookie_delete = tcase_create("Unit test for mdns_cookie_delete");
    TCase *TCase_mdns_cookie_create = tcase_create("Unit test for mdns_cookie_create");
    TCase *TCase_mdns_cookie_tree_find_query_cookie = tcase_create("Unit test for mdns_cookie_tree_find_query_cookie");
    TCase *TCase_mdns_cookie_apply_spt = tcase_create("Unit test for mdns_cookie_apply_spt");
    TCase *TCase_mdns_is_suffix_present = tcase_create("Unit test for mdns_is_suffix_present");
	TCase *TCase_pico_itoa = tcase_create("Unit test for pico_itoa");
    TCase *TCase_mdns_resolve_name_conflict = tcase_create("Unit test for mdns_resolve_name_conflict");
    TCase *TCase_mdns_generate_new_records = tcase_create("Unit test for mdns_generate_new_records");
    TCase *TCase_mdns_cookie_resolve_conflict = tcase_create("Unit test for mdns_cookie_resolve_conflict");

    /* Question functions */
    TCase *TCase_mdns_question_create = tcase_create("Unit test for mdns_question_create");

    /* Record functions */
    TCase *TCase_mdns_record_resolve_conflict = tcase_create("Unit test for mdns_record_resolve_conflict");
    TCase *TCase_mdns_record_am_i_lexi_later = tcase_create("Unit test for mdns_record_am_i_lexi_later");
    TCase *TCase_mdns_record_create_from_dns = tcase_create("Unit test for mdns_recod_create_from_dns");
    TCase *TCase_mdns_record_copy_with_new_name = tcase_create("Unit test for mdns_record_copy");
    TCase *TCase_mdns_record_copy = tcase_create("Unit test for mdns_record_copy");
    TCase *TCase_mdns_record_create = tcase_create("Unit test for mdns_record_create");
    TCase *TCase_mdns_record_delete = tcase_create("Unit test for mdns_record_delete");


    /* Record tree functions */
    TCase *TCase_mdns_record_tree_find_name = tcase_create("Unit test for mdns_record_tree_find_name");
    TCase *TCase_mdns_record_tree_find_name_type = tcase_create("Unit test for mdns_record_tree_find_name_type");
    TCase *TCase_mdns_record_tree_del_name = tcase_create("Unit test for mdns_record_tree_del_name");
    TCase *TCase_mdns_record_tree_del_name_type = tcase_create("Unit test for mdns_record_tree_del_name_type");

    /* My record functions */
    TCase *TCase_mdns_my_records_add = tcase_create("Unit test for mdns_my_records_add");
    TCase *TCase_mdns_my_records_find_probed = tcase_create("Unit test for mdns_my_records_find_probed");
    TCase *TCase_mdns_my_records_find_to_probe = tcase_create("Unit test for mdns_my_records_find_to_probe");
    TCase *TCase_mdns_my_records_claimed_id = tcase_create("Unit test for mdns_my_records_claimed_id");
    TCase *TCase_mdns_my_records_claimed = tcase_create("Unit test for mdns_my_records_claimed");

    /* Cache functions */
    TCase *TCase_mdns_cache_add_record = tcase_create("Unit test for mdns_cache_add_record");
    TCase *TCase_mdns_cache_flush = tcase_create("Unit test for mdns_cache_flush");

	/* Handling receptions */
	TCase *TCase_mdns_populate_answer_vector = tcase_create("Unit test for mdns_populate_answer_vector");
    TCase *TCase_mdns_handle_data_as_questions = tcase_create("Unit test for mdns_handle_data_as_questions");
    TCase *TCase_mdns_handle_data_as_answers = tcase_create("Unit test for mdns_handle_data_as_answers");
    TCase *TCase_mdns_handle_data_as_authorities = tcase_create("Unit test for mdns_handle_data_as_authorities");
    TCase *TCase_mdns_handle_data_as_additionals = tcase_create("Unit test for mdns_handle_data_as_additionals");

    /* Handling query packets */
    TCase *TCase_mdns_sort_unicast_multicast = tcase_create("Unit test for mdns_sort_unicast_multicast");
	TCase *TCase_mdns_gather_additionals = tcase_create("Unit test for mdns_gather_additionals");
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
    tcase_add_test(TCase_mdns_record_cmp, tc_mdns_record_cmp);
    suite_add_tcase(s, TCase_mdns_record_cmp);
    tcase_add_test(TCase_mdns_record_cmp_name_type, tc_mdns_record_cmp_name_type);
    suite_add_tcase(s, TCase_mdns_record_cmp_name_type);
    tcase_add_test(TCase_mdns_cookie_cmp, tc_mdns_cookie_cmp);
    suite_add_tcase(s, TCase_mdns_cookie_cmp);

    /* Cookie functions */
    tcase_add_test(TCase_mdns_cookie_delete, tc_mdns_cookie_delete);
    suite_add_tcase(s, TCase_mdns_cookie_delete);
    tcase_add_test(TCase_mdns_cookie_create, tc_mdns_cookie_create);
    suite_add_tcase(s, TCase_mdns_cookie_create);
    tcase_add_test(TCase_mdns_cookie_tree_find_query_cookie, tc_mdns_cookie_tree_find_query_cookie);
    suite_add_tcase(s, TCase_mdns_cookie_tree_find_query_cookie);
    tcase_add_test(TCase_mdns_cookie_apply_spt, tc_mdns_cookie_apply_spt);
    suite_add_tcase(s, TCase_mdns_cookie_apply_spt);
    tcase_add_test(TCase_mdns_is_suffix_present, tc_mdns_is_suffix_present);
    suite_add_tcase(s, TCase_mdns_is_suffix_present);
	tcase_add_test(TCase_pico_itoa, tc_pico_itoa);
	suite_add_tcase(s, TCase_pico_itoa);
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

    /* Record tree functions */
    tcase_add_test(TCase_mdns_record_tree_find_name, tc_mdns_record_tree_find_name);
    suite_add_tcase(s, TCase_mdns_record_tree_find_name);
    tcase_add_test(TCase_mdns_record_tree_find_name_type, tc_mdns_record_tree_find_name_type);
    suite_add_tcase(s, TCase_mdns_record_tree_find_name_type);
    tcase_add_test(TCase_mdns_record_tree_del_name, tc_mdns_record_tree_del_name);
    suite_add_tcase(s, TCase_mdns_record_tree_del_name);
    tcase_add_test(TCase_mdns_record_tree_del_name_type, tc_mdns_record_tree_del_name_type);
    suite_add_tcase(s, TCase_mdns_record_tree_del_name_type);

	/* My records functions */
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
	tcase_add_test(TCase_mdns_gather_additionals, tc_mdns_gather_additionals);
	suite_add_tcase(s, TCase_mdns_gather_additionals);
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

