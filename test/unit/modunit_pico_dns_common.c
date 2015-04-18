#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_common.h"
#include "pico_tree.h"
#include "modules/pico_dns_common.c"
#include "check.h"

/* MARK: DNS packet section filling */
START_TEST(tc_pico_dns_fill_packet_header)
{
    struct pico_dns_header *header = NULL;
    uint8_t answer_buf[12] = { 0x00, 0x00,
                               0x84, 0x00,
                               0x00, 0x00,
                               0x00, 0x01,
                               0x00, 0x01,
                               0x00, 0x01 };
    uint8_t query_buf[12] = { 0x00, 0x00,
                              0x00, 0x00,
                              0x00, 0x01,
                              0x00, 0x01,
                              0x00, 0x01,
                              0x00, 0x01 };

    header = (struct pico_dns_header *)
                PICO_ZALLOC(sizeof(struct pico_dns_header));

    fail_if(NULL == header, "Not enough space!\n");

    /* Create a query header */
    pico_dns_fill_packet_header(header, 1, 1, 1, 1);

    fail_unless(0 == memcmp((void *)header, (void *)query_buf, 12),
                "Comparing query header failed!\n");

    /* Create a answer header */
    pico_dns_fill_packet_header(header, 0, 1, 1, 1);

    fail_unless(0 == memcmp((void *)header, (void *)answer_buf, 12),
                "Comparing answer header failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_rr_sections)
{
    pico_dns_packet *packet = NULL;
    pico_dns_question_vector qvector = {0};
    pico_dns_record_vector anvector = {0}, nsvector = {0}, arvector = {0};
    struct pico_dns_record *record = NULL;
    char *rname = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint8_t cmp_buf[39] = { 0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x07u, 'p','i','c','o','t','c','p',
                            0x03u, 'c','o','m',
                            0x00u,
                            0x00u, 0x01u,
                            0x00u, 0x01u,
                            0x00u, 0x00u, 0x00u, 0x78u,
                            0x00u, 0x04u,
                            10u, 10u, 0u, 1u};
    uint16_t len = 0;
    int ret = 0;

    /* Create a new A record */
    record = pico_dns_record_create(rname, rdata, &len, PICO_DNS_TYPE_A,
                                    PICO_DNS_CLASS_IN, 120);
    fail_if(!record, "dns_record_create failed!\n");

    pico_dns_record_vector_add(&anvector, record);

    /* Try to fill the rr sections with packet as a NULL-pointer */
    ret = pico_dns_fill_packet_rr_sections(packet, &qvector, &anvector,
                                           &nsvector, &arvector);
    fail_unless(ret, "Checking of params failed!\n");

    len = (uint16_t)sizeof(struct pico_dns_header);
    len = (uint16_t)(len + pico_dns_question_vector_size(&qvector));
    len = (uint16_t)(len + pico_dns_record_vector_size(&anvector));
    len = (uint16_t)(len + pico_dns_record_vector_size(&nsvector));
    len = (uint16_t)(len + pico_dns_record_vector_size(&arvector));

    /* Allocate the packet with the right size */
    packet = (pico_dns_packet *)PICO_ZALLOC((size_t)len);
    fail_if(NULL == packet, "Allocating packet failed!\n");
    fail_if(pico_dns_fill_packet_rr_sections(packet, &qvector, &anvector,
                                                 &nsvector, &arvector),
                "Filling of rr sections failed!\n");

    fail_unless(memcmp((void *)packet, (void *)cmp_buf, 39) == 0,
                "Filling of rr sections went wrong!\n");
    PICO_FREE(packet);
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_question_section)
{
    pico_dns_packet *packet = NULL;
    pico_dns_question_vector qvector = {0};
    struct pico_dns_question *a = NULL, *b = NULL;
    char *qurl = (char *)"picotcp.com";
    uint8_t cmp_buf[46] = { 0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x00u, 0x00u,
                            0x07u, 'p','i','c','o','t','c','p',
                            0x03u, 'c','o','m',
                            0x00u,
                            0x00u, 0x01u,
                            0x00u, 0x01u,
                            0x07u, 'p','i','c','o','t','c','p',
                            0x03u, 'c','o','m',
                            0x00u,
                            0x00u, 0x01u,
                            0x00u, 0x01u};
    uint16_t len = 0;

    /* Create DNS questions and a vector of them */
    a = pico_dns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(NULL == a, "dns_question_create failed!\n");
    pico_dns_question_vector_add(&qvector, a);
    b = pico_dns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(NULL == b, "dns_question_create failed!\n");
    pico_dns_question_vector_add(&qvector, b);

    /* Determine the length of the packet and provide space */
    len = (uint16_t)sizeof(struct pico_dns_header);
    len = (uint16_t)(len + pico_dns_question_vector_size(&qvector));
    packet = (pico_dns_packet *)PICO_ZALLOC((size_t)len);

    fail_if(NULL == packet, "Allocating packet failed!\n");
    fail_if(pico_dns_fill_packet_question_section(packet, &qvector),
            "Filling of rr sections failed!\n");

    fail_unless(memcmp((void *)packet, (void *)cmp_buf, 46) == 0,
                "Filling of question section went wrong!\n");
    PICO_FREE(packet);
}
END_TEST
/* MARK: DNS packet compression */
START_TEST(tc_pico_dns_packet_compress_find_ptr)
{
    uint8_t *data = "abcdef\5local\0abcdef\4test\5local";
    uint8_t *name = "\5local";
    uint16_t len = 31;
    uint8_t *ptr = NULL;

    ptr = pico_dns_packet_compress_find_ptr(name, data, len);
    fail_unless(ptr == (data + 6), "Finding compression ptr failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_packet_compress_name)
{
    uint8_t buf[46] = { 0x00u, 0x00u,
                        0x00u, 0x00u,
                        0x00u, 0x00u,
                        0x00u, 0x00u,
                        0x00u, 0x00u,
                        0x00u, 0x00u,
                        0x07u, 'p','i','c','o','t','c','p',
                        0x03u, 'c','o','m',
                        0x00u,
                        0x00u, 0x01u,
                        0x00u, 0x01u,
                        0x07u, 'p','i','c','o','t','c','p',
                        0x03u, 'c','o','m',
                        0x00u,
                        0x00u, 0x01u,
                        0x00u, 0x01u};

    uint8_t *name = buf + 29u;
    uint16_t len = 46;
    int ret = 0;
    ret = pico_dns_packet_compress_name(name, buf, &len);
    fail_unless(ret == 0, "dns_packet_compress_name returned error!\n");
    fail_unless(len == (46 - 11), "packet_compress_name return wrong length!\n");
    fail_unless(memcmp(name, "\xc0\x0c", 2) == 0, "packet_compress_name failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_packet_compress)
{
    uint8_t buf[46] = { 0x00u, 0x00u,
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
                        0x07u, 'p','i','c','o','t','c','p',
                        0x03u, 'c','o','m',
                        0x00u,
                        0x00u, 0x01u,
                        0x00u, 0x01u};
    uint8_t cmp_buf[35] = { 0x00u, 0x00u,
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
                            0xC0u, 0x0Cu,
                            0x00u, 0x01u,
                            0x00u, 0x01u};
    pico_dns_packet *packet = (pico_dns_packet *)buf;
    uint16_t len = 46;
    int ret = 0;

    ret = pico_dns_packet_compress(packet, &len);
    fail_unless(ret == 0, "dns_packet_compress returned error!\n");
    fail_unless(len == (46 - 11), "packet_compress returned length %u!\n", len);
    fail_unless(memcmp(buf, cmp_buf, 35) == 0, "packet_compress_name failed!\n");
}
END_TEST
/* MARK: DNS question functions */
START_TEST(tc_pico_dns_question_fill_qsuffix)
{
    struct pico_dns_question_suffix suffix;
    pico_dns_question_fill_qsuffix(&suffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);

    fail_unless((suffix.qtype == short_be(PICO_DNS_TYPE_A)) &&
                (suffix.qclass == short_be(PICO_DNS_CLASS_IN)),
                "Filling qsuffix failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_copy)
{
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    struct pico_dns_question *b = pico_dns_question_copy(a);

    fail_unless(strcmp(a->qname, b->qname) == 0,
                "qname isn't copied correctly!\n");
    fail_unless(a->qsuffix->qtype == b->qsuffix->qtype,
                "qtype isn't copied correctly!\n");
    fail_unless(a->qsuffix->qclass == b->qsuffix->qclass,
                "qclass isn't copied correctly!\n");
    fail_if(a == b, "pointers point to same struct!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_delete)
{
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    ret = pico_dns_question_delete(&a);

    fail_unless(ret == 0, "dns_question_delete returned error!\n");
    fail_unless(a == NULL, "dns_question_delete failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_create)
{
    char *qurl = (char *)"picotcp.com";
    char *qurl2 = (char *)"1.2.3.4";
    char *qurl3 = (char *)"2001:0db8:0000:0000:0000:0000:0000:0000";
    char buf[13] = { 0x07u, 'p','i','c','o','t','c','p',
                     0x03u, 'c','o','m',
                     0x00u };
    char buf2[22] = { 0x01u, '4',
                      0x01u, '3',
                      0x01u, '2',
                      0x01u, '1',
                      0x07u, 'i','n','-','a','d','d','r',
                      0x04u, 'a','r','p','a',
                      0x00u };
    char buf3[74] = { 0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
                      0x01u, '8', 0x01u, 'b', 0x01u, 'd', 0x01u, '0',
                      0x01u, '1', 0x01u, '0', 0x01u, '0', 0x01u, '2',
                      0x03u, 'I','P','6',
                      0x04u, 'A','R','P','A',
                      0x00u };
    uint16_t len = 0;

    /* First, plain A record */
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(a == NULL, "dns_question_created returned NULL!\n");
    fail_unless(strcmp(a->qname, buf) == 0, "url not converted correctly!\n");
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_A,
                "qtype not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass not properly set!\n");
    pico_dns_question_delete(&a);

    /* Reverse PTR record for IPv4 address */
    a = pico_dns_question_create(qurl2, &len, PICO_PROTO_IPV4,
                                 PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN, 1);
    fail_unless(strcmp(a->qname, buf2) == 0, "url2 not converted correctly!\n");
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_PTR,
                "qtype2 not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass2 not properly set!\n");
    pico_dns_question_delete(&a);

    /* Reverse PTR record for IPv6 address */
    a = pico_dns_question_create(qurl3, &len, PICO_PROTO_IPV6,
                                 PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN, 1);
    fail_unless(strcmp(a->qname, buf3) == 0, "url3 not converted correctly!\n");
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_PTR,
                "qtype3 not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass3 not properly set!\n");
    pico_dns_question_delete(&a);
}
END_TEST
/* MARK: DNS question vector functions */
START_TEST(tc_pico_dns_question_vector_init)
{
    pico_dns_question_vector qvector;

    pico_dns_question_vector_init(&qvector);
    fail_unless((qvector.questions == NULL &&
                 qvector.count == 0), "dns_question_vector_init failed!\n");

}
END_TEST
START_TEST(tc_pico_dns_question_vector_count)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;

    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");

    fail_unless(pico_dns_question_vector_count(&qvector) == 0,
                "question vector count should be 0\n");
    pico_dns_question_vector_add(&qvector, a);
    fail_unless(pico_dns_question_vector_count(&qvector) == 1,
                "question vector count should be 1\n");
    pico_dns_question_vector_delete(&qvector, 0);
    fail_unless(pico_dns_question_vector_count(&qvector) == 0,
                "question vector count should be 0\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_add)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;

    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");

    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    fail_unless(a == pico_dns_question_vector_get(&qvector, 0),
                "DNS question not added properly!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_add_copy)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;

    struct pico_dns_question *b = NULL,*a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");

    ret = pico_dns_question_vector_add_copy(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    fail_unless(a != (b = pico_dns_question_vector_get(&qvector, 0)),
                "Pointers point to same question struct!\n");
    fail_unless(strcmp(a->qname, b->qname) == 0,
                "qname isn't copied correctly!\n");
    fail_unless(a->qsuffix->qtype == b->qsuffix->qtype,
                "qtype isn't copied correctly!\n");
    fail_unless(a->qsuffix->qclass == b->qsuffix->qclass,
                "qclass isn't copied correctly!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_get)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *b = NULL;
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");

    b = pico_dns_question_vector_get(&qvector, 0);
    fail_unless(b == a, "dns_question_vector_get failed!\n");

    b = pico_dns_question_vector_get(&qvector, 1);
    fail_unless(b == NULL, "dns_question_vector_get OOB failed!\n");

    b = pico_dns_question_vector_get(NULL, 1);
    fail_unless(b == NULL, "dns_question_vector_get NULL-ptr failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_delete)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;

    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");

    ret = pico_dns_question_vector_delete(&qvector, 1);
    fail_unless(ret == -1, "dns_question_vector_delete OOB failed!\n");

    ret = pico_dns_question_vector_delete(&qvector, 0);
    fail_unless(ret == 0, "dns_question_vector_delete failed!\n");
    fail_unless(pico_dns_question_vector_count(&qvector) == 0,
                "dns_question_vector_delete failed with updating the count!\n");

    ret = pico_dns_question_vector_delete(NULL, 1);
    fail_unless(ret == -1, "dns_question_vector_delete NULL-ptr failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_destroy)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    uint16_t len = 0;
    int ret = 0;

    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!a, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, a);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    struct pico_dns_question *b = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(!b, "dns_question_create failed!\n");
    ret = pico_dns_question_vector_add(&qvector, b);
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");

    ret = pico_dns_question_vector_destroy(&qvector);
    fail_unless(pico_dns_question_vector_count(&qvector) == 0,
                "dns_question_vector_destroy failed!\n");
    fail_unless(qvector.questions == NULL,
                "dns_question_vector_destroy failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_find_name)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    char *qurl2 = (char *)"google.com";
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = NULL, *b = NULL, *c = NULL;

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

    c = pico_dns_question_vector_find_name(&qvector, "\6google\3com");
    fail_unless(c == b, "dns_question_vector_find_name failed!\n");

    c = pico_dns_question_vector_find_name(&qvector, "\4test\5local");
    fail_unless(c == NULL, "question_vector_find_name unkown name failed!\n");

    c = pico_dns_question_vector_find_name(&qvector, "\7picotcp\3com");
    fail_unless(c == a, "dns_question_vector_find_name failed!\n");

    c = pico_dns_question_vector_find_name(NULL, "\4test\5local");
    fail_unless(c == NULL, "question_vector_find_name check params failed!\n");

    c = pico_dns_question_vector_find_name(&qvector, NULL);
    fail_unless(c == NULL, "question_vector_find_name check params failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_question_vector_size)
{
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    char *qurl2 = (char *)"google.com";
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = NULL, *b = NULL;

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

    len = pico_dns_question_vector_size(&qvector);
    fail_unless(len == (17 + 16),
                "dns_question_vector_size failed!\n");
    len = pico_dns_question_vector_size(NULL);
    fail_unless(len == 0,
                "dns_question_vector_size NULL-ptr failed!\n");

    /* FREE memory */
    pico_dns_question_delete(&a);
    pico_dns_question_delete(&b);
}
END_TEST
/* MARK: DNS query packet creation */
START_TEST(tc_pico_dns_query_create)
{
    pico_dns_packet *packet = NULL;
    pico_dns_question_vector qvector = { 0 };
    char *qurl = (char *)"picotcp.com";
    char *qurl2 = (char *)"google.com";
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
    fail_if(packet == NULL, "dns_query_create returned NULL!\n");
    fail_unless(memcmp(buf, (void *)packet, 42),
                "dns_query_created failed!\n");
}
END_TEST
/* MARK: DNS resource record functions */
START_TEST(tc_pico_dns_record_fill_suffix)
{
    struct pico_dns_record_suffix suffix;
    pico_dns_record_fill_suffix(&suffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN,
                                120, 4);

    fail_unless((suffix.rtype == short_be(PICO_DNS_TYPE_A) &&
                suffix.rclass == short_be(PICO_DNS_CLASS_IN) &&
                suffix.rttl == long_be(120) &&
                suffix.rdlength == short_be(4)),
                "Filling rsuffix failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_record_copy_flat)
{
    struct pico_dns_record *record = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint8_t buf[128] = { 0 };
    uint8_t ptr = NULL;
    uint8_t cmp_buf[27] = { 0x07, 'p','i','c','o','t','c','p',
                            0x03, 'c','o','m',
                            0x00,
                            0x00, 0x01,
                            0x00, 0x01,
                            0x00, 0x00, 0x00, 0x78,
                            0x00, 0x04,
                            0x0A, 0x0A, 0x00, 0x01};
    uint16_t len = 0;
    int ret = 0;

    record = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                                    PICO_DNS_CLASS_IN, 120);
    fail_if(!record, "dns_record_create failed!\n");

    ptr = buf + 20;

    /* Try to copy the record to a flat buffer */
    ret = pico_dns_record_copy_flat(record, &ptr);

    fail_unless(ret == 0, "dns_record_copy_flat returned error!\n");
    fail_unless(memcmp(buf + 20, cmp_buf, 27) == 0,
                "dns_record_copy_flat failed!\n");

    /* FREE memory */
    pico_dns_record_delete(&record);
}
END_TEST
START_TEST(tc_pico_dns_record_copy)
{
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                                    PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create failed!\n");

    /* Try to copy the first DNS record */
    b = pico_dns_record_copy(a);
    fail_unless(b != NULL, "dns_record_copy returned NULL!\n");
    fail_unless(a != b, "pointers point to same struct!\n");
    fail_unless(strcmp(a->rname, b->rname) == 0,
                "dns_record_copy failed copying names!\n");
    fail_unless(a->rsuffix->rtype == b->rsuffix->rtype,
                "dns_record_copy failed copying rtype!\n");
    fail_unless(a->rsuffix->rclass == b->rsuffix->rclass,
                "dns_record_copy failed copying rclass!\n");
    fail_unless(a->rsuffix->rttl == b->rsuffix->rttl,
                "dns_record_copy failed copying rttl!\n");
    fail_unless(a->rsuffix->rdlength == b->rsuffix->rdlength,
                "dns_record_copy failed copying rdlenth!\n");
    fail_unless(memcmp(a->rdata, b->rdata, short_be(b->rsuffix->rdlength)) == 0,
                "dns_record_copy failed copying rdata!\n");

    /* FREE memory */
    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);
}
END_TEST
START_TEST(tc_pico_dns_record_delete)
{
    struct pico_dns_record *a = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create failed!\n");

    /* Try to delete the created record */
    ret = pico_dns_record_delete(&a);
    fail_unless(ret == 0, "pico_dns_record_delete returned NULL!\n");
    fail_unless(a == NULL, "pico_dns_record_delete failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_record_create)
{
    struct pico_dns_record *a = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    fail_unless(strcmp(a->rname, "\x7picotcp\x3com"),
                "dns_record_create didn't convert url %s properly!\n",
                a->rname);
    fail_unless(a->rsuffix->rtype == short_be(PICO_DNS_TYPE_A),
                "dns_record_create failed setting rtype!\n");
    fail_unless(a->rsuffix->rclass == short_be(PICO_DNS_CLASS_IN),
                "dns_record_create failed setting rclass!\n");
    fail_unless(a->rsuffix->rttl == long_be(120),
                "dns_record_create failed setting rttl!\n");
    fail_unless(a->rsuffix->rdlength == short_be(4),
                "dns_record_create failed setting rdlenth!\n");
    fail_unless(memcmp(a->rdata, rdata, 4) == 0,
                "dns_record_create failed setting rdata!\n");

    pico_dns_record_delete(&a);
}
END_TEST
/* MARK: DNS record vector functions */
START_TEST(tc_pico_dns_record_vector_init)
{
    pico_dns_record_vector rvector;

    pico_dns_record_vector_init(&rvector);
    fail_unless((rvector.records == NULL &&
                 rvector.count == 0), "dns_record_vector_init failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_record_vector_count)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    fail_unless(pico_dns_record_vector_count(&rvector) == 0,
                "question vector count should be 0\n");
    pico_dns_question_vector_add(&rvector, a);
    fail_unless(pico_dns_record_vector_count(&rvector) == 1,
                "question vector count should be 1\n");
    pico_dns_question_vector_delete(&rvector, 0);
    fail_unless(pico_dns_record_vector_count(&rvector) == 0,
                "question vector count should be 0\n");
}
END_TEST
START_TEST(tc_pico_dns_record_vector_add)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    fail_unless(a == pico_dns_record_vector_get(&rvector, 0),
                "DNS record not added properly!\n");
}
END_TEST
START_TEST(tc_pico_dns_record_vector_add_copy)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    /* Try to add copy of record to vector */
    ret = pico_dns_record_vector_add_copy(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    fail_unless(a != (b = pico_dns_record_vector_get(&rvector, 0)),
                "Pointers point to same record struct!\n");
    fail_unless(strcmp(a->rname, b->rname) == 0,
                "rname isn't copied correctly!\n");
    fail_unless(a->rsuffix->rtype == b->rsuffix->rtype,
                "rtype isn't copied correctly!\n");
    fail_unless(a->rsuffix->rclass == b->rsuffix->rclass,
                "rclass isn't copied correctly!\n");
    fail_unless(a->rsuffix->rttl == b->rsuffix->rttl,
                "rttl isn't copied correctly!\n");
    fail_unless(a->rsuffix->rdlength == b->rsuffix->rdlength,
                "rdlength isn't copied correctly!\n");
    fail_unless(memcmp(a->rdata, b->rdata, short_be(b->rsuffix->rdlength)) == 0,
                "rdata isn't copied correctly!\n");

    /* FREE memory */
    pico_dns_record_delete(&a);
}
END_TEST
START_TEST(tc_pico_dns_record_vector_get)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    b = pico_dns_record_vector_get(&rvector, 0);
    fail_unless(b == a, "dns_record_vector_get failed!\n");

    b = pico_dns_record_vector_get(&rvector, 1);
    fail_unless(b == NULL, "dns_record_vector_get OOB failed!\n");

    b = pico_dns_record_vector_get(NULL, 1);
    fail_unless(b == NULL, "dns_record_vector_get NULL-ptr failed!\n");

    /* FREE memory */
    pico_dns_record_delete(&a);
}
END_TEST
START_TEST(tc_pico_dns_record_vector_delete)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    ret = pico_dns_record_vector_delete(&rvector, 1);
    fail_unless(ret == -1, "dns_record_vector_delete OOB failed!\n");

    ret = pico_dns_record_vector_delete(&rvector, 0);
    fail_unless(ret == 0, "dns_record_vector_delete failed!\n");
    fail_unless(pico_dns_record_vector_count(&rvector) == 0,
                "dns_record_vector_delete failed with updating the count!\n");

    ret = pico_dns_record_vector_delete(NULL, 1);
    fail_unless(ret == -1, "dns_record_vector_delete NULL-ptr failed!\n");
}
END_TEST
START_TEST(tc_pico_dns_record_vector_destroy)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    /* Try to destroy the entire contents of the vector */
    ret = pico_dns_record_vector_destroy(&rvector);
    fail_unless(ret == 0, "dns_record_vector_destroy returned error!\n");
    fail_unless((rvector.records == NULL &&
                 rvector.count == 0), "dns_record_vector_destroy failed!\n");

    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);
}
END_TEST
START_TEST(tc_pico_dns_record_vector_size)
{
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    uint8_t rdata[4] = { 10, 10, 0, 1 };
    uint16_t len = 0, i = 0;
    int ret = 0;

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    len = pico_dns_record_vector_size(&rvector);
    fail_unless(len == (27 + 27),
                "dns_record_vector_size failed!\n");
    len = pico_dns_record_vector_size(NULL);
    fail_unless(len == 0,
                "dns_record_vector_size NULL-ptr failed!\n");

    /* FREE memory */
    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);
}
END_TEST
/* MARK: DNS answer packet creation */
START_TEST(tc_pico_dns_answer_create)
{
    pico_dns_packet *packet = NULL;
    pico_dns_record_vector rvector = { 0 };
    struct pico_dns_record *a = NULL, *b = NULL;
    char *url = (char *)"picotcp.com";
    char *url2 = (char *)"google.com";
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

    a = pico_dns_record_create(url, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_dns_record_create(url2, (void *)rdata, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    ret = pico_dns_record_vector_add(&rvector, a);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");
    ret = pico_dns_record_vector_add(&rvector, b);
    fail_unless(ret == 0, "dns_record_vector_add returned error!\n");

    /* Try to create an answer packet */
    packet = pico_dns_answer_create(&rvector, NULL, NULL, &len);
    fail_if (packet == NULL, "dns_answer_create returned NULL!\n");
    fail_unless(memcmp((void *)packet, (void *)buf, 62) == 0,
                "dns_answer_create failed!\n");
}
END_TEST
/* MARK: Name conversion and compression functions */
START_TEST(tc_pico_dns_namelen_comp)
{
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_dns_namelen_comp(name);
    fail_unless(ret == 12, "Namelength is wrong!\n");

    /* name with compression */
    ret = pico_dns_namelen_comp(name_comp);
    fail_unless(ret == 13, "Namelength is wrong!\n");
}
END_TEST
START_TEST(tc_pico_dns_namelen_uncomp)
{
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    char name_comp2[] = "\xc0\x00";
    char buf[] = "00\5index\0";
    unsigned int ret = 0;

    /* name without compression */
    ret = pico_dns_namelen_uncomp(name, (pico_dns_packet *)buf);
    fail_unless(ret == 12, "Namelength '%d' is wrong with no pointer!\n", ret);
    /* name with compression */
    ret = pico_dns_namelen_uncomp(name_comp, (pico_dns_packet *)buf);
    fail_unless(ret == 18, "Namelength '%d' is wrong with pointer!\n", ret);

    /* name with compression, but with name as 'buf' */
    ret = pico_dns_namelen_uncomp(name_comp2, (pico_dns_packet *)name);
    fail_unless(ret == 12, "Namelength '%d' is wrong with only pointer!\n", ret);
}
END_TEST
START_TEST(tc_pico_dns_decompress_name)
{
    char name[] = "\4mail\xc0\x02";
    char name2[] = "\xc0\x02";
    char buf[] = "00\6google\3com";
    char *ret;

    /* Test normal DNS name compression */
    ret = pico_dns_decompress_name(name, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, "\4mail\6google\3com") == 0, "Not correctly decompressed: '%s'!\n", ret);

    /* Free memory */
    PICO_FREE(ret);
    ret = NULL;

    /* Test when there is only a pointer */
    ret = pico_dns_decompress_name(name2, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, "\6google\3com") == 0, "Not correctly decompressed: '%s'!\n", ret);

    /* Free memory */
    PICO_FREE(ret);
    ret = NULL;
}
END_TEST
START_TEST(tc_pico_dns_url_get_reverse_len)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_url_to_reverse_qname)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_qname_to_url)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_url_to_qname)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_name_to_dns_notation)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_notation_to_name)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_mirror_addr)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_dns_ptr_ip6_nibble_lo)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_dns_ptr_ip6_nibble_hi)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_ipv6_set_ptr)
{
    /* TODO: Write test */
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    /* DNS packet section filling */
    TCase *TCase_pico_dns_fill_packet_header = tcase_create("Unit test for 'pico_dns_fill_packet_header'");
    TCase *TCase_pico_dns_fill_packet_rr_sections = tcase_create("Unit test for 'pico_dns_fill_packet_rr_sections'");
    TCase *TCase_pico_dns_fill_packet_question_section = tcase_create("Unit test for 'pico_dns_fill_packet_question_sections'");

    /* DNS packet compression */
    TCase *TCase_pico_dns_packet_compress_find_ptr = tcase_create("Unit test for 'pico_dns_packet_compress_find_ptr'");
    TCase *TCase_pico_dns_packet_compress_name = tcase_create("Unit test for 'pico_dns_packet_compress_name'");
    TCase *TCase_pico_dns_packet_compress = tcase_create("Unit test for 'pico_dns_packet_compress'");

    /* DNS question functions */
    TCase *TCase_pico_dns_question_fill_qsuffix = tcase_create("Unit test for 'pico_dns_question_fill_qsuffix'");
    TCase *TCase_pico_dns_question_copy = tcase_create("Unit test for 'pico_dns_question_copy'");
    TCase *TCase_pico_dns_question_delete = tcase_create("Unit test for 'pico_dns_question_delete'");
    TCase *TCase_pico_dns_question_create = tcase_create("Unit test for 'pico_dns_question_create'");

    /* DNS question vector functions */
    TCase *TCase_pico_dns_question_vector_init = tcase_create("Unit test for 'pico_dns_question_vector_init'");
    TCase *TCase_pico_dns_question_vector_count = tcase_create("Unit test for 'pico_dns_question_vector_count'");
    TCase *TCase_pico_dns_question_vector_add = tcase_create("Unit test for 'pico_dns_question_vector_add'");
    TCase *TCase_pico_dns_question_vector_add_copy = tcase_create("Unit test for 'pico_dns_question_vector_add_copy'");
    TCase *TCase_pico_dns_question_vector_get = tcase_create("Unit test for 'pico_dns_question_vector_get'");
    TCase *TCase_pico_dns_question_vector_delete = tcase_create("Unit test for 'pico_dns_question_vector_delete'");
    TCase *TCase_pico_dns_question_vector_destroy = tcase_create("Unit test for 'pico_dns_question_vector_destroy'");
    TCase *TCase_pico_dns_question_vector_find_name = tcase_create("Unit test for 'pico_dns_question_vector_find_name'");
    TCase *TCase_pico_dns_question_vector_size = tcase_create("Unit test for 'pico_dns_question_vector_size'");

    /* DNS query packet creation */
    TCase *TCase_pico_dns_query_create = tcase_create("Unit test for 'pico_dns_query_create'");

    /* DNS resource record functions */
    TCase *TCase_pico_dns_record_fill_suffix = tcase_create("Unit test for 'pico_dns_record_fill_suffix'");
    TCase *TCase_pico_dns_record_copy_flat = tcase_create("Unit test for 'pico_dns_record_copy_flat'");
    TCase *TCase_pico_dns_record_copy = tcase_create("Unit test for 'pico_dns_record_copy'");
    TCase *TCase_pico_dns_record_delete = tcase_create("Unit test for 'pico_dns_record_delete'");
    TCase *TCAse_pico_dns_record_create = tcase_create("Unit test for 'pico_dns_record_create'");

    /* DNS record vector funcitons */
    TCase *TCase_pico_dns_record_vector_init = tcase_create("Unit test for 'pico_dns_record_vector_init'");
    TCase *TCase_pico_dns_record_vector_count = tcase_create("Unit test for 'pico_dns_record_vector_count'");
    TCase *TCase_pico_dns_record_vector_add = tcase_create("Unit test for 'pico_dns_record_vector_add'");
    TCase *TCase_pico_dns_record_vector_add_copy = tcase_create("Unit test for 'pico_dns_record_vector_add_copy'");
    TCase *TCase_pico_dns_record_vector_get = tcase_create("Unit test for 'pico_dns_record_vector_get'");
    TCase *TCase_pico_dns_record_vector_delete = tcase_create("Unit test for 'pico_dns_record_vector_delete'");
    TCase *TCase_pico_dns_record_vector_destroy = tcase_create("Unit test for 'pico_dns_record_vector_destroy'");
    TCase *TCase_pico_dns_record_vector_size = tcase_create("Unit test for 'pico_dns_record_vector_size'");

    /* DNS answer packet creation */
    TCase *TCase_pico_dns_answer_create = tcase_create("Unit test for 'pico_dns_answer_create'");

    /* Name conversion and compression function */
    TCase *TCase_pico_dns_namelen_comp = tcase_create("Unit test for 'pico_dns_namelen_comp'");
    TCase *TCase_pico_dns_namelen_uncomp = tcase_create("Unit test for 'pico_dns_namelen_uncomp'");
    TCase *TCase_pico_dns_decompress_name = tcase_create("Unit test for 'pico_dns_decompress_name'");
    TCase *TCase_pico_dns_url_get_reverse_len = tcase_create("Unit test for 'pico_dns_url_get_reverse_len'");
    TCase *TCase_pico_dns_url_to_reverse_qname = tcase_create("Unit test for 'pico_dns_url_to_reverse_qname'");
    TCase *TCase_pico_dns_qname_to_url = tcase_create("Unit test for 'pico_dns_qname_to_url'");
    TCase *TCase_pico_dns_url_to_qname = tcase_create("Unit test for 'pico_dns_url_to_qname'");
    TCase *TCase_pico_dns_name_to_dns_notation = tcase_create("Unit test for 'pico_dns_name_to_dns_notation'");
    TCase *TCase_pico_dns_notation_to_name = tcase_create("Unit test for 'pico_dns_notation_to_name'");
    TCase *TCase_pico_dns_mirror_addr = tcase_create("Unit test for 'pico_dns_mirror_addr'");
    TCase *TCase_dns_ptr_ip6_nibble_lo = tcase_create("Unit test for 'dns_ptr_ip6_nibble_lo'");
    TCase *TCase_dns_ptr_ip6_nibble_hi = tcase_create("Unit test for 'dns_ptr_ip6_nibble_hi'");
    TCase *TCase_pico_dns_ipv6_set_ptr = tcase_create("Unit test for 'pico_dns_ipv6_set_ptr'");

    tcase_add_test(TCase_pico_dns_fill_packet_header, tc_pico_dns_fill_packet_header);
    tcase_add_test(TCase_pico_dns_fill_packet_rr_sections, tc_pico_dns_fill_packet_rr_sections);
    tcase_add_test(TCase_pico_dns_fill_packet_question_section, tc_pico_dns_fill_packet_question_section);
    tcase_add_test(TCase_pico_dns_packet_compress_find_ptr, tc_pico_dns_packet_compress_find_ptr);
    tcase_add_test(TCase_pico_dns_packet_compress_name, tc_pico_dns_packet_compress_name);
    tcase_add_test(TCase_pico_dns_packet_compress, tc_pico_dns_packet_compress);
    tcase_add_test(TCase_pico_dns_question_fill_qsuffix, tc_pico_dns_question_fill_qsuffix);
    tcase_add_test(TCase_pico_dns_question_copy, tc_pico_dns_question_copy);
    tcase_add_test(TCase_pico_dns_question_delete, tc_pico_dns_question_delete);
    tcase_add_test(TCase_pico_dns_question_create, tc_pico_dns_question_create);
    tcase_add_test(TCase_pico_dns_question_vector_init, tc_pico_dns_question_vector_init);
    tcase_add_test(TCase_pico_dns_question_vector_count, tc_pico_dns_question_vector_count);
    tcase_add_test(TCase_pico_dns_question_vector_add, tc_pico_dns_question_vector_add);
    tcase_add_test(TCase_pico_dns_question_vector_add_copy, tc_pico_dns_question_vector_add_copy);
    tcase_add_test(TCase_pico_dns_question_vector_get, tc_pico_dns_question_vector_get);
    tcase_add_test(TCase_pico_dns_question_vector_delete, tc_pico_dns_question_vector_delete);
    tcase_add_test(TCase_pico_dns_question_vector_destroy, tc_pico_dns_question_vector_destroy);
    tcase_add_test(TCase_pico_dns_question_vector_find_name, tc_pico_dns_question_vector_find_name);
    tcase_add_test(TCase_pico_dns_question_vector_size, tc_pico_dns_question_vector_size);
    tcase_add_test(TCase_pico_dns_query_create, tc_pico_dns_query_create);
    tcase_add_test(TCase_pico_dns_record_fill_suffix, tc_pico_dns_record_fill_suffix);
    tcase_add_test(TCase_pico_dns_record_copy_flat, tc_pico_dns_record_copy_flat);
    tcase_add_test(TCase_pico_dns_record_copy, tc_pico_dns_record_copy);
    tcase_add_test(TCase_pico_dns_record_delete, tc_pico_dns_record_delete);
    tcase_add_test(TCAse_pico_dns_record_create, tc_pico_dns_record_create);
    tcase_add_test(TCase_pico_dns_record_vector_init, tc_pico_dns_record_vector_init);
    tcase_add_test(TCase_pico_dns_record_vector_count, tc_pico_dns_record_vector_count);
    tcase_add_test(TCase_pico_dns_record_vector_add, tc_pico_dns_record_vector_add);
    tcase_add_test(TCase_pico_dns_record_vector_add_copy, tc_pico_dns_record_vector_add_copy);
    tcase_add_test(TCase_pico_dns_record_vector_get, tc_pico_dns_record_vector_get);
    tcase_add_test(TCase_pico_dns_record_vector_delete, tc_pico_dns_record_vector_delete);
    tcase_add_test(TCase_pico_dns_record_vector_destroy, tc_pico_dns_record_vector_destroy);
    tcase_add_test(TCase_pico_dns_record_vector_size, tc_pico_dns_record_vector_size);
    tcase_add_test(TCase_pico_dns_answer_create, tc_pico_dns_answer_create);
    tcase_add_test(TCase_pico_dns_namelen_comp, tc_pico_dns_namelen_comp);
    tcase_add_test(TCase_pico_dns_namelen_uncomp, tc_pico_dns_namelen_uncomp);
    tcase_add_test(TCase_pico_dns_decompress_name, tc_pico_dns_decompress_name);
    tcase_add_test(TCase_pico_dns_url_get_reverse_len, tc_pico_dns_url_get_reverse_len);
    tcase_add_test(TCase_pico_dns_url_to_reverse_qname, tc_pico_dns_url_to_reverse_qname);
    tcase_add_test(TCase_pico_dns_qname_to_url, tc_pico_dns_qname_to_url);
    tcase_add_test(TCase_pico_dns_url_to_qname, tc_pico_dns_url_to_qname);
    tcase_add_test(TCase_pico_dns_name_to_dns_notation, tc_pico_dns_name_to_dns_notation);
    tcase_add_test(TCase_pico_dns_notation_to_name, tc_pico_dns_notation_to_name);
    tcase_add_test(TCase_pico_dns_mirror_addr, tc_pico_dns_mirror_addr);
    tcase_add_test(TCase_dns_ptr_ip6_nibble_lo, tc_dns_ptr_ip6_nibble_lo);
    tcase_add_test(TCase_dns_ptr_ip6_nibble_hi, tc_dns_ptr_ip6_nibble_hi);
    tcase_add_test(TCase_pico_dns_ipv6_set_ptr, tc_pico_dns_ipv6_set_ptr);

    suite_add_tcase(s, TCase_pico_dns_fill_packet_header);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_rr_sections);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_question_section);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_find_ptr);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_name);
    suite_add_tcase(s, TCase_pico_dns_packet_compress);
    suite_add_tcase(s, TCase_pico_dns_question_fill_qsuffix);
    suite_add_tcase(s, TCase_pico_dns_question_copy);
    suite_add_tcase(s, TCase_pico_dns_question_delete);
    suite_add_tcase(s, TCase_pico_dns_question_create);
    suite_add_tcase(s, TCase_pico_dns_question_vector_init);
    suite_add_tcase(s, TCase_pico_dns_question_vector_count);
    suite_add_tcase(s, TCase_pico_dns_question_vector_add);
    suite_add_tcase(s, TCase_pico_dns_question_vector_add_copy);
    suite_add_tcase(s, TCase_pico_dns_question_vector_get);
    suite_add_tcase(s, TCase_pico_dns_question_vector_delete);
    suite_add_tcase(s, TCase_pico_dns_question_vector_destroy);
    suite_add_tcase(s, TCase_pico_dns_question_vector_find_name);
    suite_add_tcase(s, TCase_pico_dns_question_vector_size);
    suite_add_tcase(s, TCase_pico_dns_query_create);
    suite_add_tcase(s, TCase_pico_dns_record_fill_suffix);
    suite_add_tcase(s, TCase_pico_dns_record_copy);
    suite_add_tcase(s, TCase_pico_dns_record_delete);
    suite_add_tcase(s, TCAse_pico_dns_record_create);
    suite_add_tcase(s, TCase_pico_dns_record_vector_init);
    suite_add_tcase(s, TCase_pico_dns_record_vector_count);
    suite_add_tcase(s, TCase_pico_dns_record_vector_add);
    suite_add_tcase(s, TCase_pico_dns_record_vector_add_copy);
    suite_add_tcase(s, TCase_pico_dns_record_vector_get);
    suite_add_tcase(s, TCase_pico_dns_record_vector_delete);
    suite_add_tcase(s, TCase_pico_dns_record_vector_destroy);
    suite_add_tcase(s, TCase_pico_dns_record_vector_size);
    suite_add_tcase(s, TCase_pico_dns_answer_create);
    suite_add_tcase(s, TCase_pico_dns_namelen_comp);
    suite_add_tcase(s, TCase_pico_dns_namelen_uncomp);
    suite_add_tcase(s, TCase_pico_dns_decompress_name);
    suite_add_tcase(s, TCase_pico_dns_url_get_reverse_len);
    suite_add_tcase(s, TCase_pico_dns_url_to_reverse_qname);
    suite_add_tcase(s, TCase_pico_dns_qname_to_url);
    suite_add_tcase(s, TCase_pico_dns_url_to_qname);
    suite_add_tcase(s, TCase_pico_dns_name_to_dns_notation);
    suite_add_tcase(s, TCase_pico_dns_notation_to_name);
    suite_add_tcase(s, TCase_pico_dns_mirror_addr);
    suite_add_tcase(s, TCase_dns_ptr_ip6_nibble_lo);
    suite_add_tcase(s, TCase_dns_ptr_ip6_nibble_hi);
    suite_add_tcase(s, TCase_pico_dns_ipv6_set_ptr);

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

