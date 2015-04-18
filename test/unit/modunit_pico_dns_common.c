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
    int ret = 0;

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
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_question_section)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS packet compression */
START_TEST(tc_pico_dns_packet_compress_find_ptr)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_packet_compress_name)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_packet_compress)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS question functions */
START_TEST(tc_pico_dns_question_fill_qsuffix)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_copy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_delete)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_create)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS question vector functions */
START_TEST(tc_pico_dns_question_vector_init)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_count)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_add)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_add_copy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_get)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_delete)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_destroy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_find_name)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_question_vector_size)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS query packet creation */
START_TEST(tc_pico_dns_query_create)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS resource record functions */
START_TEST(tc_pico_dns_record_fill_suffix)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_copy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_delete)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_create)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS record vector functions */
START_TEST(tc_pico_dns_record_vector_init)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_count)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_add)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_add_copy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_get)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_delete)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_destroy)
{
    /* TODO: Write test */
}
END_TEST
START_TEST(tc_pico_dns_record_vector_size)
{
    /* TODO: Write test */
}
END_TEST
/* MARK: DNS answer packet creation */
START_TEST(tc_pico_dns_answer_create)
{
    /* TODO: Write test */
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
START_TEST(tc_pico_dns_expand_name_comp)
{
    char name[] = "\4mail\xc0\x02";
    char name2[] = "\xc0\x02";
    char buf[] = "00\6google\3com";
    char *ret;

    /* Test normal DNS name compression */
    ret = pico_dns_expand_name_comp(name, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, ".mail.google.com") == 0, "Not correctly decompressed: '%s'!\n", ret);

    /* Free memory */
    PICO_FREE(ret);
    ret = NULL;

    /* Test when there is only a pointer */
    ret = pico_dns_expand_name_comp(name2, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, ".google.com") == 0, "Not correctly decompressed: '%s'!\n", ret);

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
    TCase *TCase_pico_dns_fill_packet_question_section = tcase_create("Unit test for 'pico_dns_packet_question_sections'");

    tcase_add_test(TCase_pico_dns_fill_packet_header, tc_pico_dns_fill_packet_header);
    tcase_add_test(TCase_pico_dns_fill_packet_rr_sections, tc_pico_dns_fill_packet_rr_sections);
    tcase_add_test(TCase_pico_dns_fill_packet_question_section, tc_pico_dns_fill_packet_question_section);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_header);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_rr_sections);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_question_section);

    /* DNS packet compression */
    TCase *TCase_pico_dns_packet_compress_find_ptr("Unit test for 'pico_dns_packet_compress_find_ptr'");
    TCase *TCase_pico_dns_packet_compress_name("Unit test for 'pico_dns_packet_compress_name'");
    TCase *TCase_pico_dns_packet_compress("Unit test for 'pico_dns_packet_compress'");

    tcase_add_test(TCase_pico_dns_packet_compress_find_ptr, tc_pico_dns_packet_compress_find_ptr);
    tcase_add_test(TCase_pico_dns_packet_compress_name, tc_pico_dns_packet_compress_name);
    tcase_add_test(TCase_pico_dns_packet_compress, tc_pico_dns_packet_compress);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_find_ptr);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_name);
    suite_add_tcase(s, TCase_pico_dns_packet_compress);

    /* DNS question functions */
    TCase *TCase_pico_dns_question_fill_qsuffix("Unit test for 'pico_dns_question_fill_qsuffix'");
    TCase *TCase_pico_dns_question_copy("Unit test for 'pico_dns_question_copy'");
    TCase *TCase_pico_dns_question_delete("Unit test for 'pico_dns_question_delete'");
    TCase *TCase_pico_dns_question_create("Unit test for 'pico_dns_question_create'");

    tcase_add_test(TCase_pico_dns_question_fill_qsuffix, tc_pico_dns_question_fill_qsuffix);
    tcase_add_test(TCase_pico_dns_question_copy, tc_pico_dns_question_copy);
    tcase_add_test(TCase_pico_dns_question_delete, tc_pico_dns_question_delete);
    tcase_add_test(TCase_pico_dns_question_create, tc_pico_dns_question_create);
    suite_add_tcase(s, TCase_pico_dns_question_fill_qsuffix);
    suite_add_tcase(s, TCase_pico_dns_question_copy);
    suite_add_tcase(s, TCase_pico_dns_question_delete);
    suite_add_tcase(s, TCase_pico_dns_question_create);

    /* DNS question vector functions */
    TCase *TCase_pico_dns_question_vector_init("Unit test for 'pico_dns_question_vector_init'");
    TCase *TCase_pico_dns_question_vector_count("Unit test for 'pico_dns_question_vector_count'");
    TCase *TCase_pico_dns_question_vector_add("Unit test for 'pico_dns_question_vector_add'");
    TCase *TCase_pico_dns_question_vector_add_copy("Unit test for 'pico_dns_question_vector_add_copy'");
    TCase *TCase_pico_dns_question_vector_get("Unit test for 'pico_dns_question_vector_get'");
    TCase *TCase_pico_dns_question_vector_delete("Unit test for 'pico_dns_question_vector_delete'");
    TCase *TCase_pico_dns_question_vector_destroy("Unit test for 'pico_dns_question_vector_destroy'");
    TCase *TCase_pico_dns_question_vector_find_name("Unit test for 'pico_dns_question_vector_find_name'");
    TCase *TCase_pico_dns_question_vector_size("Unit test for 'pico_dns_question_vector_size'");

    tcase_add_test(TCase_pico_dns_question_vector_init, tc_pico_dns_question_vector_init);
    tcase_add_test(TCase_pico_dns_question_vector_count, tc_pico_dns_question_vector_count);
    tcase_add_test(TCase_pico_dns_question_vector_add, tc_pico_dns_question_vector_add);
    tcase_add_test(TCase_pico_dns_question_vector_add_copy, tc_pico_dns_question_vector_add_copy);
    tcase_add_test(TCase_pico_dns_question_vector_get, tc_pico_dns_question_vector_get);
    tcase_add_test(TCase_pico_dns_question_vector_delete, tc_pico_dns_question_vector_delete);
    tcase_add_test(TCase_pico_dns_question_vector_destroy, tc_pico_dns_question_vector_destroy);
    tcase_add_test(TCase_pico_dns_question_vector_find_name, tc_pico_dns_question_vector_find_name);
    tcase_add_test(TCase_pico_dns_question_vector_size, tc_pico_dns_question_vector_size);
    suite_add_tcase(s, TCase_pico_dns_question_vector_init);
    suite_add_tcase(s, TCase_pico_dns_question_vector_count);
    suite_add_tcase(s, TCase_pico_dns_question_vector_add);
    suite_add_tcase(s, TCase_pico_dns_question_vector_add_copy);
    suite_add_tcase(s, TCase_pico_dns_question_vector_get);
    suite_add_tcase(s, TCase_pico_dns_question_vector_delete);
    suite_add_tcase(s, TCase_pico_dns_question_vector_destroy);
    suite_add_tcase(s, TCase_pico_dns_question_vector_find_name);
    suite_add_tcase(s, TCase_pico_dns_question_vector_size);

    /* DNS query packet creation */
    TCase *TCase_pico_dns_query_create("Unit test for 'pico_dns_query_create'");

    tcase_add_test(TCase_pico_dns_query_create, tc_pico_dns_query_create);
    suite_add_tcase(s, TCase_pico_dns_query_create);

    /* DNS resource record functions */
    TCase *TCase_pico_dns_record_fill_suffix("Unit test for 'pico_dns_record_fill_suffix'");
    TCase *TCase_pico_dns_record_copy("Unit test for 'pico_dns_record_copy'");
    TCase *TCase_pico_dns_record_delete("Unit test for 'pico_dns_record_delete'");
    TCase *TCAse_pico_dns_record_create("Unit test for 'pico_dns_record_create'");

    tcase_add_test(TCase_pico_dns_record_fill_suffix, tc_pico_dns_record_fill_suffix);
    tcase_add_test(TCase_pico_dns_record_copy, tc_pico_dns_record_copy);
    tcase_add_test(TCase_pico_dns_record_delete, tc_pico_dns_record_delete);
    tcase_add_test(TCAse_pico_dns_record_create, tc_pico_dns_record_create);
    suite_add_tcase(s, TCase_pico_dns_record_fill_suffix);
    suite_add_tcase(s, TCase_pico_dns_record_copy);
    suite_add_tcase(s, TCase_pico_dns_record_delete);
    suite_add_tcase(s, TCAse_pico_dns_record_create);

    /* DNS record vector funcitons */
    TCase *TCase_pico_dns_record_vector_init("Unit test for 'pico_dns_record_vector_init'");
    TCase *TCase_pico_dns_record_vector_count("Unit test for 'pico_dns_record_vector_count'");
    TCase *TCase_pico_dns_record_vector_add("Unit test for 'pico_dns_record_vector_add'");
    TCase *TCase_pico_dns_record_vector_add_copy("Unit test for 'pico_dns_record_vector_add_copy'");
    TCase *TCase_pico_dns_record_vector_get("Unit test for 'pico_dns_record_vector_get'");
    TCase *TCase_pico_dns_record_vector_delete("Unit test for 'pico_dns_record_vector_delete'");
    TCase *TCase_pico_dns_record_vector_destroy("Unit test for 'pico_dns_record_vector_destroy'");
    TCase *TCase_pico_dns_record_vector_size("Unit test for 'pico_dns_record_vector_size'");

    tcase_add_test(TCase_pico_dns_record_vector_init, tc_pico_dns_record_vector_init);
    tcase_add_test(TCase_pico_dns_record_vector_count, tc_pico_dns_record_vector_count);
    tcase_add_test(TCase_pico_dns_record_vector_add, tc_pico_dns_record_vector_add);
    tcase_add_test(TCase_pico_dns_record_vector_add_copy, tc_pico_dns_record_vector_add_copy);
    tcase_add_test(TCase_pico_dns_record_vector_get, tc_pico_dns_record_vector_get);
    tcase_add_test(TCase_pico_dns_record_vector_delete, tc_pico_dns_record_vector_delete);
    tcase_add_test(TCase_pico_dns_record_vector_destroy, tc_pico_dns_record_vector_destroy);
    tcase_add_test(TCase_pico_dns_record_vector_size, tc_pico_dns_record_vector_size);
    suite_add_tcase(s, TCase_pico_dns_record_vector_init);
    suite_add_tcase(s, TCase_pico_dns_record_vector_count);
    suite_add_tcase(s, TCase_pico_dns_record_vector_add);
    suite_add_tcase(s, TCase_pico_dns_record_vector_add_copy);
    suite_add_tcase(s, TCase_pico_dns_record_vector_get);
    suite_add_tcase(s, TCase_pico_dns_record_vector_delete);
    suite_add_tcase(s, TCase_pico_dns_record_vector_destroy);
    suite_add_tcase(s, TCase_pico_dns_record_vector_size);

    /* DNS answer packet creation */
    TCase *TCase_pico_dns_answer_create("Unit test for 'pico_dns_answer_create'");

    tcase_add_test(TCase_pico_dns_answer_create, tc_pico_dns_answer_create);
    suite_add_tcase(s, TCase_pico_dns_answer_create);

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

