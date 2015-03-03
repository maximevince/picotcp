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

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");
    
    TCase *TCase_pico_dns_namelen_comp = tcase_create("Unit test for pico_dns_namelen_comp");
    TCase *TCase_pico_dns_namelen_uncomp = tcase_create("Unit test for pico_dns_namelen_uncomp");
    TCase *TCase_pico_dns_expand_name_comp = tcase_create("Unit test for pico_dns_expand_name_comp");
    
    tcase_add_test(TCase_pico_dns_namelen_comp, tc_pico_dns_namelen_comp);
    suite_add_tcase(s, TCase_pico_dns_namelen_comp);
    tcase_add_test(TCase_pico_dns_namelen_uncomp, tc_pico_dns_namelen_uncomp);
    suite_add_tcase(s, TCase_pico_dns_namelen_uncomp);
    tcase_add_test(TCase_pico_dns_expand_name_comp, tc_pico_dns_expand_name_comp);
    suite_add_tcase(s, TCase_pico_dns_expand_name_comp);
    
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
