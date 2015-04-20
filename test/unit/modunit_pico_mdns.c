#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_dns_common.h"
#include "pico_tree.h"
#include "modules/pico_mdns.c"
#include "check.h"

void callback(void *data, void *arg)
{
    (void) data;
    (void) arg;
}

START_TEST(tc_mdns_cache_cmp)
{
    //    struct pico_mdns_cache_rr ka;
    //    struct pico_mdns_cache_rr kb;
    //    struct pico_dns_res_record_suffix sa;
    //    struct pico_dns_res_record_suffix sb;
    //
    //    char qname1[] = "\3www\6google\3com";
    //    char qname2[] = "\3www\6apple\3com";
    //
    //    /* Set the rescoure record types */
    //    sa.rtype = PICO_DNS_TYPE_A;
    //    sb.rtype = PICO_DNS_TYPE_A;
    //
    //    /* Set the qnames of the resource records */
    //    ka.url = qname1;
    //    kb.url = qname2;
    //
    //    /* Set the suffixes of the cache rr's */
    //    ka.suf = &sa;
    //    kb.suf = &sb;
    //
    //    fail_unless(mdns_cache_cmp(&ka, &kb) != 0, "RR cmp returned equal!");
    //
    //    /* See what happens when urls are the same */
    //    ka.url = qname1;
    //    kb.url = qname1;
    //
    //    fail_unless(mdns_cache_cmp(&ka, &kb) == 0, "RR cmp returned different!");
}
END_TEST
START_TEST(tc_mdns_cmp)
{
    //    struct pico_mdns_cookie ka;
    //    struct pico_mdns_cookie kb;
    //
    //    char qname1[] = "\3www\6google\3com";
    //    char qname2[] = "\3www\6apple\3com";
    //
    //    /* Set the question types */
    //    ka.qtype = PICO_DNS_TYPE_A;
    //    kb.qtype = PICO_DNS_TYPE_A;
    //
    //    /* Set the question names */
    //    ka.qname = qname1;
    //    kb.qname = qname2;
    //
    //    fail_unless(mdns_cmp(&ka, &kb) != 0, "cmp returned equal!");
    //
    //    /* See what happens when the qnames are the same */
    //    ka.qname = qname1;
    //    kb.qname = qname1;
    //
    //    fail_unless(mdns_cmp(&ka, &kb) == 0, "cmp returned different!");
}
END_TEST
START_TEST(tc_pico_mdns_send)
{
    //    pico_dns_packet packet = { 0 };
    //    uint16_t len = 0;
    //    uint16_t sentlen = 0;
    //    sentlen = (uint16_t)pico_mdns_send_packet(&packet, len);
    //    fail_unless(sentlen == len, "Sent %d iso expected %d bytes!\n", sentlen, len);
}
END_TEST
START_TEST(tc_pico_mdns_cache_del_rr)
{
    // TODO: Still need to update this function in mDNS module
}
END_TEST
START_TEST(tc_pico_mdns_add_cookie)
{
    // TODO: Add cookie, find cookie in tree cmp to see if cookie is correct
}
END_TEST
START_TEST(tc_pico_mdns_answer_create)
{
    //    struct pico_dns_res_record record = { 0 };
    //    pico_dns_packet *packet = NULL;
    //    uint16_t len = 0;
    //
    //    /* Provide space for rname and fill in */
    //    record.rname = PICO_ZALLOC(strlen("\3www\6google\3com") + 1u);
    //    strcpy(record.rname, "\3www\6google\3com");
    //
    //    /* Provide space for the suffix and fill in */
    //    record.rsuffix = PICO_ZALLOC(sizeof(struct pico_dns_res_record_suffix));
    //    record.rsuffix->rtype = PICO_DNS_TYPE_A;
    //    record.rsuffix->rclass = PICO_DNS_CLASS_IN;
    //    record.rsuffix->rttl = 120;
    //    record.rsuffix->rdlength = 4;
    //
    //    /* Provide space for rdata and fill in */
    //    record.rdata = PICO_ZALLOC(4);
    //    record.rdata[0] = 192;
    //    record.rdata[1] = 168;
    //    record.rdata[2] = 1;
    //    record.rdata[3] = 1;
    //
    //    /* Fill in meta fields */
    //    record.rname_length = (uint16_t)strlen("\3www\6google\3com");
    //    record.next = NULL;
    //
    //    /* Try to create a DNS answer packet */
    //    packet = pico_mdns_answer_create(&record, NULL, NULL, &len);
    //
    //    fail_unless(packet != NULL, "Answer packet returned is NULL!\n");
    //
    //    /* TODO: memcmp to test if packet is correctly formed */
    //
    //    PICO_FREE(record.rname);
    //    PICO_FREE(record.rsuffix);
    //    PICO_FREE(record.rdata);
    //
    //    PICO_FREE(packet);
}
END_TEST
START_TEST(tc_pico_mdns_query_create)
{
    //    struct pico_dns_question question = { 0 };
    //    pico_dns_packet *packet = NULL;
    //    uint16_t len = 0;
    //
    //    /* Provide space for the qname and fill in */
    //    question.qname = PICO_ZALLOC(strlen("\3www\6google\3com") + 1u);
    //    strcpy(question.qname, "\3www\6google\3com");
    //
    //    /* Provide space for the suffix and fill in */
    //    question.qsuffix = PICO_ZALLOC(sizeof(struct pico_dns_question_suffix));
    //    question.qsuffix->qtype = PICO_DNS_TYPE_A;
    //    question.qsuffix->qclass = PICO_DNS_CLASS_IN;
    //
    //    /* Fill in meta fields */
    //    question.qname_length = (uint16_t)strlen("\3www\6google\3com");
    //    question.next = NULL;
    //
    //    /* Try to create a DNS query packet */
    //    packet = pico_mdns_query_create(&question, &len);
    //
    //    fail_unless(packet != NULL, "Query packet returned is NULL!\n");
    //
    //    /* TODO: memcmp to test if packet is correctly formed */
    //
    //    PICO_FREE(question.qname);
    //    PICO_FREE(question.qsuffix);
    //
    //    PICO_FREE(packet);
}
END_TEST
START_TEST(tc_pico_mdns_del_cookie)
{
    /* TODO: Add cookie, Try to delete cookie and look for cookie & see if it's deleted */
}
END_TEST
START_TEST(tc_pico_mdns_cache_find_rr)
{
    //    char url[] = "findrr.local";
    //    uint16_t qtype = PICO_DNS_TYPE_A;
    //    struct pico_mdns_cache_rr *rr = NULL;
    //    struct pico_dns_answer_suffix suf = {
    //        .qtype = short_be(qtype),
    //        .ttl = long_be(100)
    //    };
    //    char rdata[] = "somedata";
    //
    //    pico_stack_init();
    //    rr = pico_mdns_cache_find_rr(url, qtype);
    //    fail_unless(rr == NULL, "Found nonexistent RR in cache!\n");
    //
    //    rr = NULL;
    //    pico_mdns_cache_add_rr(url, &suf, rdata);
    //    rr = pico_mdns_cache_find_rr(url, qtype);
    //    fail_unless(rr != NULL, "RR not found in cache!\n");
}
END_TEST
START_TEST(tc_pico_mdns_cache_add_rr)
{
    //    char url[] = "addrr.local";
    //    uint16_t qtype = PICO_DNS_TYPE_A;
    //    struct pico_dns_answer_suffix suf = {
    //        .qtype = short_be(qtype),
    //        .ttl = long_be(100)
    //    };
    //    char rdata[] = "somedata";
    //
    //    pico_stack_init();
    //    fail_unless(pico_mdns_cache_add_rr(url, &suf, rdata) == 0, "Failed to add RR to cache\n");
}
END_TEST
START_TEST(tc_pico_mdns_flush_cache)
{
    //    char url[] = "flush.local";
    //    char url2[] = "flush2.local";
    //    uint16_t qtype = PICO_DNS_TYPE_A;
    //    struct pico_mdns_cache_rr *rr = NULL;
    //    struct pico_dns_answer_suffix suf = {
    //        .qtype = short_be(qtype),
    //        .ttl = long_be(100)
    //    };
    //    char rdata[] = "somedata";
    //
    //    pico_stack_init();
    //    /* Add RR and find it in the cache, then flush cache and look for it again */
    //    fail_unless(pico_mdns_cache_add_rr(url, &suf, rdata) == 0, "Failed to add RR to cache\n");
    //    fail_unless(pico_mdns_cache_add_rr(url2, &suf, rdata) == 0, "Failed to add RR to cache\n");
    //
    //    rr = pico_mdns_cache_find_rr(url, qtype);
    //    fail_unless(rr != NULL, "RR not found in cache!\n");
    //    fail_unless(pico_mdns_flush_cache() == 0, "RR cache flushing failure!\n");
    //
    //    rr = NULL;
    //    rr = pico_mdns_cache_find_rr(url, qtype);
    //    fail_unless(rr == NULL, "RR found in cache after flush!\n");
    //
    //    rr = NULL;
    //    rr = pico_mdns_cache_find_rr(url2, qtype);
    //    fail_unless(rr == NULL, "RR found in cache after flush!\n");
}
END_TEST
START_TEST(tc_pico_mdns_find_cookie)
{
    /* TODO: Add cookie to tree, see if you can find cookie */
}
END_TEST
START_TEST(tc_pico_mdns_reply_query)
{
    /* TODO: test this: static int pico_mdns_reply_query(uint16_t qtype, struct pico_ip4 peer) */
    //    uint16_t qtype = 0;
    //    struct pico_ip4 peer = {
    //        0
    //    };
    //    char *name = NULL;
    //
    //    fail_unless(pico_mdns_reply_query(qtype, peer, name) == -1, "Replied to query with invalid arg \n");
}
END_TEST
START_TEST(tc_pico_mdns_handle_query)
{
    /* TODO: test this: static int pico_mdns_handle_query(char *url, struct pico_dns_query_suffix *suf, struct pico_ip4 peer) */
    //    char url[256] = {
    //        0
    //    };
    //    struct pico_dns_query_suffix suf = {
    //        0
    //    };
    //    struct pico_ip4 peer = {
    //        0
    //    };
    //
    //    pico_mdns_handle_query(url, &suf, peer);
}
END_TEST
START_TEST(tc_pico_mdns_handle_answer)
{
    /* TODO: test this: static int pico_mdns_handle_answer(char *url, struct pico_dns_answer_suffix *suf, char *data) */
    //    char url[] = "han-ans.local";
    //    struct pico_dns_answer_suffix suf = {
    //        0
    //    };
    //    char data[] = "somedata";
    //    pico_mdns_handle_answer(url, &suf, data);
}
END_TEST
START_TEST(tc_pico_mdns_recv)
{
    /* TODO: test this: static int pico_mdns_recv(void *buf, int buflen, struct pico_ip4 peer) */
    //    char buf[256] = { 0 };
    //    int buflen = 0;
    //    struct pico_ip4 peer = {
    //        0
    //    };
    //
    //    fail_unless(pico_mdns_recv(buf, buflen, peer) == -1, "No error with invalid args!\n");
}
END_TEST
START_TEST(tc_pico_mdns_wakeup)
{
    /* TODO: test this: static void pico_mdns_wakeup(uint16_t ev, struct pico_socket *s) */
    //    uint16_t ev = 0;
    //    struct pico_socket *s = NULL;
    //
    //    pico_mdns_wakeup(ev, s);
}
END_TEST
START_TEST(tc_pico_mdns_announce_timer)
{
    /* TODO: test this: static void pico_mdns_announce_timer(pico_time now, void *arg) */
    //    pico_time now = 0;
    //    void *arg = NULL;
    //
    //    pico_mdns_announce_timer(now, arg);
}
END_TEST
START_TEST(tc_pico_mdns_announce)
{
    /* TODO: test this: static int pico_mdns_announce() */
    //pico_mdns_announce();
}
END_TEST
START_TEST(tc_pico_mdns_probe_timer)
{
    /* TODO: test this: static void pico_mdns_probe_timer(pico_time now, void *arg) */
    //    pico_time now = 0;
    //    void *arg = NULL;
    //
    //    pico_mdns_probe_timer(now, arg);
}
END_TEST
START_TEST(tc_pico_mdns_probe)
{
    /* TODO: test this: static int pico_mdns_probe(char *hostname, void (*cb_initialised)(char *str, void *arg), void *arg) */
    //    char hostname[256] = {
    //        0
    //    };
    //    void *arg = NULL;
    //    pico_stack_init();
    //    pico_mdns_probe(hostname, callback, arg);
}
END_TEST
START_TEST(tc_pico_mdns_getaddr_generic)
{
    /* TODO: test this: static int pico_mdns_getaddr_generic(const char *url, void (*callback)(char *ip, void *arg), void *arg, uint16_t proto) */
    //    const char *url = NULL;
    //    void *arg = NULL;
    //    uint16_t proto = 0;
    //    pico_mdns_getaddr_generic(url, callback, arg, proto);
}
END_TEST
START_TEST(tc_pico_mdns_getname_generic)
{
    /* TODO: test this: static int pico_mdns_getname_generic(const char *ip, void (*callback)(char *url, void *arg), void *arg, uint16_t proto) */
    //    const char *ip = NULL;
    //    void *arg = NULL;
    //    uint16_t proto = 0;
    //
    //    pico_mdns_getname_generic(ip, callback, arg, proto);
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    /* Comparing functions */
    TCase *TCase_mdns_rdata_cmp = tcase_create("Unit test for mdns_rdata_cmp");
    TCase *TCase_mdns_cmp = tcase_create("Unit test for mdns_cmp");
    TCase *TCase_mdns_cookie_cmp = tcase_create("Unit test for mdns_cookie_cmp");

    /* Sending functions */
    TCase *TCase_mdns_send_packet = tcase_create("Unit test for mdns_send_packet");
    TCase *TCase_mdns_send_packet_unicast = tcase_create("Unit test for mdns_send_packet_unicast");

    /* Cookie functions */
    TCase *TCase_mdns_cookie_delete = tcase_create("Unit test for mdns_cookie_delete");
    TCase *TCase_mdns_cookie_create = tcase_create("Unit test for mdns_cookie_create");
    TCase *TCase_mdns_cookie_tree_find_query_cookie = tcase_create("Unit test for mdns_cookie_tree_find_query_cookie");
    TCase *TCase_mdns_cookie_tree_del_cookie = tcase_create("Unit test for mdns_cookie_tree_del_cookie");
    TCase *TCase_mdns_cookie_tree_add_cookie = tcase_create("Unit test for mdns_cookie_tree_add_cookie");
    TCase *TCase_mdns_cookie_apply_spt = tcase_create("Unit test for mdns_cookie_apply_spt");
    TCase *TCase_mdns_resolve_name_conflict = tcase_create("Unit test for mdns_resolve_name_conflict");
    TCase *TCase_mdns_cookie_resolve_conflict = tcase_create("Unit test for mdns_cookie_resolve_conflict");
    TCase *TCase_mdns_timeout = tcase_create("Unit test for mdns_timeout");

    /* Question functions */
    TCase *TCase_mdns_question_create = tcase_create("Unit test for mdns_question_create");

    /* Record functions */
    TCase *TCase_mdns_dns_record_create = tcase_create("Unit test for mdns_dns_record_create");
    TCase *TCase_mdns_record_am_i_lexi_later = tcase_create("Unit test for mdns_record_am_i_lexi_later");
    TCase *TCase_mdns_record_create_from_dns = tcase_create("Unit test for mdns_recod_create_from_dns");
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
    TCase *TCase_mdns_record_vector_find_by_name_type = tcase_create("Unit test for mdns_record_vector_find_by_name_type");
    TCase *TCase_mdns_record_vecotr_find_record = tcase_create("Unit test for mdns_record_vector_find_record");
    TCase *TCase_mdns_record_vector_del_record = tcase_create("Unit test for mdns_record_vector_del_record");

    /* Record tree functions */
    TCase *TCase_mdns_record_tree_find_records_by_url = tcase_create("Unit test for mdns_record_tree_find_records_by_url");
    TCase *TCase_mdns_record_tree_find_records = tcase_create("Unit test for mdns_record_tree_find_records");
    TCase *TCase_mdns_record_tree_find_record = tcase_create("Unit test for mdns_record_tree_find_record");
    TCase *TCase_mdns_record_tree_del_records_by_url = tcase_create("Unit test for mdns_record_tree_del_records_by_url");
    TCase *TCase_mdns_record_tree_del_records = tcase_create("Unit test for mdns_record_tree_del_records");
    TCase *TCase_mdns_record_tree_del_record = tcase_create("Unit test for mdns_record_tree_del_record");
    TCase *TCase_mdns_record_tree_add_record = tcase_create("Unit test for mdns_record_tree_add_record");

    /* My record functions */
    TCase *TCase_mdns_my_records_find_probed = tcase_create("Unit test for mdns_my_records_find_probed");
    TCase *TCase_mdns_my_records_find_to_probe = tcase_create("Unit test for mdns_my_records_find_to_probe");
    TCase *TCase_mdns_my_records_claimed = tcase_create("Unit test for mdns_my_records_claimed");

    /* Query functions */
    TCase *TCase_mdns_query_create = tcase_create("Unit test for mdns_query_create");

    /* Answer functions */
    TCase *TCase_mdns_answer_create = tcase_create("Unit test for mdns_answer_create");

    /* Cache functions */
    TCase *TCase_mdns_cache_add_record = tcase_create("Unit test for mdns_cache_add_record");
    TCase *TCase_mdns_cache_tick = tcase_create("Unit test for mdns_cache_tick");
    TCase *TCase_mdns_cache_flush = tcase_create("Unit test for mdns_cache_flush");

    /* Handling receptions */
    TCase *TCase_mdns_handle_single_question = tcase_create("Unit test for mdns_handle_single_question");
    TCase *TCase_mdns_handle_single_answer = tcase_create("Unit test for mdns_handle_single_answer");
    TCase *TCase_mdns_handle_single_authority = tcase_create("Unit test for mdns_handle_single_authority");
    TCase *TCase_mdns_handle_single_additional = tcase_create("Unit test for mdns_handle_single_additional");

    TCase *TCase_mdns_handle_data_as_questions = tcase_create("Unit test for mdns_handle_data_as_questions");
    TCase *TCase_mdns_handle_data_as_answers = tcase_create("Unit test for mdns_handle_data_as_answers");
    TCase *TCase_mdns_handle_data_as_authorities = tcase_create("Unit test for mdns_handle_data_as_authorities");
    TCase *TCase_mdns_handle_data_as_additionals = tcase_create("Unit test for mdns_handle_data_as_additionals");

    TCase *TCase_mdns_handle_query_packet = tcase_create("Unit test for mdns_handle_query_packet");
    TCase *TCase_mdns_handle_probe_packet = tcase_create("Unit test for mdns_handle_probe_packet");
    TCase *TCase_mdns_handle_response_packet = tcase_create("Unit test for mdns_hadnle_response_packet");

    TCase *TCase_mdns_recv = tcase_create("Unit test for mdns_recv");
    TCase *TCase_mdns_event4 = tcase_create("Unit test for mdns_event4");

    /* Address resolving functions */
    TCase *TCase_mdns_send_query_packet = tcase_create("Unit test for mdns_send_query_packet");
    TCase *TCase_mdns_getrecord_generic = tcase_create("Unit test for mdns_getrecord_generic");
    TCase *TCase_mdns_getrecord = tcase_create("Unit test for mdns_getrecord");

    /* Announcement functions */
    TCase *TCase_mdns_send_announcement_packet = tcase_create("Unit test for mdns_send_announcement_packet");
    TCase *TCase_mdns_announce = tcase_create("Unit test for mdns_announce");
    TCase *TCase_mdns_send_probe_packet = tcase_create("Unit test for mdns_send_probe_packet");
    TCase *TCase_mdns_probe = tcase_create("Unit test for mdns_probe");

    /* Claiming functions */
    TCase *TCase_mdns_claim = tcase_create("Unit test for mnds_claim");
    TCase *TCase_mdns_reclaim = tcase_create("Unit test for mdns_reclaim");

    /* API functions */
    TCase *TCase_mdns_set_hostname = tcase_create("Unit test for mdns_set_hostname");
    TCase *TCase_mdns_get_hostname = tcase_create("Unit test for mdns_get_hostname");
    TCase *TCase_mdns_init = tcase_create("Unit test for mdns_init");

    /* Comparing functions */
    tcase_add_test(TCase_mdns_rdata_cmp, tc_mdns_rdata_cmp);
    suite_add_tcase(s, TCase_mdns_rdata_cmp);
    tcase_add_test(TCase_mdns_cmp, tc_mdns_cmp);
    suite_add_tcase(s, TCase_mdns_cmp);
    tcase_add_test(TCase_mdns_cookie_cmp, tc_mdns_cookie_cmp);
    suite_add_tcase(s, TCase_mdns_cookie_cmp);

    /* Sending functions */
    tcase_add_test(TCase_mdns_send_packet, tc_mdns_send_packet);
    suite_add_tcase(s, TCase_mdns_send_packet);
    tcase_add_test(TCase_mdns_send_packet_unicast, tc_mdns_send_packet_unicast);
    suite_add_tcase(s, TCase_mdns_send_packet_unicast);

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
    tcase_add_test(TCase_mdns_cookie_apply_spt, tc_mdns_cookie_apply_spt);
    suite_add_tcase(s, TCase_mdns_cookie_apply_spt);
    tcase_add_test(TCase_mdns_resolve_name_conflict, tc_mdns_resolve_name_conflict);
    suite_add_tcase(s, TCase_mdns_resolve_name_conflict);
    tcase_add_test(TCase_mdns_cookie_resolve_conflict, tc_mdns_cookie_resolve_conflict);
    suite_add_tcase(s, TCase_mdns_cookie_resolve_conflict);
    tcase_add_test(TCase_mdns_timeout, tc_mdns_timeout);
    suite_add_tcase(s, TCase_mdns_timeout);

    /* Question functions */
    tcase_add_test(TCase_mdns_question_create, tc_mdns_question_create);
    suite_add_tcase(s, TCase_mdns_question_create);

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

