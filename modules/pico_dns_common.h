
/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Toon Stegen
 *********************************************************************/

#ifndef INCLUDE_PICO_DNS_COMMON
#define INCLUDE_PICO_DNS_COMMON

#include "pico_config.h"

/* QTYPE values */
#define PICO_DNS_TYPE_A 1
#define PICO_DNS_TYPE_CNAME 5
#define PICO_DNS_TYPE_AAAA 28
#define PICO_DNS_TYPE_PTR 12
#define PICO_DNS_TYPE_ANY 255

/* QCLASS values */
#define PICO_DNS_CLASS_IN 1

/* FLAG values */
#define PICO_DNS_QR_QUERY 0
#define PICO_DNS_QR_RESPONSE 1
#define PICO_DNS_OPCODE_QUERY 0
#define PICO_DNS_OPCODE_IQUERY 1
#define PICO_DNS_OPCODE_STATUS 2
#define PICO_DNS_AA_NO_AUTHORITY 0
#define PICO_DNS_AA_IS_AUTHORITY 1
#define PICO_DNS_TC_NO_TRUNCATION 0
#define PICO_DNS_TC_IS_TRUNCATED 1
#define PICO_DNS_RD_NO_DESIRE 0
#define PICO_DNS_RD_IS_DESIRED 1
#define PICO_DNS_RA_NO_SUPPORT 0
#define PICO_DNS_RA_IS_SUPPORTED 1
#define PICO_DNS_RCODE_NO_ERROR 0
#define PICO_DNS_RCODE_EFORMAT 1
#define PICO_DNS_RCODE_ESERVER 2
#define PICO_DNS_RCODE_ENAME 3
#define PICO_DNS_RCODE_ENOIMP 4
#define PICO_DNS_RCODE_EREFUSED 5

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63
#endif

enum pico_dns_arpa
{
    PICO_DNS_ARPA4,
    PICO_DNS_ARPA6,
    PICO_DNS_NO_ARPA,
};

/* flags split in 2x uint8 due to endianness */
PACKED_STRUCT_DEF pico_dns_header
{
    uint16_t id;        // Packet id
    uint8_t rd : 1;     // Recursion Desired
    uint8_t tc : 1;     // TrunCation
    uint8_t aa : 1;     // Authoritative Answer
    uint8_t opcode : 4; // Opcode
    uint8_t qr : 1;     // Query
    uint8_t rcode : 4;  // Response code
    uint8_t z : 3;      // Zero
    uint8_t ra : 1;     // Recursion Available
    uint16_t qdcount;   // Question count
    uint16_t ancount;   // Answer count
    uint16_t nscount;   // Authority count
    uint16_t arcount;   // Additional count
};

typedef struct pico_dns_header pico_dns_packet;

/* Question fixed-sized fields */
PACKED_STRUCT_DEF pico_dns_question_suffix
{
    uint16_t qtype;
    uint16_t qclass;
};

/* Resource record fixed-sized fields */
PACKED_STRUCT_DEF pico_dns_res_record_suffix
{
    uint16_t rtype;
    uint16_t rclass;
    uint32_t rttl;
    uint16_t rdlength;
};

/* To store a DNS question in code-style format */
struct pico_dns_question
{
    char *qname;
    struct pico_dns_question_suffix *qsuffix;
    //---------------- META ----------------//
    uint8_t qname_length;
    struct pico_dns_question *next;
};

/* To store a DNS resource record in code-style format */
struct pico_dns_res_record
{
    char *rname;
    struct pico_dns_res_record_suffix *rsuffix;
    uint8_t *rdata;
    //---------------- META ----------------//
    uint8_t rname_length;
    struct pico_dns_res_record *next;
};

// MARK: DNS PACKET FUNCTIONS

/* **************************************************************************
 *
 *  Fills the header section of a DNS packet with correct flags and section-
 *  counts.
 *
 * **************************************************************************/
void pico_dns_fill_packet_header( struct pico_dns_header *hdr, uint16_t qdcount, uint16_t ancount, uint16_t authcount, uint16_t addcount );

// MARK: QUESTION FUNCTIONS

/* **************************************************************************
 *
 *  Fills the question fixed-sized flags & fields accordingly.
 *
 * **************************************************************************/
void pico_dns_question_fill_suffix( struct pico_dns_question_suffix *suf, uint16_t type, uint16_t qclass );

// MARK: QUERY FUNCTIONS

/* **************************************************************************
 *
 * Creates a DNS packet meant for querying. Currently only questions can be
 * inserted in the packet.
 *
 * TODO: Allow resource records to be added to Authority & Answer Section
 *          - Answer Section: To implement Known-Answer Suppression
 *          - Authority Section: To implement probe queries and tiebreaking
 *
 * **************************************************************************/
static pico_dns_packet *pico_mdns_dns_query_create( struct pico_dns_question *question_list, uint16_t *len );


// MARK: RESOURCE RECORD FUNCTIONS

/* **************************************************************************
 *
 *  Fills the resource record fixed-sized flags & fields accordingly.
 *
 * **************************************************************************/
void pico_dns_rr_fill_suffix( struct pico_dns_res_record_suffix *suf, uint16_t rtype, uint16_t rclass, uint32_t rttl, uint16_t rdlength );

/* **************************************************************************
 *
 * Creates a standalone DNS resource record for given 'url'. Fills the
 * 'len'-argument with the total length of the res_record.
 *
 * **************************************************************************/
struct pico_dns_res_record *pico_dns_rr_create( const char *url, void *_rdata, uint16_t *len, uint16_t rtype, uint16_t rclass, uint16_t rttl );

/* **************************************************************************
 *
 *  Free's the memory for a certain dns resource record
 *
 * **************************************************************************/
int pico_dns_rr_delete( struct pico_dns_res_record **rr );

/* **************************************************************************
 *
 *  Returns the size summed up of all the resource records contained in a
 *  linked list. Fills [count] with the number of records in the list.
 *
 * **************************************************************************/
uint16_t pico_dns_rr_list_size( struct pico_dns_res_record *list_begin, uint8_t *count );

/* **************************************************************************
 *
 *  Copies the contents a resource record [res_record] to a single flat
 *  location in [destination]. [destination] pointer will point to address
 *  right after this flat resource record on success.
 *
 * **************************************************************************/
int pico_dns_rr_copy_flat( struct pico_dns_res_record *res_record, uint8_t *destination );

// MARK: ANSWER FUNCTIONS

/* **************************************************************************
 *
 *  Creates a DNS Answer packet with given resource records to put in the 
 *  Resource Record Sections. If a NULL-pointer is provided for a certain
 *  list, no records will be added to the packet for that section.
 *
 * **************************************************************************/
pico_dns_packet *pico_dns_create_answer( struct pico_dns_res_record *answer_list, struct pico_dns_res_record *authority_list, struct pico_dns_res_record *additional_list, uint16_t *len );

/* **************************************************************************
 *  Determines the length of a string
 * **************************************************************************/
uint16_t pico_dns_client_strlen( const char *url );

/* **************************************************************************
 *
 *  Converts a URL at location url + 1 to a FQDN in the form 3www6google3com0
 *  f.e. www.google.be => 3www6google2be0
 *  Size of ptr[] has to +2u more than the URL itself.
 *
 * **************************************************************************/
int pico_dns_name_to_dns_notation( char *url );

/* **************************************************************************
 *
 *  Converts a FQDN at location fqdn to an URL in the form .www.google.com
 *  f.e. 3www6google2be0 => .www.google.be
 *
 * **************************************************************************/
int pico_dns_notation_to_name( char *fqdn );

/* **************************************************************************
 *
 *  Mirrors and IP-address in ptr to an ARPA-format
 *  f.e. 192.168.0.1 => 1.0.168.192
 *
 * **************************************************************************/
int8_t pico_dns_mirror_addr( char *ptr );

/* **************************************************************************
 *
 *
 *
 * **************************************************************************/
void pico_dns_ipv6_set_ptr( const char *ip, char *dst );

#endif /* _INCLUDE_PICO_DNS_COMMON */
