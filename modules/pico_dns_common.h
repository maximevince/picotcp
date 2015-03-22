
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

#define PICO_ARPA_IPV4_SUFFIX ".in-addr.arpa"

#ifdef PICO_SUPPORT_IPV6
#define STRLEN_PTR_IP6 63
#define PICO_ARPA_IPV6_SUFFIX ".IP6.ARPA"
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
    uint16_t qname_length;
    uint8_t proto;
    struct pico_dns_question *next;
};

/* A list of them is just the same */
typedef struct pico_dns_question pico_dns_question_list;

/* To store a DNS resource record in code-style format */
struct pico_dns_res_record
{
    char *rname;
    struct pico_dns_res_record_suffix *rsuffix;
    uint8_t *rdata;
    //---------------- META ----------------//
    uint16_t rname_length;
    struct pico_dns_res_record *next;
};

/* A list of them is just the same */
typedef struct pico_dns_res_record pico_dns_res_record_list;

// MARK: DNS PACKET FUNCTIONS

/* ****************************************************************************
 *  Fills the header section of a DNS packet with correct flags and section-
 *  counts.
 * ****************************************************************************/
void
pico_dns_fill_packet_header( struct pico_dns_header *hdr,
                             uint16_t qdcount,
                             uint16_t ancount,
                             uint16_t authcount,
                             uint16_t addcount );

// MARK: QUESTION FUNCTIONS

/* ****************************************************************************
 *  Just copies a question provided in [questio]
 * ****************************************************************************/
struct pico_dns_question *
pico_dns_question_copy( struct pico_dns_question *question );

/* ****************************************************************************
 *  Appends a resource record to the end of a resource record list
 * ****************************************************************************/
int
pico_dns_question_list_append( struct pico_dns_question *question,
                               pico_dns_question_list **questions );

/* ****************************************************************************
 *  Appends a copy of a resource record to the end of a resource record list
 * ****************************************************************************/
int
pico_dns_question_list_append_copy( struct pico_dns_question *question,
                                    pico_dns_question_list **questions );

/* ****************************************************************************
 *  Searches for a question with [qname] in a question list [question_list]
 * ****************************************************************************/
struct pico_dns_question *
pico_dns_question_list_find( char *qname,
                             pico_dns_question_list *question_list );

/* ****************************************************************************
 *  Returns the size summed up of all the questions contained in a
 *  linked list. Fills [count] with the number of questions in the list.
 * ****************************************************************************/
uint16_t
pico_dns_question_list_size( struct pico_dns_question *list_begin,
                            uint8_t *count );

/* ****************************************************************************
 *  Deletes & free's the memory for all the questions contained in a question-
 *  list.
 * ****************************************************************************/
int
pico_dns_question_list_delete ( pico_dns_question_list **questions );

/* ****************************************************************************
 *  Fills the question fixed-sized flags & fields accordingly.
 * ****************************************************************************/
void
pico_dns_question_fill_qsuffix( struct pico_dns_question_suffix *suf,
                                uint16_t type,
                                uint16_t qclass );

/* ****************************************************************************
 *  Creates a standalone DNS question for given 'url'. Fills the 'len'-argument
 *  with the total length of the question.
 * ****************************************************************************/
struct pico_dns_question *
pico_dns_question_create( const char *url,
                          uint16_t *len,
                          uint8_t proto,
                          uint16_t qtype,
                          uint16_t qclass );

/* ****************************************************************************
 *  Deletes & free's the memory for a certain dns resource record. Doesn't take
 *  lists into account so if applied to a list, most probably, gaps will arise.
 * ****************************************************************************/
int
pico_dns_question_delete( struct pico_dns_question **question);

// MARK: QUERY FUNCTIONS

/* ****************************************************************************
 * Creates a DNS packet meant for querying. Currently only questions can be
 * inserted in the packet.
 * ****************************************************************************/
pico_dns_packet *
pico_dns_query_create( pico_dns_question_list *question_list,
                       pico_dns_res_record_list *answer_list,
                       pico_dns_res_record_list *authority_list,
                       pico_dns_res_record_list *additional_list,
                       uint16_t *len );

// MARK: RESOURCE RECORD FUNCTIONS

/* ****************************************************************************
 *  Just copies a resource record provided in [record]
 * ****************************************************************************/
struct pico_dns_res_record *
pico_dns_rr_copy( struct pico_dns_res_record *record );

/* ****************************************************************************
 *  Appends a resource record to the end of a resource record list
 * ****************************************************************************/
int
pico_dns_rr_list_append( struct pico_dns_res_record *record,
                         pico_dns_res_record_list **records );

/* ****************************************************************************
 *  Appends a copy of a resource record to the end of a resource record list
 * ****************************************************************************/
int
pico_dns_rr_list_append_copy( struct pico_dns_res_record *record,
                              pico_dns_res_record_list **records);

/* ****************************************************************************
 * Creates a standalone DNS resource record for given 'url'. Fills the
 * 'len'-argument with the total length of the res_record.
 * ****************************************************************************/
struct pico_dns_res_record *
pico_dns_rr_create( const char *url,
                    void *_rdata,
                    uint16_t *len,
                    uint16_t rtype,
                    uint16_t rclass,
                    uint32_t rttl );

/* ****************************************************************************
 *  Deletes & free's the memory for a certain dns resource record
 * ****************************************************************************/
int
pico_dns_rr_delete( struct pico_dns_res_record **rr );

/* ****************************************************************************
 *  Returns the size summed up of all the resource records contained in a
 *  linked list. Fills [count] with the number of records in the list.
 * ****************************************************************************/
uint16_t
pico_dns_rr_list_size( struct pico_dns_res_record *records, uint8_t *count );

// MARK: ANSWER FUNCTIONS

/* ****************************************************************************
 *  Creates a DNS Answer packet with given resource records to put in the 
 *  Resource Record Sections. If a NULL-pointer is provided for a certain
 *  list, no records will be added to the packet for that section.
 * ****************************************************************************/
pico_dns_packet *
pico_dns_answer_create( pico_dns_res_record_list *answer_list,
                        pico_dns_res_record_list *authority_list,
                        pico_dns_res_record_list *additional_list,
                        uint16_t *len );

// MARK: NAME & IP FUNCTIONS

/* ****************************************************************************
 *  Returns the length of an FQDN in a DNS-packet as if DNS name compression
 *  would be applied to the packet
 * ****************************************************************************/
uint16_t pico_dns_namelen_comp( char *name );

/* ****************************************************************************
 *  Returns the length of an FQDN. If DNS name compression is applied in the
 *  DNS packet, this will be the length as if the compressed name would be 
 *  decompressed.
 * ****************************************************************************/
uint16_t
pico_dns_namelen_uncomp( char *name, pico_dns_packet *packet );

/* ****************************************************************************
 *  Returns the uncompressed FQDN when DNS name compression is applied in the
 *  DNS packet.
 * ****************************************************************************/
char *
pico_dns_expand_name_comp( char *name, pico_dns_packet *packet );

/* ****************************************************************************
 *  Create an URL in *[url_addr] from any qname given in [qname]. [url_addr]
 *  needs to be an addres to a NULL-pointer. Returns a string
 *  1 byte smaller in size than [qname] or 2 bytes smaller than the
 *  string-length. Use PICO_FREE() to deallocate the memory for this pointer.
 *
 *  f.e. *  4tass5local0 -> tass.local
 *       *  11112102107in-addr4arpa0 -> 1.1.10.10.in-addr.arpa
 * ****************************************************************************/
char *
pico_dns_qname_to_url( const char *qname );

/* ****************************************************************************
 * Create a qname in *[qname_addr] from any url given in [url]. [qname_addr]
 * needs to be an address to a NULL-pointer. Returns a string
 * 1 byte larger in size than [url] or 2 bytes larger than the
 * string-length. use PICO_FREE() to deallocate the memory for this pointer.
 *
 * f.e. -  tass.local -> 4tass5local0
 *      -  1.1.10.10.in-addr.arpa -> 11112102107in-addr4arpa0
 * ****************************************************************************/
char *
pico_dns_url_to_qname( const char *url );

/* ****************************************************************************
 *  Determines the length of a string
 * ****************************************************************************/
uint16_t
pico_dns_client_strlen( const char *url );

/* ****************************************************************************
 *  Converts a URL at location url + 1 to a FQDN in the form 3www6google3com0
 *  f.e. www.google.be => 3www6google2be0
 *  Size of ptr[] has to +2u more than the URL itself.
 * ****************************************************************************/
int
pico_dns_name_to_dns_notation( char *url );

/* ****************************************************************************
 *  Converts a FQDN at location fqdn to an URL in the form .www.google.com
 *  f.e. 3www6google2be0 => .www.google.be
 * ****************************************************************************/
int
pico_dns_notation_to_name( char *fqdn );

/* ****************************************************************************
 *  Mirrors and IP-address in ptr to an ARPA-format
 *  f.e. 192.168.0.1 => 1.0.168.192
 * ****************************************************************************/
int8_t
pico_dns_mirror_addr( char *ptr );

/* ****************************************************************************
 *
 * ****************************************************************************/
void
pico_dns_ipv6_set_ptr( const char *ip, char *dst );

/* ****************************************************************************
 *  TEMP: Just prints a DNS packet with given length in [len].
 *  For debugging purposes...
 * ****************************************************************************/
void
pico_dns_print_packet( struct pico_dns_header *packet, uint16_t len );

/* ****************************************************************************
 *  TEMP: Just prints a DNS question
 *  For debugging purposes...
 * ****************************************************************************/
void
pico_dns_print_question( struct pico_dns_question *question);

#endif /* _INCLUDE_PICO_DNS_COMMON */
