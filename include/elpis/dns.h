/*
 * elpis/dns.h -- protocol constants.
 *
 * References: RFC 1035, 2181, 2308, 2671/6891, 3225, 3596, 4033-4035, 4343,
 * 4470, 4592, 5155, 5452, 5936, 6147, 6605, 6672, 6761, 6840, 6891, 7766,
 * 7873, 8020, 8080, 8198, 8482, 8767, 8914, 9156, 9210, 9471, 9520, 9619.
 */
#ifndef ELPIS_DNS_H
#define ELPIS_DNS_H

#include "elpis/common.h"

/* ---- sizes ------------------------------------------------------- */
#define ELPIS_HDR_LEN          12
#define ELPIS_MAX_NAME         255
#define ELPIS_MAX_LABEL        63
#define ELPIS_MAX_LABELS       128
#define ELPIS_MAX_UDP_LEGACY   512
#define ELPIS_MAX_UDP          4096
#define ELPIS_MAX_MSG          65535
#define ELPIS_EDNS_DEFAULT     1232    /* RFC 9715 / DNS Flag Day 2020 */
#define ELPIS_MAX_CNAME_CHAIN  12
#define ELPIS_MAX_REFERRALS    32
#define ELPIS_MAX_RESTARTS     16

/* ---- header flags ------------------------------------------------ */
#define ELPIS_FLAG_QR   0x8000u
#define ELPIS_FLAG_AA   0x0400u
#define ELPIS_FLAG_TC   0x0200u
#define ELPIS_FLAG_RD   0x0100u
#define ELPIS_FLAG_RA   0x0080u
#define ELPIS_FLAG_Z    0x0040u
#define ELPIS_FLAG_AD   0x0020u
#define ELPIS_FLAG_CD   0x0010u
#define ELPIS_OPCODE_MASK 0x7800u
#define ELPIS_OPCODE_SHIFT 11
#define ELPIS_RCODE_MASK  0x000Fu

/* ---- opcodes ----------------------------------------------------- */
#define ELPIS_OP_QUERY   0
#define ELPIS_OP_IQUERY  1
#define ELPIS_OP_STATUS  2
#define ELPIS_OP_NOTIFY  4
#define ELPIS_OP_UPDATE  5
#define ELPIS_OP_DSO     6

/* ---- rcodes ------------------------------------------------------ */
#define ELPIS_RC_NOERROR   0
#define ELPIS_RC_FORMERR   1
#define ELPIS_RC_SERVFAIL  2
#define ELPIS_RC_NXDOMAIN  3
#define ELPIS_RC_NOTIMP    4
#define ELPIS_RC_REFUSED   5
#define ELPIS_RC_YXDOMAIN  6
#define ELPIS_RC_YXRRSET   7
#define ELPIS_RC_NXRRSET   8
#define ELPIS_RC_NOTAUTH   9
#define ELPIS_RC_NOTZONE   10
#define ELPIS_RC_DSOTYPENI 11
#define ELPIS_RC_BADVERS   16
#define ELPIS_RC_BADKEY    17
#define ELPIS_RC_BADTIME   18
#define ELPIS_RC_BADMODE   19
#define ELPIS_RC_BADNAME   20
#define ELPIS_RC_BADALG    21
#define ELPIS_RC_BADTRUNC  22
#define ELPIS_RC_BADCOOKIE 23

/* ---- classes ----------------------------------------------------- */
#define ELPIS_CLASS_IN   1
#define ELPIS_CLASS_CH   3
#define ELPIS_CLASS_HS   4
#define ELPIS_CLASS_NONE 254
#define ELPIS_CLASS_ANY  255

/* ---- rr types ---------------------------------------------------- */
#define ELPIS_T_A          1
#define ELPIS_T_NS         2
#define ELPIS_T_MD         3
#define ELPIS_T_MF         4
#define ELPIS_T_CNAME      5
#define ELPIS_T_SOA        6
#define ELPIS_T_MB         7
#define ELPIS_T_MG         8
#define ELPIS_T_MR         9
#define ELPIS_T_NULL       10
#define ELPIS_T_WKS        11
#define ELPIS_T_PTR        12
#define ELPIS_T_HINFO      13
#define ELPIS_T_MINFO      14
#define ELPIS_T_MX         15
#define ELPIS_T_TXT        16
#define ELPIS_T_RP         17
#define ELPIS_T_AFSDB      18
#define ELPIS_T_X25        19
#define ELPIS_T_ISDN       20
#define ELPIS_T_RT         21
#define ELPIS_T_NSAP       22
#define ELPIS_T_NSAP_PTR   23
#define ELPIS_T_SIG        24
#define ELPIS_T_KEY        25
#define ELPIS_T_PX         26
#define ELPIS_T_GPOS       27
#define ELPIS_T_AAAA       28
#define ELPIS_T_LOC        29
#define ELPIS_T_NXT        30
#define ELPIS_T_EID        31
#define ELPIS_T_NIMLOC     32
#define ELPIS_T_SRV        33
#define ELPIS_T_ATMA       34
#define ELPIS_T_NAPTR      35
#define ELPIS_T_KX         36
#define ELPIS_T_CERT       37
#define ELPIS_T_A6         38
#define ELPIS_T_DNAME      39
#define ELPIS_T_SINK       40
#define ELPIS_T_OPT        41
#define ELPIS_T_APL        42
#define ELPIS_T_DS         43
#define ELPIS_T_SSHFP      44
#define ELPIS_T_IPSECKEY   45
#define ELPIS_T_RRSIG      46
#define ELPIS_T_NSEC       47
#define ELPIS_T_DNSKEY     48
#define ELPIS_T_DHCID      49
#define ELPIS_T_NSEC3      50
#define ELPIS_T_NSEC3PARAM 51
#define ELPIS_T_TLSA       52
#define ELPIS_T_SMIMEA     53
#define ELPIS_T_HIP        55
#define ELPIS_T_NINFO      56
#define ELPIS_T_RKEY       57
#define ELPIS_T_TALINK     58
#define ELPIS_T_CDS        59
#define ELPIS_T_CDNSKEY    60
#define ELPIS_T_OPENPGPKEY 61
#define ELPIS_T_CSYNC      62
#define ELPIS_T_ZONEMD     63
#define ELPIS_T_SVCB       64
#define ELPIS_T_HTTPS      65
#define ELPIS_T_DSYNC      66
#define ELPIS_T_SPF        99
#define ELPIS_T_NID        104
#define ELPIS_T_L32        105
#define ELPIS_T_L64        106
#define ELPIS_T_LP         107
#define ELPIS_T_EUI48      108
#define ELPIS_T_EUI64      109
#define ELPIS_T_TKEY       249
#define ELPIS_T_TSIG       250
#define ELPIS_T_IXFR       251
#define ELPIS_T_AXFR       252
#define ELPIS_T_MAILB      253
#define ELPIS_T_MAILA      254
#define ELPIS_T_ANY        255
#define ELPIS_T_URI        256
#define ELPIS_T_CAA        257
#define ELPIS_T_AVC        258
#define ELPIS_T_DOA        259
#define ELPIS_T_AMTRELAY   260
#define ELPIS_T_RESINFO    261
#define ELPIS_T_TA         32768
#define ELPIS_T_DLV        32769

/* ---- EDNS(0) ----------------------------------------------------- */
#define ELPIS_EDNS_VERSION   0
#define ELPIS_EDNS_DO        0x8000u   /* top bit of the TTL field */

#define ELPIS_OPT_LLQ            1
#define ELPIS_OPT_UL             2
#define ELPIS_OPT_NSID           3
#define ELPIS_OPT_DAU            5
#define ELPIS_OPT_DHU            6
#define ELPIS_OPT_N3U            7
#define ELPIS_OPT_ECS            8
#define ELPIS_OPT_EXPIRE         9
#define ELPIS_OPT_COOKIE         10
#define ELPIS_OPT_TCP_KEEPALIVE  11
#define ELPIS_OPT_PADDING        12
#define ELPIS_OPT_CHAIN          13
#define ELPIS_OPT_KEY_TAG        14
#define ELPIS_OPT_EDE            15
#define ELPIS_OPT_CLIENT_TAG     16
#define ELPIS_OPT_SERVER_TAG     17
#define ELPIS_OPT_REPORT_CHANNEL 18
#define ELPIS_OPT_ZONEVERSION    19

/* ---- extended DNS errors (RFC 8914) ------------------------------ */
#define ELPIS_EDE_OTHER                 0
#define ELPIS_EDE_UNSUPPORTED_DNSKEY    1
#define ELPIS_EDE_UNSUPPORTED_DS_DIGEST 2
#define ELPIS_EDE_STALE_ANSWER          3
#define ELPIS_EDE_FORGED_ANSWER         4
#define ELPIS_EDE_DNSSEC_INDETERMINATE  5
#define ELPIS_EDE_DNSSEC_BOGUS          6
#define ELPIS_EDE_SIGNATURE_EXPIRED     7
#define ELPIS_EDE_SIGNATURE_NOT_YET     8
#define ELPIS_EDE_DNSKEY_MISSING        9
#define ELPIS_EDE_RRSIGS_MISSING        10
#define ELPIS_EDE_NO_ZONE_KEY_BIT       11
#define ELPIS_EDE_NSEC_MISSING          12
#define ELPIS_EDE_CACHED_ERROR          13
#define ELPIS_EDE_NOT_READY             14
#define ELPIS_EDE_BLOCKED               15
#define ELPIS_EDE_CENSORED              16
#define ELPIS_EDE_FILTERED              17
#define ELPIS_EDE_PROHIBITED            18
#define ELPIS_EDE_STALE_NXDOMAIN        19
#define ELPIS_EDE_NOT_AUTHORITATIVE     20
#define ELPIS_EDE_NOT_SUPPORTED         21
#define ELPIS_EDE_NO_REACHABLE_AUTH     22
#define ELPIS_EDE_NETWORK_ERROR         23
#define ELPIS_EDE_INVALID_DATA          24
#define ELPIS_EDE_SIGNATURE_EXPIRED_BW  25
#define ELPIS_EDE_TOO_EARLY             26
#define ELPIS_EDE_UNSUPPORTED_NSEC3_IT  27
#define ELPIS_EDE_UNABLE_TO_CONFORM     28
#define ELPIS_EDE_SYNTHESIZED           29

/* ---- DNSSEC ------------------------------------------------------ */
#define ELPIS_ALG_RSAMD5             1
#define ELPIS_ALG_DH                 2
#define ELPIS_ALG_DSA                3
#define ELPIS_ALG_RSASHA1            5
#define ELPIS_ALG_DSA_NSEC3_SHA1     6
#define ELPIS_ALG_RSASHA1_NSEC3_SHA1 7
#define ELPIS_ALG_RSASHA256          8
#define ELPIS_ALG_RSASHA512          10
#define ELPIS_ALG_ECC_GOST           12
#define ELPIS_ALG_ECDSAP256SHA256    13
#define ELPIS_ALG_ECDSAP384SHA384    14
#define ELPIS_ALG_ED25519            15
#define ELPIS_ALG_ED448              16
#define ELPIS_ALG_SM2SM3             17
#define ELPIS_ALG_ECC_GOST12         23
#define ELPIS_ALG_INDIRECT           252
#define ELPIS_ALG_PRIVATEDNS         253
#define ELPIS_ALG_PRIVATEOID         254

/*
 * ML-DSA (FIPS 204) for DNSSEC: draft-westerbaan-dnssec-mldsa section 5 gives
 * ML-DSA-44 the algorithm number 18, mnemonic MLDSA44, and that is what the
 * deployed test zones sign with.  IANA has not made the assignment final, and
 * the draft registers no number for the 65 and 87 parameter sets at all, so
 * all three stay overridable from elpis.conf:  mldsa44-algorithm: <n>
 *
 * The 65 and 87 values below are placeholders in unassigned space.  They are
 * not interoperable with anything and exist only so a deployment that has
 * agreed on numbers locally can say so.
 */
#define ELPIS_ALG_MLDSA44_DEFAULT    18
#define ELPIS_ALG_MLDSA65_DEFAULT    25
#define ELPIS_ALG_MLDSA87_DEFAULT    26

#define ELPIS_DS_SHA1        1
#define ELPIS_DS_SHA256      2
#define ELPIS_DS_GOST        3
#define ELPIS_DS_SHA384      4
#define ELPIS_DS_GOST12      5
#define ELPIS_DS_SM3         6

#define ELPIS_DNSKEY_ZONE    0x0100u   /* bit 7  */
#define ELPIS_DNSKEY_REVOKE  0x0080u   /* bit 8  */
#define ELPIS_DNSKEY_SEP     0x0001u   /* bit 15 */

#define ELPIS_NSEC3_SHA1     1
#define ELPIS_NSEC3_OPTOUT   0x01u

/* Security status of cached data (RFC 4035 section 4.3). */
typedef enum {
    ELPIS_SEC_UNCHECKED = 0,
    ELPIS_SEC_INDETERMINATE = 1,
    ELPIS_SEC_INSECURE  = 2,
    ELPIS_SEC_SECURE    = 3,
    ELPIS_SEC_BOGUS     = 4
} elpis_sec_t;

const char *elpis_rcode_name(unsigned rcode);
const char *elpis_type_name(uint16_t t);
const char *elpis_class_name(uint16_t c);
const char *elpis_sec_name(elpis_sec_t s);
const char *elpis_opcode_name(unsigned op);
const char *elpis_alg_name(uint8_t alg);
/* Text -> numeric; also accepts TYPE#### / CLASS#### (RFC 3597). */
int elpis_type_parse(const char *s, uint16_t *out);
int elpis_class_parse(const char *s, uint16_t *out);

/* Types that may only ever appear once per name (RFC 2181 section 10.1). */
int elpis_type_is_singleton(uint16_t t);
/* Meta types that must never be cached or appear in an answer section. */
int elpis_type_is_meta(uint16_t t);

#endif /* ELPIS_DNS_H */
