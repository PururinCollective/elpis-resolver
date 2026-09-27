/*
 * rdata.c -- per-type RDATA descriptors, validation, canonicalisation.
 */
#include "elpis/rdata.h"
#include "elpis/log.h"
#include "elpis/util.h"
#include "elpis/simd.h"

#include <stdarg.h>

/* ================================================================== */
/* Descriptor table                                                    */
/* ================================================================== */

typedef struct {
    uint16_t       type;
    const char    *name;
    const uint8_t *f;
    /*
     * Names in this type's rdata are case-folded for the DNSSEC canonical
     * form.  RFC 4034 section 6.2, corrected by RFC 6840 section 5.1: HINFO
     * carries no names, NSEC's next-domain keeps its case, RRSIG's signer is
     * folded, and the list is closed to types defined after RFC 4034.
     */
    uint8_t        downcase;
} rr_desc_t;

#define F(name, ...) static const uint8_t f_##name[] = { __VA_ARGS__, RDF_END }

F(a,          RDF_A);
F(aaaa,       RDF_AAAA);
F(name,       RDF_NAME);
F(name_unc,   RDF_NAME_UNC);
F(soa,        RDF_NAME, RDF_NAME, RDF_U32, RDF_U32, RDF_U32, RDF_U32, RDF_U32);
F(wks,        RDF_WKS);
F(hinfo,      RDF_STR, RDF_STR);
F(minfo,      RDF_NAME, RDF_NAME);
F(mx,         RDF_U16, RDF_NAME);
F(txt,        RDF_STR, RDF_STRS);
F(afsdb,      RDF_U16, RDF_NAME);
F(x25,        RDF_STR);
F(isdn,       RDF_STR, RDF_STRS);
F(nsap,       RDF_BLOB1);
F(px,         RDF_U16, RDF_NAME, RDF_NAME);
F(gpos,       RDF_STR, RDF_STR, RDF_STR);
F(loc,        RDF_LOC);
F(nxt,        RDF_NAME, RDF_BLOB);
F(srv,        RDF_U16, RDF_U16, RDF_U16, RDF_NAME_UNC);
F(naptr,      RDF_U16, RDF_U16, RDF_STR, RDF_STR, RDF_STR, RDF_NAME_UNC);
F(kx,         RDF_U16, RDF_NAME_UNC);
F(cert,       RDF_U16, RDF_U16, RDF_U8, RDF_BLOB);
F(ds,         RDF_U16, RDF_U8, RDF_U8, RDF_BLOB1);
F(sshfp,      RDF_U8, RDF_U8, RDF_BLOB1);
F(ipseckey,   RDF_IPSECKEY);
F(rrsig,      RDF_U16, RDF_U8, RDF_U8, RDF_U32, RDF_U32, RDF_U32, RDF_U16,
              RDF_NAME_UNC, RDF_BLOB1);
F(nsec,       RDF_NAME_UNC, RDF_BITMAP);
F(dnskey,     RDF_U16, RDF_U8, RDF_U8, RDF_BLOB1);
F(dhcid,      RDF_BLOB1);
F(nsec3,      RDF_U8, RDF_U8, RDF_U16, RDF_NSEC3_SALT, RDF_NSEC3_HASH, RDF_BITMAP);
F(nsec3param, RDF_U8, RDF_U8, RDF_U16, RDF_NSEC3_SALT);
F(tlsa,       RDF_U8, RDF_U8, RDF_U8, RDF_BLOB1);
F(hip,        RDF_HIP);
F(csync,      RDF_U32, RDF_U16, RDF_BITMAP);
F(zonemd,     RDF_U32, RDF_U8, RDF_U8, RDF_BLOB1);
F(svcb,       RDF_U16, RDF_NAME_UNC, RDF_SVCPARAMS);
F(openpgpkey, RDF_BLOB1);
F(nid,        RDF_U16, RDF_U64);
F(l32,        RDF_U16, RDF_U32);
F(l64,        RDF_U16, RDF_U64);
F(lp,         RDF_U16, RDF_NAME_UNC);
F(eui48,      RDF_U48);
F(eui64,      RDF_U64);
F(uri,        RDF_U16, RDF_U16, RDF_BLOB1);
F(caa,        RDF_U8, RDF_STR, RDF_BLOB);
F(apl,        RDF_APL);
F(amtrelay,   RDF_AMTRELAY);
F(dsync,      RDF_U16, RDF_U8, RDF_U16, RDF_NAME_UNC);
F(blob,       RDF_BLOB);

/*
 * Sorted by type so lookups can binary search.  A missing entry means
 * RFC 3597 opaque handling.
 */
static const rr_desc_t k_desc[] = {
    { ELPIS_T_A,          "A",          f_a,          0 },
    { ELPIS_T_NS,         "NS",         f_name,       1 },
    { ELPIS_T_MD,         "MD",         f_name,       1 },
    { ELPIS_T_MF,         "MF",         f_name,       1 },
    { ELPIS_T_CNAME,      "CNAME",      f_name,       1 },
    { ELPIS_T_SOA,        "SOA",        f_soa,        1 },
    { ELPIS_T_MB,         "MB",         f_name,       1 },
    { ELPIS_T_MG,         "MG",         f_name,       1 },
    { ELPIS_T_MR,         "MR",         f_name,       1 },
    { ELPIS_T_NULL,       "NULL",       f_blob,       0 },
    { ELPIS_T_WKS,        "WKS",        f_wks,        0 },
    { ELPIS_T_PTR,        "PTR",        f_name,       1 },
    { ELPIS_T_HINFO,      "HINFO",      f_hinfo,      0 },
    { ELPIS_T_MINFO,      "MINFO",      f_minfo,      1 },
    { ELPIS_T_MX,         "MX",         f_mx,         1 },
    { ELPIS_T_TXT,        "TXT",        f_txt,        0 },
    { ELPIS_T_RP,         "RP",         f_minfo,      1 },
    { ELPIS_T_AFSDB,      "AFSDB",      f_afsdb,      1 },
    { ELPIS_T_X25,        "X25",        f_x25,        0 },
    { ELPIS_T_ISDN,       "ISDN",       f_isdn,       0 },
    { ELPIS_T_RT,         "RT",         f_afsdb,      1 },
    { ELPIS_T_NSAP,       "NSAP",       f_nsap,       0 },
    { ELPIS_T_NSAP_PTR,   "NSAP-PTR",   f_name,       1 },
    { ELPIS_T_SIG,        "SIG",        f_rrsig,      1 },
    { ELPIS_T_KEY,        "KEY",        f_dnskey,     0 },
    { ELPIS_T_PX,         "PX",         f_px,         1 },
    { ELPIS_T_GPOS,       "GPOS",       f_gpos,       0 },
    { ELPIS_T_AAAA,       "AAAA",       f_aaaa,       0 },
    { ELPIS_T_LOC,        "LOC",        f_loc,        0 },
    { ELPIS_T_NXT,        "NXT",        f_nxt,        1 },
    { ELPIS_T_SRV,        "SRV",        f_srv,        1 },
    { ELPIS_T_NAPTR,      "NAPTR",      f_naptr,      1 },
    { ELPIS_T_KX,         "KX",         f_kx,         1 },
    { ELPIS_T_CERT,       "CERT",       f_cert,       0 },
    { ELPIS_T_A6,         "A6",         f_blob,       0 },
    { ELPIS_T_DNAME,      "DNAME",      f_name_unc,   1 },
    { ELPIS_T_APL,        "APL",        f_apl,        0 },
    { ELPIS_T_DS,         "DS",         f_ds,         0 },
    { ELPIS_T_SSHFP,      "SSHFP",      f_sshfp,      0 },
    { ELPIS_T_IPSECKEY,   "IPSECKEY",   f_ipseckey,   0 },
    { ELPIS_T_RRSIG,      "RRSIG",      f_rrsig,      1 },
    { ELPIS_T_NSEC,       "NSEC",       f_nsec,       0 },
    { ELPIS_T_DNSKEY,     "DNSKEY",     f_dnskey,     0 },
    { ELPIS_T_DHCID,      "DHCID",      f_dhcid,      0 },
    { ELPIS_T_NSEC3,      "NSEC3",      f_nsec3,      0 },
    { ELPIS_T_NSEC3PARAM, "NSEC3PARAM", f_nsec3param, 0 },
    { ELPIS_T_TLSA,       "TLSA",       f_tlsa,       0 },
    { ELPIS_T_SMIMEA,     "SMIMEA",     f_tlsa,       0 },
    { ELPIS_T_HIP,        "HIP",        f_hip,        0 },
    { ELPIS_T_NINFO,      "NINFO",      f_txt,        0 },
    { ELPIS_T_RKEY,       "RKEY",       f_dnskey,     0 },
    { ELPIS_T_TALINK,     "TALINK",     f_minfo,      0 },
    { ELPIS_T_CDS,        "CDS",        f_ds,         0 },
    { ELPIS_T_CDNSKEY,    "CDNSKEY",    f_dnskey,     0 },
    { ELPIS_T_OPENPGPKEY, "OPENPGPKEY", f_openpgpkey, 0 },
    { ELPIS_T_CSYNC,      "CSYNC",      f_csync,      0 },
    { ELPIS_T_ZONEMD,     "ZONEMD",     f_zonemd,     0 },
    { ELPIS_T_SVCB,       "SVCB",       f_svcb,       0 },
    { ELPIS_T_HTTPS,      "HTTPS",      f_svcb,       0 },
    { ELPIS_T_DSYNC,      "DSYNC",      f_dsync,      0 },
    { ELPIS_T_SPF,        "SPF",        f_txt,        0 },
    { ELPIS_T_NID,        "NID",        f_nid,        0 },
    { ELPIS_T_L32,        "L32",        f_l32,        0 },
    { ELPIS_T_L64,        "L64",        f_l64,        0 },
    { ELPIS_T_LP,         "LP",         f_lp,         0 },
    { ELPIS_T_EUI48,      "EUI48",      f_eui48,      0 },
    { ELPIS_T_EUI64,      "EUI64",      f_eui64,      0 },
    { ELPIS_T_URI,        "URI",        f_uri,        0 },
    { ELPIS_T_CAA,        "CAA",        f_caa,        0 },
    { ELPIS_T_AVC,        "AVC",        f_txt,        0 },
    { ELPIS_T_AMTRELAY,   "AMTRELAY",   f_amtrelay,   0 },
    { ELPIS_T_RESINFO,    "RESINFO",    f_txt,        0 }
};

/* Types with no rdata layout of their own: meta and query types. */
static const struct { uint16_t t; const char *n; } k_meta[] = {
    { ELPIS_T_OPT,   "OPT"   }, { ELPIS_T_TKEY,  "TKEY"  },
    { ELPIS_T_TSIG,  "TSIG"  }, { ELPIS_T_IXFR,  "IXFR"  },
    { ELPIS_T_AXFR,  "AXFR"  }, { ELPIS_T_MAILB, "MAILB" },
    { ELPIS_T_MAILA, "MAILA" }, { ELPIS_T_ANY,   "ANY"   },
    { ELPIS_T_TA,    "TA"    }, { ELPIS_T_DLV,   "DLV"   }
};

/*
 * These helpers return a pointer valid until the caller's next few calls.
 * A per-thread ring keeps them usable in a single printf with several
 * conversions, without forcing every call site to carry a buffer.
 */
#define SCRATCH_SLOTS 8
#define SCRATCH_SIZE  24
static ELPIS_TLS char  g_scratch[SCRATCH_SLOTS][SCRATCH_SIZE];
static ELPIS_TLS unsigned g_scratch_i;

static char *scratch(void)
{
    char *p = g_scratch[g_scratch_i];
    g_scratch_i = (g_scratch_i + 1u) % SCRATCH_SLOTS;
    return p;
}

static const rr_desc_t *desc_of(uint16_t type)
{
    size_t lo = 0, hi = ELPIS_ARRAY_LEN(k_desc);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (k_desc[mid].type == type)
            return &k_desc[mid];
        if (k_desc[mid].type < type)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/* ================================================================== */
/* Names                                                               */
/* ================================================================== */

const char *elpis_type_name(uint16_t t)
{
    char *buf;
    const rr_desc_t *d = desc_of(t);
    size_t i;

    if (d != NULL)
        return d->name;
    for (i = 0; i < ELPIS_ARRAY_LEN(k_meta); i++)
        if (k_meta[i].t == t)
            return k_meta[i].n;
    buf = scratch();
    snprintf(buf, SCRATCH_SIZE, "TYPE%u", (unsigned)t);
    return buf;
}

const char *elpis_class_name(uint16_t c)
{
    char *buf;
    switch (c) {
    case ELPIS_CLASS_IN:   return "IN";
    case ELPIS_CLASS_CH:   return "CH";
    case ELPIS_CLASS_HS:   return "HS";
    case ELPIS_CLASS_NONE: return "NONE";
    case ELPIS_CLASS_ANY:  return "ANY";
    default:
        buf = scratch();
        snprintf(buf, SCRATCH_SIZE, "CLASS%u", (unsigned)c);
        return buf;
    }
}

const char *elpis_rcode_name(unsigned rcode)
{
    static const char *const n[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI"
    };
    char *buf;
    if (rcode < ELPIS_ARRAY_LEN(n))
        return n[rcode];
    switch (rcode) {
    case ELPIS_RC_BADVERS:   return "BADVERS";
    case ELPIS_RC_BADKEY:    return "BADKEY";
    case ELPIS_RC_BADTIME:   return "BADTIME";
    case ELPIS_RC_BADMODE:   return "BADMODE";
    case ELPIS_RC_BADNAME:   return "BADNAME";
    case ELPIS_RC_BADALG:    return "BADALG";
    case ELPIS_RC_BADTRUNC:  return "BADTRUNC";
    case ELPIS_RC_BADCOOKIE: return "BADCOOKIE";
    default:
        buf = scratch();
        snprintf(buf, SCRATCH_SIZE, "RCODE%u", rcode);
        return buf;
    }
}

const char *elpis_opcode_name(unsigned op)
{
    char *buf;
    switch (op) {
    case ELPIS_OP_QUERY:  return "QUERY";
    case ELPIS_OP_IQUERY: return "IQUERY";
    case ELPIS_OP_STATUS: return "STATUS";
    case ELPIS_OP_NOTIFY: return "NOTIFY";
    case ELPIS_OP_UPDATE: return "UPDATE";
    case ELPIS_OP_DSO:    return "DSO";
    default:
        buf = scratch();
        snprintf(buf, SCRATCH_SIZE, "OPCODE%u", op);
        return buf;
    }
}

const char *elpis_sec_name(elpis_sec_t s)
{
    switch (s) {
    case ELPIS_SEC_UNCHECKED:     return "unchecked";
    case ELPIS_SEC_INDETERMINATE: return "indeterminate";
    case ELPIS_SEC_INSECURE:      return "insecure";
    case ELPIS_SEC_SECURE:        return "secure";
    case ELPIS_SEC_BOGUS:         return "bogus";
    default:                      return "?";
    }
}

const char *elpis_alg_name(uint8_t alg)
{
    char *buf;
    switch (alg) {
    case ELPIS_ALG_RSAMD5:             return "RSAMD5";
    case ELPIS_ALG_DSA:                return "DSA";
    case ELPIS_ALG_RSASHA1:            return "RSASHA1";
    case ELPIS_ALG_DSA_NSEC3_SHA1:     return "DSA-NSEC3-SHA1";
    case ELPIS_ALG_RSASHA1_NSEC3_SHA1: return "RSASHA1-NSEC3-SHA1";
    case ELPIS_ALG_RSASHA256:          return "RSASHA256";
    case ELPIS_ALG_RSASHA512:          return "RSASHA512";
    case ELPIS_ALG_ECDSAP256SHA256:    return "ECDSAP256SHA256";
    case ELPIS_ALG_ECDSAP384SHA384:    return "ECDSAP384SHA384";
    case ELPIS_ALG_ED25519:            return "ED25519";
    case ELPIS_ALG_ED448:              return "ED448";
    default:
        buf = scratch();
        snprintf(buf, SCRATCH_SIZE, "ALG%u", (unsigned)alg);
        return buf;
    }
}

int elpis_type_parse(const char *s, uint16_t *out)
{
    size_t i;
    uint32_t v;

    for (i = 0; i < ELPIS_ARRAY_LEN(k_desc); i++)
        if (!elpis_strcasecmp_ascii(s, k_desc[i].name)) {
            *out = k_desc[i].type;
            return 0;
        }
    for (i = 0; i < ELPIS_ARRAY_LEN(k_meta); i++)
        if (!elpis_strcasecmp_ascii(s, k_meta[i].n)) {
            *out = k_meta[i].t;
            return 0;
        }
    if (strlen(s) > 4 &&
        (s[0] == 'T' || s[0] == 't') && (s[1] == 'Y' || s[1] == 'y') &&
        (s[2] == 'P' || s[2] == 'p') && (s[3] == 'E' || s[3] == 'e')) {
        if (elpis_parse_u32(s + 4, &v) == 0 && v <= 0xFFFF) {
            *out = (uint16_t)v;
            return 0;
        }
    }
    return -1;
}

int elpis_class_parse(const char *s, uint16_t *out)
{
    uint32_t v;
    if (!elpis_strcasecmp_ascii(s, "IN"))   { *out = ELPIS_CLASS_IN;   return 0; }
    if (!elpis_strcasecmp_ascii(s, "CH"))   { *out = ELPIS_CLASS_CH;   return 0; }
    if (!elpis_strcasecmp_ascii(s, "HS"))   { *out = ELPIS_CLASS_HS;   return 0; }
    if (!elpis_strcasecmp_ascii(s, "NONE")) { *out = ELPIS_CLASS_NONE; return 0; }
    if (!elpis_strcasecmp_ascii(s, "ANY"))  { *out = ELPIS_CLASS_ANY;  return 0; }
    /* RFC 3597 generic form: CLASS#### */
    if (strlen(s) > 5 &&
        (s[0] == 'C' || s[0] == 'c') && (s[1] == 'L' || s[1] == 'l') &&
        (s[2] == 'A' || s[2] == 'a') && (s[3] == 'S' || s[3] == 's') &&
        (s[4] == 'S' || s[4] == 's') &&
        elpis_parse_u32(s + 5, &v) == 0 && v <= 0xFFFF) {
        *out = (uint16_t)v;
        return 0;
    }
    return -1;
}

int elpis_type_is_singleton(uint16_t t)
{
    return t == ELPIS_T_CNAME || t == ELPIS_T_DNAME || t == ELPIS_T_SOA;
}

int elpis_type_is_meta(uint16_t t)
{
    return t == ELPIS_T_OPT || t == ELPIS_T_TSIG || t == ELPIS_T_TKEY ||
           t == ELPIS_T_IXFR || t == ELPIS_T_AXFR || t == ELPIS_T_ANY ||
           t == ELPIS_T_MAILA || t == ELPIS_T_MAILB;
}

int elpis_rdata_downcase(uint16_t type)
{
    const rr_desc_t *d = desc_of(type);
    return d != NULL && d->downcase;
}

/* ================================================================== */
/* Type bitmaps                                                        */
/* ================================================================== */

int elpis_bitmap_validate(const uint8_t *bm, size_t bmlen)
{
    size_t i = 0;
    int last = -1;

    while (i < bmlen) {
        unsigned win, len;
        if (i + 2 > bmlen)
            return ELPIS_EFORMAT;
        win = bm[i];
        len = bm[i + 1];
        if (len == 0 || len > 32)
            return ELPIS_EFORMAT;
        if ((int)win <= last)
            return ELPIS_EFORMAT;        /* windows must strictly increase */
        last = (int)win;
        if (i + 2 + len > bmlen)
            return ELPIS_EFORMAT;
        i += 2 + len;
    }
    return ELPIS_OK;
}

int elpis_bitmap_has(const uint8_t *bm, size_t bmlen, uint16_t type)
{
    unsigned want_win = (unsigned)(type >> 8);
    unsigned bit      = (unsigned)(type & 0xFF);
    size_t i = 0;

    while (i + 2 <= bmlen) {
        unsigned win = bm[i];
        unsigned len = bm[i + 1];
        if (len == 0 || len > 32 || i + 2 + len > bmlen)
            return 0;
        if (win == want_win) {
            unsigned byte = bit / 8u;
            if (byte >= len)
                return 0;
            return (bm[i + 2 + byte] >> (7u - (bit % 8u))) & 1u;
        }
        if (win > want_win)
            return 0;
        i += 2 + len;
    }
    return 0;
}

/* ================================================================== */
/* The walker: validate and/or copy                                    */
/* ================================================================== */

typedef struct {
    const uint8_t *wire;      /* whole message, for compression pointers */
    size_t         wlen;
    size_t         p;         /* cursor within the message               */
    size_t         stop;      /* end of this rdata                        */
    uint8_t       *out;       /* NULL to validate only                    */
    size_t         osz;
    size_t         olen;
    int            downcase;
    int            drop;
} walk_t;

static int w_need(walk_t *w, size_t n)
{
    if (w->p + n > w->stop) {
        w->drop = ELPIS_DROP_RDATA;
        return 0;
    }
    return 1;
}

static int w_copy(walk_t *w, size_t n)
{
    if (!w_need(w, n))
        return ELPIS_EFORMAT;
    if (w->out != NULL) {
        if (w->olen + n > w->osz)
            return ELPIS_ETRUNC;
        memcpy(w->out + w->olen, w->wire + w->p, n);
        w->olen += n;
    }
    w->p += n;
    return ELPIS_OK;
}

static int w_name(walk_t *w, int fold)
{
    elpis_name_t n;
    size_t end;
    int d = 0;

    /*
     * Compression pointers are honoured for every known type, not only the
     * RFC 1035 set.  Refusing them here would mis-parse the (non-conforming
     * but real) traffic that compresses SRV and NAPTR targets, and the name
     * we produce is fully expanded either way.
     */
    if (elpis_name_parse(&n, w->wire, w->wlen, w->p, &end, &d) != ELPIS_OK) {
        w->drop = d;
        return ELPIS_EFORMAT;
    }
    if (end > w->stop) {
        w->drop = ELPIS_DROP_RDATA;
        return ELPIS_EFORMAT;
    }
    if (fold && w->downcase)
        elpis_name_lower(&n);
    if (w->out != NULL) {
        if (w->olen + n.len > w->osz)
            return ELPIS_ETRUNC;
        memcpy(w->out + w->olen, n.d, n.len);
        w->olen += n.len;
    }
    w->p = end;
    return ELPIS_OK;
}

static int w_str(walk_t *w)
{
    unsigned l;
    if (!w_need(w, 1))
        return ELPIS_EFORMAT;
    l = w->wire[w->p];
    return w_copy(w, 1u + l);
}

static int walk(walk_t *w, const uint8_t *f)
{
    int rc;

    for (; *f != RDF_END; f++) {
        switch (*f) {
        case RDF_U8:   rc = w_copy(w, 1);  break;
        case RDF_U16:  rc = w_copy(w, 2);  break;
        case RDF_U32:  rc = w_copy(w, 4);  break;
        case RDF_U48:  rc = w_copy(w, 6);  break;
        case RDF_U64:  rc = w_copy(w, 8);  break;
        case RDF_A:    rc = w_copy(w, 4);  break;
        case RDF_AAAA: rc = w_copy(w, 16); break;

        case RDF_NAME:
        case RDF_NAME_UNC:
            rc = w_name(w, 1);
            break;

        case RDF_STR:
            rc = w_str(w);
            break;

        case RDF_STRS:
            rc = ELPIS_OK;
            while (w->p < w->stop && rc == ELPIS_OK)
                rc = w_str(w);
            break;

        case RDF_BLOB:
            rc = w_copy(w, w->stop - w->p);
            break;

        case RDF_BLOB1:
            if (w->p >= w->stop) {
                w->drop = ELPIS_DROP_RDATA;
                return ELPIS_EFORMAT;
            }
            rc = w_copy(w, w->stop - w->p);
            break;

        case RDF_BITMAP:
            if (elpis_bitmap_validate(w->wire + w->p, w->stop - w->p) != ELPIS_OK) {
                w->drop = ELPIS_DROP_RDATA;
                return ELPIS_EFORMAT;
            }
            rc = w_copy(w, w->stop - w->p);
            break;

        case RDF_NSEC3_SALT:
        case RDF_NSEC3_HASH: {
            unsigned l;
            if (!w_need(w, 1))
                return ELPIS_EFORMAT;
            l = w->wire[w->p];
            if (*f == RDF_NSEC3_HASH && l == 0) {
                w->drop = ELPIS_DROP_RDATA;   /* next hashed owner is required */
                return ELPIS_EFORMAT;
            }
            rc = w_copy(w, 1u + l);
            break;
        }

        case RDF_LOC: {
            size_t rem = w->stop - w->p;
            if (rem < 1) { w->drop = ELPIS_DROP_RDATA; return ELPIS_EFORMAT; }
            if (w->wire[w->p] == 0 && rem != 16) {
                w->drop = ELPIS_DROP_RDATA;   /* version 0 is exactly 16 octets */
                return ELPIS_EFORMAT;
            }
            rc = w_copy(w, rem);
            break;
        }

        case RDF_WKS:
            if (w->stop - w->p < 5) { w->drop = ELPIS_DROP_RDATA; return ELPIS_EFORMAT; }
            rc = w_copy(w, w->stop - w->p);
            break;

        case RDF_IPSECKEY: {
            unsigned gwtype;
            if (!w_need(w, 3)) return ELPIS_EFORMAT;
            gwtype = w->wire[w->p + 1];
            rc = w_copy(w, 3);
            if (rc != ELPIS_OK) break;
            switch (gwtype) {
            case 0: break;
            case 1: rc = w_copy(w, 4);  break;
            case 2: rc = w_copy(w, 16); break;
            case 3: rc = w_name(w, 0);  break;   /* never case-folded */
            default:
                w->drop = ELPIS_DROP_RDATA;
                return ELPIS_EFORMAT;
            }
            if (rc == ELPIS_OK && w->p < w->stop)
                rc = w_copy(w, w->stop - w->p);
            break;
        }

        case RDF_HIP: {
            unsigned hitlen, pklen;
            if (!w_need(w, 4)) return ELPIS_EFORMAT;
            hitlen = w->wire[w->p];
            pklen  = elpis_get16(w->wire + w->p + 2);
            if (hitlen == 0 || pklen == 0) {
                w->drop = ELPIS_DROP_RDATA;
                return ELPIS_EFORMAT;
            }
            rc = w_copy(w, 4u + hitlen + pklen);
            while (rc == ELPIS_OK && w->p < w->stop)
                rc = w_name(w, 0);
            break;
        }

        case RDF_APL:
            rc = ELPIS_OK;
            while (w->p < w->stop && rc == ELPIS_OK) {
                unsigned n;
                if (!w_need(w, 4)) return ELPIS_EFORMAT;
                n = w->wire[w->p + 3] & 0x7Fu;
                if (w->wire[w->p + 2] > 128) {    /* prefix length */
                    w->drop = ELPIS_DROP_RDATA;
                    return ELPIS_EFORMAT;
                }
                rc = w_copy(w, 4u + n);
            }
            break;

        case RDF_AMTRELAY: {
            unsigned rtype;
            if (!w_need(w, 2)) return ELPIS_EFORMAT;
            rtype = w->wire[w->p + 1] & 0x7Fu;
            rc = w_copy(w, 2);
            if (rc != ELPIS_OK) break;
            switch (rtype) {
            case 0: break;
            case 1: rc = w_copy(w, 4);  break;
            case 2: rc = w_copy(w, 16); break;
            case 3: rc = w_name(w, 0);  break;
            default:
                w->drop = ELPIS_DROP_RDATA;
                return ELPIS_EFORMAT;
            }
            break;
        }

        case RDF_SVCPARAMS: {
            long last = -1;
            rc = ELPIS_OK;
            while (w->p < w->stop && rc == ELPIS_OK) {
                unsigned key, vlen;
                if (!w_need(w, 4)) return ELPIS_EFORMAT;
                key  = elpis_get16(w->wire + w->p);
                vlen = elpis_get16(w->wire + w->p + 2);
                /* RFC 9460: keys appear at most once, in ascending order. */
                if ((long)key <= last) {
                    w->drop = ELPIS_DROP_RDATA;
                    return ELPIS_EFORMAT;
                }
                last = (long)key;
                rc = w_copy(w, 4u + vlen);
            }
            break;
        }

        default:
            w->drop = ELPIS_DROP_RDATA;
            return ELPIS_EFORMAT;
        }

        if (rc != ELPIS_OK)
            return rc;
    }

    /* Trailing octets the descriptor did not account for mean a bad record. */
    if (w->p != w->stop) {
        w->drop = ELPIS_DROP_RDATA;
        return ELPIS_EFORMAT;
    }
    return ELPIS_OK;
}

int elpis_rdata_validate(uint16_t type, const uint8_t *wire, size_t len,
                         size_t rdoff, uint16_t rdlen, int *drop)
{
    const rr_desc_t *d = desc_of(type);
    walk_t w;

    if (rdoff + rdlen > len) {
        *drop = ELPIS_DROP_RDLEN;
        return ELPIS_EFORMAT;
    }
    if (d == NULL) {
        *drop = ELPIS_DROP_NONE;
        return ELPIS_OK;          /* RFC 3597 opaque */
    }

    memset(&w, 0, sizeof w);
    w.wire = wire;
    w.wlen = len;
    w.p    = rdoff;
    w.stop = rdoff + rdlen;
    w.drop = ELPIS_DROP_RDATA;

    if (walk(&w, d->f) != ELPIS_OK) {
        *drop = w.drop;
        return ELPIS_EFORMAT;
    }
    *drop = ELPIS_DROP_NONE;
    return ELPIS_OK;
}

int elpis_rdata_canonical(uint16_t type, const uint8_t *wire, size_t len,
                          size_t rdoff, uint16_t rdlen,
                          uint8_t *out, size_t outsz, size_t *outlen,
                          int downcase)
{
    const rr_desc_t *d = desc_of(type);
    walk_t w;
    int rc;

    if (rdoff + rdlen > len)
        return ELPIS_EFORMAT;

    if (d == NULL) {
        if (rdlen > outsz)
            return ELPIS_ETRUNC;
        memcpy(out, wire + rdoff, rdlen);
        *outlen = rdlen;
        return ELPIS_OK;
    }

    memset(&w, 0, sizeof w);
    w.wire     = wire;
    w.wlen     = len;
    w.p        = rdoff;
    w.stop     = rdoff + rdlen;
    w.out      = out;
    w.osz      = outsz;
    w.downcase = downcase && d->downcase;
    w.drop     = ELPIS_DROP_RDATA;

    rc = walk(&w, d->f);
    if (rc != ELPIS_OK)
        return rc;
    *outlen = w.olen;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Name harvesting over already-decompressed rdata                     */
int elpis_rdata_target(uint16_t type, const uint8_t *rd, size_t rdlen,
                       elpis_name_t *out)
{
    size_t off = 0, used;

    switch (type) {
    case ELPIS_T_NS: case ELPIS_T_CNAME: case ELPIS_T_DNAME:
    case ELPIS_T_PTR: case ELPIS_T_MB: case ELPIS_T_MD: case ELPIS_T_MF:
    case ELPIS_T_MG: case ELPIS_T_MR: case ELPIS_T_NSAP_PTR:
    case ELPIS_T_SOA:
        off = 0;
        break;
    case ELPIS_T_MX: case ELPIS_T_AFSDB: case ELPIS_T_RT:
    case ELPIS_T_KX: case ELPIS_T_LP:
        off = 2;
        break;
    case ELPIS_T_SRV:
        off = 6;
        break;
    case ELPIS_T_SVCB: case ELPIS_T_HTTPS:
        off = 2;
        break;
    case ELPIS_T_NAPTR: {
        size_t p = 4;
        int i;
        for (i = 0; i < 3; i++) {
            if (p >= rdlen) return ELPIS_EFORMAT;
            p += 1u + rd[p];
        }
        off = p;
        break;
    }
    default:
        return ELPIS_ENOTFOUND;
    }
    if (off > rdlen)
        return ELPIS_EFORMAT;
    return elpis_name_parse_nocomp(out, rd + off, rdlen - off, &used);
}

/* ------------------------------------------------------------------ */
/* Presentation format (logs, cache dump)                              */
/* ------------------------------------------------------------------ */

static int txt_append(char *buf, size_t sz, size_t *o, const char *fmt, ...)
    ELPIS_PRINTF(4, 5);

static int txt_append(char *buf, size_t sz, size_t *o, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (*o >= sz)
        return ELPIS_ETRUNC;
    va_start(ap, fmt);
    n = vsnprintf(buf + *o, sz - *o, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sz - *o)
        return ELPIS_ETRUNC;
    *o += (size_t)n;
    return ELPIS_OK;
}

static int hex_append(char *buf, size_t sz, size_t *o,
                      const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;
    if (*o + n * 2 + 1 > sz)
        return ELPIS_ETRUNC;
    for (i = 0; i < n; i++) {
        buf[(*o)++] = hx[p[i] >> 4];
        buf[(*o)++] = hx[p[i] & 0x0F];
    }
    buf[*o] = '\0';
    return ELPIS_OK;
}

int elpis_rdata_to_text(uint16_t type, const uint8_t *rd, size_t rdlen,
                        char *buf, size_t sz)
{
    size_t o = 0;
    char nbuf[ELPIS_MAX_NAME * 4 + 8];
    elpis_name_t n;
    size_t used;

    if (sz == 0)
        return ELPIS_ETRUNC;
    buf[0] = '\0';

    switch (type) {
    case ELPIS_T_A:
        if (rdlen != 4) break;
        if (elpis_ntop4(rd, nbuf, sizeof nbuf) != 0) break;
        return txt_append(buf, sz, &o, "%s", nbuf);

    case ELPIS_T_AAAA:
        if (rdlen != 16) break;
        if (elpis_ntop6(rd, nbuf, sizeof nbuf) != 0) break;
        return txt_append(buf, sz, &o, "%s", nbuf);

    case ELPIS_T_NS: case ELPIS_T_CNAME: case ELPIS_T_PTR: case ELPIS_T_DNAME:
        if (elpis_name_parse_nocomp(&n, rd, rdlen, &used) != ELPIS_OK) break;
        elpis_name_to_text(&n, nbuf, sizeof nbuf);
        return txt_append(buf, sz, &o, "%s", nbuf);

    case ELPIS_T_MX:
        if (rdlen < 3) break;
        if (elpis_name_parse_nocomp(&n, rd + 2, rdlen - 2, &used) != ELPIS_OK) break;
        elpis_name_to_text(&n, nbuf, sizeof nbuf);
        return txt_append(buf, sz, &o, "%u %s", (unsigned)elpis_get16(rd), nbuf);

    case ELPIS_T_SOA: {
        elpis_name_t mname, rname;
        size_t u1, u2;
        if (elpis_name_parse_nocomp(&mname, rd, rdlen, &u1) != ELPIS_OK) break;
        if (elpis_name_parse_nocomp(&rname, rd + u1, rdlen - u1, &u2) != ELPIS_OK) break;
        if (u1 + u2 + 20 != rdlen) break;
        elpis_name_to_text(&mname, nbuf, sizeof nbuf);
        if (txt_append(buf, sz, &o, "%s ", nbuf) != ELPIS_OK) return ELPIS_ETRUNC;
        elpis_name_to_text(&rname, nbuf, sizeof nbuf);
        return txt_append(buf, sz, &o, "%s %lu %lu %lu %lu %lu", nbuf,
                          (unsigned long)elpis_get32(rd + u1 + u2),
                          (unsigned long)elpis_get32(rd + u1 + u2 + 4),
                          (unsigned long)elpis_get32(rd + u1 + u2 + 8),
                          (unsigned long)elpis_get32(rd + u1 + u2 + 12),
                          (unsigned long)elpis_get32(rd + u1 + u2 + 16));
    }

    case ELPIS_T_SRV:
        if (rdlen < 7) break;
        if (elpis_name_parse_nocomp(&n, rd + 6, rdlen - 6, &used) != ELPIS_OK) break;
        elpis_name_to_text(&n, nbuf, sizeof nbuf);
        return txt_append(buf, sz, &o, "%u %u %u %s",
                          (unsigned)elpis_get16(rd), (unsigned)elpis_get16(rd + 2),
                          (unsigned)elpis_get16(rd + 4), nbuf);

    case ELPIS_T_TXT: case ELPIS_T_SPF: {
        size_t p = 0;
        while (p < rdlen) {
            unsigned l = rd[p];
            size_t i;
            if (p + 1u + l > rdlen) break;
            if (txt_append(buf, sz, &o, "%s\"", p ? " " : "") != ELPIS_OK)
                return ELPIS_ETRUNC;
            for (i = 0; i < l; i++) {
                uint8_t c = rd[p + 1 + i];
                int rc = (c >= 0x20 && c < 0x7F && c != '"' && c != '\\')
                       ? txt_append(buf, sz, &o, "%c", (char)c)
                       : txt_append(buf, sz, &o, "\\%03u", (unsigned)c);
                if (rc != ELPIS_OK) return ELPIS_ETRUNC;
            }
            if (txt_append(buf, sz, &o, "\"") != ELPIS_OK) return ELPIS_ETRUNC;
            p += 1u + l;
        }
        return ELPIS_OK;
    }

    case ELPIS_T_DS: case ELPIS_T_CDS:
        if (rdlen < 5) break;
        if (txt_append(buf, sz, &o, "%u %u %u ", (unsigned)elpis_get16(rd),
                       (unsigned)rd[2], (unsigned)rd[3]) != ELPIS_OK)
            return ELPIS_ETRUNC;
        return hex_append(buf, sz, &o, rd + 4, rdlen - 4);

    case ELPIS_T_DNSKEY: case ELPIS_T_CDNSKEY:
        if (rdlen < 5) break;
        if (txt_append(buf, sz, &o, "%u %u %u <%zu-byte key>",
                       (unsigned)elpis_get16(rd), (unsigned)rd[2],
                       (unsigned)rd[3], rdlen - 4) != ELPIS_OK)
            return ELPIS_ETRUNC;
        return ELPIS_OK;

    case ELPIS_T_RRSIG: case ELPIS_T_SIG: {
        if (rdlen < 18) break;
        if (elpis_name_parse_nocomp(&n, rd + 18, rdlen - 18, &used) != ELPIS_OK) break;
        elpis_name_to_text(&n, nbuf, sizeof nbuf);
        return txt_append(buf, sz, &o,
                          "%s %u %u %lu %lu %lu %u %s <%zu-byte sig>",
                          elpis_type_name(elpis_get16(rd)), (unsigned)rd[2],
                          (unsigned)rd[3], (unsigned long)elpis_get32(rd + 4),
                          (unsigned long)elpis_get32(rd + 8),
                          (unsigned long)elpis_get32(rd + 12),
                          (unsigned)elpis_get16(rd + 16), nbuf,
                          rdlen - 18 - used);
    }

    default:
        break;
    }

    /* RFC 3597 generic representation. */
    if (txt_append(buf, sz, &o, "\\# %zu ", rdlen) != ELPIS_OK)
        return ELPIS_ETRUNC;
    return hex_append(buf, sz, &o, rd, rdlen);
}
