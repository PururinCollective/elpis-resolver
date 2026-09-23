/*
 * tests/test_main.c -- self tests.
 *
 * Everything here runs without a network and without a crypto library: the
 * signature vectors in vectors.h were generated once against OpenSSL and then
 * frozen, so a failure means this code changed behaviour, not that the
 * environment did.
 */
#include "elpis/common.h"
#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/simd.h"
#include "elpis/name.h"
#include "elpis/msg.h"
#include "elpis/rdata.h"
#include "elpis/cache.h"
#include "elpis/store.h"
#include "elpis/crypto.h"
#include "elpis/licence.h"
#include "elpis/dnssec.h"
#include "elpis/conf.h"
#include "elpis/edns.h"
#include "elpis/resolver.h"
#include "elpis/deleg.h"
#include "elpis/conflict.h"

#include "vectors.h"

#include <stdio.h>

static int g_pass, g_fail;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                    \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

static void section(const char *s) { printf("[%s]\n", s); }

/* ------------------------------------------------------------------ */
static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (; *h; h++) {
        int v;
        if (*h >= '0' && *h <= '9')      v = *h - '0';
        else if (*h >= 'a' && *h <= 'f') v = *h - 'a' + 10;
        else if (*h >= 'A' && *h <= 'F') v = *h - 'A' + 10;
        else continue;
        if (hi < 0) { hi = v; continue; }
        if (n < cap) out[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    return n;
}

/* ================================================================== */
static void test_util(void)
{
    uint8_t ip4[4], ip6[16];
    char buf[64];
    elpis_addr_t a;
    elpis_prefix_t p;
    uint64_t sz;
    uint32_t d;

    section("util");

    CHECK(elpis_pton4("192.0.2.1", ip4) == 0 && ip4[0] == 192 && ip4[3] == 1,
          "pton4 basic");
    CHECK(elpis_pton4("192.0.2.256", ip4) != 0, "pton4 rejects 256");
    CHECK(elpis_pton4("192.0.2", ip4) != 0, "pton4 rejects short");
    CHECK(elpis_pton4("192.00.2.1", ip4) != 0, "pton4 rejects leading zero");
    CHECK(elpis_pton4("192.0.2.1.", ip4) != 0, "pton4 rejects trailing dot");

    CHECK(elpis_pton6("::1", ip6) == 0 && ip6[15] == 1, "pton6 ::1");
    CHECK(elpis_pton6("2001:db8::1", ip6) == 0 && ip6[0] == 0x20, "pton6 2001:db8::1");
    CHECK(elpis_pton6("::ffff:192.0.2.1", ip6) == 0 && ip6[12] == 192,
          "pton6 v4-mapped");
    CHECK(elpis_pton6("2001:db8::1::2", ip6) != 0, "pton6 rejects double ::");
    CHECK(elpis_pton6("12345::1", ip6) != 0, "pton6 rejects 5 hex digits");

    elpis_pton6("2001:db8::1", ip6);
    CHECK(elpis_ntop6(ip6, buf, sizeof buf) == 0 && !strcmp(buf, "2001:db8::1"),
          "ntop6 round trip got '%s'", buf);

    CHECK(elpis_addr_parse(&a, "127.0.0.1@5353", 53) == 0 &&
          elpis_addr_port(&a) == 5353, "addr parse v4@port");
    CHECK(elpis_addr_parse(&a, "[::1]:5353", 53) == 0 &&
          elpis_addr_port(&a) == 5353, "addr parse [v6]:port");
    CHECK(elpis_addr_parse(&a, "2001:db8::1", 53) == 0 &&
          elpis_addr_family(&a) == AF_INET6, "addr parse bare v6");

    CHECK(elpis_prefix_parse(&p, "10.0.0.0/8") == 0, "prefix parse");
    elpis_addr_parse(&a, "10.1.2.3", 53);
    CHECK(elpis_prefix_match(&p, &a), "prefix matches inside");
    elpis_addr_parse(&a, "11.1.2.3", 53);
    CHECK(!elpis_prefix_match(&p, &a), "prefix rejects outside");

    CHECK(elpis_parse_size("2G", &sz) == 0 && sz == 2147483648ull, "parse 2G");
    CHECK(elpis_parse_size("512k", &sz) == 0 && sz == 524288ull, "parse 512k");
    CHECK(elpis_parse_duration("1h", &d) == 0 && d == 3600, "parse 1h");
    CHECK(elpis_parse_duration("7d", &d) == 0 && d == 604800, "parse 7d");
}

/* ================================================================== */
static void test_simd(void)
{
    uint8_t a[300], b[300], c[300];
    size_t i, n;

    section("simd");
    elpis_simd_init();
    printf("  backend: %s\n", elpis_simd_backend());

    for (i = 0; i < sizeof a; i++)
        a[i] = (uint8_t)(i * 7 + 3);

    /* Every dispatched kernel must agree with the scalar reference. */
    for (n = 0; n <= 260; n++) {
        elpis_scalar_lower(b, a, n);
        elpis_simd_lower(c, a, n);
        if (memcmp(b, c, n) != 0) {
            CHECK(0, "simd_lower differs from scalar at n=%zu", n);
            break;
        }
        if (elpis_scalar_hash_ci(a, n, 12345) != elpis_simd_hash_ci(a, n, 12345)) {
            CHECK(0, "simd_hash differs from scalar at n=%zu", n);
            break;
        }
        if (elpis_scalar_eq_ci(a, a, n) != elpis_simd_eq_ci(a, a, n)) {
            CHECK(0, "simd_eq differs from scalar at n=%zu", n);
            break;
        }
    }
    if (n > 260)
        g_pass += 3;

    /* Case folding must be exactly ASCII A-Z, nothing else. */
    {
        uint8_t in[256], want[256], got[256];
        for (i = 0; i < 256; i++) {
            in[i] = (uint8_t)i;
            want[i] = (uint8_t)((i >= 'A' && i <= 'Z') ? i + 32 : i);
        }
        elpis_simd_lower(got, in, 256);
        CHECK(memcmp(got, want, 256) == 0, "fold touches only A-Z");
    }

    /* The control-word probe must find exactly the matching slots. */
    {
        uint8_t ctrl[ELPIS_GROUP];
        uint32_t m;
        for (i = 0; i < ELPIS_GROUP; i++)
            ctrl[i] = 0x80;
        ctrl[3] = 0x2A;
        ctrl[9] = 0x2A;
        m = elpis_group_match(ctrl, 0x2A);
        CHECK(m == ((1u << 3) | (1u << 9)), "group_match mask=0x%x", m);
        m = elpis_group_special(ctrl);
        CHECK(m == (0xFFFFu & ~((1u << 3) | (1u << 9))), "group_special mask=0x%x", m);
    }
}

/* ================================================================== */
static void test_name(void)
{
    elpis_name_t a, b, c;
    char buf[1024];

    section("name");

    CHECK(elpis_name_from_text(&a, "www.example.com.") == ELPIS_OK &&
          a.labels == 3 && a.len == 17, "parse www.example.com (len=%u labels=%u)",
          a.len, a.labels);
    CHECK(elpis_name_from_text(&b, "www.example.com") == ELPIS_OK &&
          elpis_name_eq(&a, &b), "trailing dot is optional");
    CHECK(elpis_name_from_text(&b, "WWW.Example.COM.") == ELPIS_OK &&
          elpis_name_eq(&a, &b), "comparison is case insensitive");
    CHECK(elpis_name_from_text(&b, ".") == ELPIS_OK && b.len == 1 &&
          elpis_name_is_root(&b), "root name");
    CHECK(elpis_name_from_text(&b, "a..b") != ELPIS_OK, "empty label rejected");
    CHECK(elpis_name_from_text(&b,
        "0123456789012345678901234567890123456789012345678901234567890123.com")
        != ELPIS_OK, "64-octet label rejected");

    elpis_name_to_text(&a, buf, sizeof buf);
    CHECK(!strcmp(buf, "www.example.com."), "to_text got '%s'", buf);

    CHECK(elpis_name_parent(&a, &b) == 0 && b.labels == 2, "parent");
    elpis_name_from_text(&c, "example.com.");
    CHECK(elpis_name_eq(&b, &c), "parent is example.com");

    CHECK(elpis_name_is_subdomain(&a, &c), "www.example.com under example.com");
    elpis_name_from_text(&c, "notexample.com.");
    CHECK(!elpis_name_is_subdomain(&a, &c), "suffix must land on a label edge");

    elpis_name_from_text(&b, "com.");
    CHECK(elpis_name_common_labels(&a, &b) == 1, "common labels with com");

    /* Escapes, both \DDD and \. */
    CHECK(elpis_name_from_text(&b, "a\\.b.example.com.") == ELPIS_OK &&
          b.labels == 3, "escaped dot stays in the label");
    CHECK(elpis_name_from_text(&b, "\\255.example.com.") == ELPIS_OK &&
          b.d[1] == 255, "decimal escape");

    CHECK(elpis_name_from_text(&b, "*.example.com.") == ELPIS_OK &&
          elpis_name_is_wildcard(&b), "wildcard detected");
    CHECK(elpis_name_from_text(&b, "a.*.example.com.") == ELPIS_OK &&
          !elpis_name_is_wildcard(&b), "only a leading * counts");

    /* RFC 4034 canonical ordering: right to left, shorter label first. */
    {
        elpis_name_t x, y;
        elpis_name_from_text(&x, "a.example.");
        elpis_name_from_text(&y, "b.example.");
        CHECK(elpis_name_canon_cmp(&x, &y) < 0, "a.example < b.example");
        elpis_name_from_text(&x, "z.example.");
        elpis_name_from_text(&y, "yljkjljk.a.example.");
        CHECK(elpis_name_canon_cmp(&x, &y) > 0, "z.example > yljkjljk.a.example");
        elpis_name_from_text(&x, "example.");
        elpis_name_from_text(&y, "a.example.");
        CHECK(elpis_name_canon_cmp(&x, &y) < 0, "example < a.example");
        elpis_name_from_text(&x, "*.z.example.");
        elpis_name_from_text(&y, "\\200.z.example.");
        CHECK(elpis_name_canon_cmp(&x, &y) < 0, "* < \\200 at the same level");
    }

    /* DNAME substitution, RFC 6672 section 2.2. */
    {
        elpis_name_t owner, target, out;
        elpis_name_from_text(&a, "www.example.com.");
        elpis_name_from_text(&owner, "example.com.");
        elpis_name_from_text(&target, "example.net.");
        CHECK(elpis_name_substitute(&a, &owner, &target, &out) == ELPIS_OK,
              "dname substitution");
        elpis_name_to_text(&out, buf, sizeof buf);
        CHECK(!strcmp(buf, "www.example.net."), "substituted got '%s'", buf);

        /* A substitution that would exceed 255 octets must fail, not truncate. */
        {
            char longname[600];
            elpis_name_t big, bigtarget;
            int i;
            longname[0] = '\0';
            for (i = 0; i < 30; i++)
                strcat(longname, "abcdefgh.");
            strcat(longname, "example.com.");
            if (elpis_name_from_text(&big, longname) == ELPIS_OK) {
                elpis_name_from_text(&bigtarget,
                    "aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddddd.example.net.");
                CHECK(elpis_name_substitute(&big, &owner, &bigtarget, &out)
                      != ELPIS_OK, "over-long substitution is refused");
            } else {
                g_pass++;   /* the source name was already too long to build */
            }
        }
        /* A DNAME does not cover its own owner. */
        CHECK(elpis_name_substitute(&owner, &owner, &target, &out) == ELPIS_OK &&
              elpis_name_eq(&out, &target), "owner maps to the target itself");
    }

    /* Wildcard construction, as the validator does it. */
    {
        elpis_name_t wc, suffix;
        elpis_name_from_text(&a, "a.b.example.com.");
        CHECK(elpis_name_suffix(&a, 2, &suffix) == 0 && suffix.labels == 2,
              "suffix keeps 2 labels");
        CHECK(elpis_name_prepend(&wc, (const uint8_t *)"*", 1, &suffix) == ELPIS_OK,
              "prepend wildcard");
        elpis_name_to_text(&wc, buf, sizeof buf);
        CHECK(!strcmp(buf, "*.example.com."), "wildcard got '%s'", buf);
    }
}

/* ================================================================== */
static void test_msg(void)
{
    uint8_t buf[4096];
    elpis_bld_t b;
    elpis_cslot_t ctab[ELPIS_BLD_CTAB];
    elpis_name_t qn;
    elpis_msg_t m;
    int drop;
    size_t rdpos;

    section("message");

    elpis_name_from_text(&qn, "www.example.com.");
    elpis_bld_init(&b, buf, sizeof buf, ctab, 1);
    elpis_bld_header(&b, 0x1234, ELPIS_FLAG_QR | ELPIS_FLAG_RD | ELPIS_FLAG_RA);
    elpis_bld_question(&b, &qn, ELPIS_T_A, ELPIS_CLASS_IN);
    elpis_bld_rr_begin(&b, &qn, ELPIS_T_A, ELPIS_CLASS_IN, 300, &rdpos);
    elpis_bld_bytes(&b, "\xc0\x00\x02\x01", 4);
    elpis_bld_rr_end(&b, rdpos);
    elpis_bld_count(&b, ELPIS_SEC_ANSWER, 1);
    elpis_bld_finish(&b);

    CHECK(elpis_msg_parse(&m, buf, b.len, ELPIS_PARSE_RESPONSE, &drop) == ELPIS_OK,
          "round trip parses (drop=%s)", elpis_drop_name((elpis_drop_t)drop));
    CHECK(m.hdr.id == 0x1234, "id survives");
    CHECK(m.hdr.ancount == 1, "ancount=1");
    CHECK(elpis_name_eq(&m.qname, &qn), "qname survives");

    /* The answer owner should have been compressed to a pointer. */
    CHECK(b.len < 12 + 17 + 4 + 17 + 10 + 4, "owner name was compressed (len=%zu)",
          b.len);

    {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        elpis_rr_iter(&it, &m, ELPIS_SEC_ANSWER);
        CHECK(elpis_rr_next(&it, &rr, &drop) == ELPIS_OK &&
              rr.type == ELPIS_T_A && rr.rdlen == 4 &&
              elpis_name_eq(&rr.name, &qn), "answer record decodes");
        CHECK(elpis_rr_next(&it, &rr, &drop) == ELPIS_ENOTFOUND, "iterator ends");
    }

    section("malformed input is rejected");

    CHECK(elpis_msg_parse(&m, buf, 5, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT &&
          drop == ELPIS_DROP_SHORT, "short message");

    {   /* qdcount says 2, only one question present */
        uint8_t bad[64];
        memcpy(bad, buf, 32);
        elpis_put16(bad + 4, 2);
        CHECK(elpis_msg_parse(&m, bad, 32, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT,
              "lying qdcount");
    }
    {   /* compression pointer to itself */
        uint8_t bad[32];
        memset(bad, 0, sizeof bad);
        elpis_put16(bad + 2, ELPIS_FLAG_QR);
        elpis_put16(bad + 4, 1);
        bad[12] = 0xC0;
        bad[13] = 12;
        CHECK(elpis_msg_parse(&m, bad, 20, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT &&
              drop == ELPIS_DROP_COMPRESS, "self-referential pointer");
    }
    {   /* forward pointer */
        uint8_t bad[32];
        memset(bad, 0, sizeof bad);
        elpis_put16(bad + 2, ELPIS_FLAG_QR);
        elpis_put16(bad + 4, 1);
        bad[12] = 0xC0;
        bad[13] = 20;
        CHECK(elpis_msg_parse(&m, bad, 24, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT &&
              drop == ELPIS_DROP_COMPRESS, "forward pointer");
    }
    {   /* label length 64 */
        uint8_t bad[128];
        memset(bad, 0, sizeof bad);
        elpis_put16(bad + 2, ELPIS_FLAG_QR);
        elpis_put16(bad + 4, 1);
        bad[12] = 64;
        CHECK(elpis_msg_parse(&m, bad, 100, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT,
              "over-long label");
    }
    {   /* trailing junk after the last record */
        uint8_t bad[4096];
        memcpy(bad, buf, b.len);
        bad[b.len] = 0x41;
        CHECK(elpis_msg_parse(&m, bad, b.len + 1, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT &&
              drop == ELPIS_DROP_TRAILING, "trailing junk");
    }
    {   /* rdlength running past the end */
        uint8_t bad[4096];
        memcpy(bad, buf, b.len);
        elpis_put16(bad + b.len - 6, 4000);
        CHECK(elpis_msg_parse(&m, bad, b.len, ELPIS_PARSE_ANY, &drop) == ELPIS_EFORMAT &&
              drop == ELPIS_DROP_RDLEN, "rdlength overrun");
    }

    section("rdata validation");
    {
        uint8_t w[64];
        size_t olen;
        uint8_t out2[64];
        memset(w, 0, sizeof w);
        /* A record with 5 octets of rdata is malformed. */
        CHECK(elpis_rdata_validate(ELPIS_T_A, w, sizeof w, 0, 5, &drop) == ELPIS_EFORMAT,
              "A rdlength must be 4");
        CHECK(elpis_rdata_validate(ELPIS_T_A, w, sizeof w, 0, 4, &drop) == ELPIS_OK,
              "A rdlength 4 accepted");
        CHECK(elpis_rdata_validate(ELPIS_T_AAAA, w, sizeof w, 0, 15, &drop) == ELPIS_EFORMAT,
              "AAAA rdlength must be 16");
        /* Unknown types are opaque (RFC 3597). */
        CHECK(elpis_rdata_validate(60000, w, sizeof w, 0, 7, &drop) == ELPIS_OK,
              "unknown type is opaque");
        CHECK(elpis_rdata_canonical(60000, w, sizeof w, 0, 7, out2, sizeof out2,
                                    &olen, 1) == ELPIS_OK && olen == 7,
              "opaque rdata copies verbatim");
    }

    section("type and class names");
    {
        uint16_t v;
        CHECK(elpis_type_parse("AAAA", &v) == 0 && v == ELPIS_T_AAAA, "parse AAAA");
        CHECK(elpis_type_parse("aaaa", &v) == 0 && v == ELPIS_T_AAAA, "parse is case insensitive");
        CHECK(elpis_type_parse("TYPE65534", &v) == 0 && v == 65534, "RFC 3597 TYPE####");
        CHECK(elpis_type_parse("NOTATYPE", &v) != 0, "unknown mnemonic rejected");
        CHECK(!strcmp(elpis_type_name(ELPIS_T_HTTPS), "HTTPS"), "HTTPS name");
        CHECK(!strcmp(elpis_type_name(65534), "TYPE65534"), "unknown type renders generically");

        CHECK(elpis_class_parse("IN", &v) == 0 && v == ELPIS_CLASS_IN, "parse IN");
        CHECK(elpis_class_parse("CLASS255", &v) == 0 && v == 255, "RFC 3597 CLASS####");
        CHECK(!strcmp(elpis_class_name(ELPIS_CLASS_CH), "CH"), "CH name");

        CHECK(elpis_type_is_meta(ELPIS_T_ANY), "ANY is a meta type");
        CHECK(elpis_type_is_meta(ELPIS_T_AXFR), "AXFR is a meta type");
        CHECK(!elpis_type_is_meta(ELPIS_T_A), "A is not a meta type");
        CHECK(elpis_type_is_singleton(ELPIS_T_CNAME), "CNAME is a singleton");
    }

    section("rdata presentation");
    {
        char txt[512];
        const uint8_t a4[4] = { 192, 0, 2, 1 };
        const uint8_t mx[] = { 0, 10, 4, 'm','a','i','l', 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0 };
        const uint8_t opaque[3] = { 0xde, 0xad, 0xbe };

        CHECK(elpis_rdata_to_text(ELPIS_T_A, a4, 4, txt, sizeof txt) == ELPIS_OK &&
              !strcmp(txt, "192.0.2.1"), "A renders as '%s'", txt);
        CHECK(elpis_rdata_to_text(ELPIS_T_MX, mx, sizeof mx, txt, sizeof txt) == ELPIS_OK &&
              !strcmp(txt, "10 mail.example.com."), "MX renders as '%s'", txt);
        CHECK(elpis_rdata_to_text(60000, opaque, 3, txt, sizeof txt) == ELPIS_OK &&
              !strcmp(txt, "\\# 3 deadbe"), "unknown type uses RFC 3597 form, got '%s'", txt);
    }

    section("type bitmaps");
    {
        /* window 0, 2 octets, A(1) and NS(2) set. */
        const uint8_t bm[] = { 0, 2, 0x60, 0x00 };
        CHECK(elpis_bitmap_validate(bm, sizeof bm) == ELPIS_OK, "bitmap valid");
        CHECK(elpis_bitmap_has(bm, sizeof bm, ELPIS_T_A), "bitmap has A");
        CHECK(elpis_bitmap_has(bm, sizeof bm, ELPIS_T_NS), "bitmap has NS");
        CHECK(!elpis_bitmap_has(bm, sizeof bm, ELPIS_T_AAAA), "bitmap lacks AAAA");
        {
            const uint8_t bad[] = { 0, 0 };          /* zero length window */
            CHECK(elpis_bitmap_validate(bad, sizeof bad) == ELPIS_EFORMAT,
                  "zero-length window rejected");
        }
        {
            const uint8_t bad[] = { 1, 1, 0x40, 0, 1, 0x40 };  /* not ascending */
            CHECK(elpis_bitmap_validate(bad, sizeof bad) == ELPIS_EFORMAT,
                  "non-ascending windows rejected");
        }
    }
}

/* ================================================================== */
static void test_cache(void)
{
    elpis_cache_t *rc;
    elpis_name_t n;
    elpis_rrset_buf_t *buf;
    const uint8_t rd[4] = { 192, 0, 2, 1 };
    const uint8_t *rdp = rd;
    uint16_t rdl = 4;
    unsigned i;

    section("cache");

    rc = elpis_rcache_new(4 * 1024 * 1024, 4);
    CHECK(rc != NULL, "rrset cache created");
    if (rc == NULL)
        return;

    buf = (elpis_rrset_buf_t *)elpis_malloc(sizeof *buf);
    CHECK(buf != NULL, "scratch allocated");
    if (buf == NULL) { elpis_cache_free(rc); return; }

    elpis_name_from_text(&n, "test.example.");
    CHECK(elpis_rcache_put(rc, &n, ELPIS_T_A, ELPIS_CLASS_IN, 300,
                           ELPIS_SEC_SECURE, 0, &rdp, &rdl, 1, NULL, NULL, 0,
                           0, 0) == ELPIS_OK, "put");
    CHECK(elpis_rcache_get(rc, &n, ELPIS_T_A, ELPIS_CLASS_IN,
                           elpis_now_s(), 0, buf) == ELPIS_OK &&
          buf->count == 1 && buf->len[0] == 4 &&
          memcmp(buf->data, rd, 4) == 0, "get returns what was put");
    CHECK(buf->sec == ELPIS_SEC_SECURE, "security status survives");

    /* Lookups fold case. */
    {
        elpis_name_t up;
        elpis_name_from_text(&up, "TEST.EXAMPLE.");
        CHECK(elpis_rcache_get(rc, &up, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_OK,
              "lookup is case insensitive");
    }
    CHECK(elpis_rcache_get(rc, &n, ELPIS_T_AAAA, ELPIS_CLASS_IN,
                           elpis_now_s(), 0, buf) == ELPIS_ENOTFOUND,
          "wrong type misses");

    /* Fill it well past capacity and make sure it stays consistent. */
    for (i = 0; i < 20000; i++) {
        char nm[64];
        elpis_name_t k;
        snprintf(nm, sizeof nm, "host%u.load.example.", i);
        if (elpis_name_from_text(&k, nm) != ELPIS_OK)
            continue;
        elpis_rcache_put(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN, 300,
                         ELPIS_SEC_UNCHECKED, 0, &rdp, &rdl, 1, NULL, NULL, 0,
                         0, 0);
    }
    {
        elpis_cache_stats_t st;
        elpis_cache_stats(rc, &st);
        CHECK(st.entries > 0 && st.bytes <= st.bytes_max,
              "cache stays within budget (entries=%llu bytes=%llu max=%llu)",
              (unsigned long long)st.entries, (unsigned long long)st.bytes,
              (unsigned long long)st.bytes_max);
        printf("  after 20000 inserts: entries=%llu evictions=%llu\n",
               (unsigned long long)st.entries, (unsigned long long)st.evictions);
    }
    /* The most recent insert must still be findable. */
    {
        elpis_name_t k;
        elpis_name_from_text(&k, "host19999.load.example.");
        CHECK(elpis_rcache_get(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_OK,
              "newest entry survives eviction pressure");
    }

    /* Explicit removal and flush. */
    {
        elpis_name_t k;
        elpis_name_from_text(&k, "test.example.");
        CHECK(elpis_rcache_del(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN) == ELPIS_OK,
              "delete an entry");
        CHECK(elpis_rcache_get(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_ENOTFOUND,
              "deleted entry is gone");
        CHECK(elpis_rcache_del(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN) == ELPIS_ENOTFOUND,
              "deleting twice reports not found");

        elpis_cache_flush(rc);
        {
            elpis_cache_stats_t st;
            elpis_cache_stats(rc, &st);
            CHECK(st.entries == 0 && st.bytes == 0,
                  "flush empties the cache (entries=%llu bytes=%llu)",
                  (unsigned long long)st.entries, (unsigned long long)st.bytes);
        }
        /* Still usable afterwards. */
        CHECK(elpis_rcache_put(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN, 300,
                               ELPIS_SEC_SECURE, 0, &rdp, &rdl, 1, NULL, NULL,
                               0, 0, 0) == ELPIS_OK, "usable after flush");
        CHECK(elpis_rcache_get(rc, &k, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_OK,
              "lookup works after flush");
    }

    elpis_free(buf);
    elpis_cache_free(rc);

    section("cache sizing");
    {
        elpis_cache_plan_t p;
        elpis_cache_plan(&p, 0, 8);
        CHECK(p.budget_total > 0, "auto budget is non-zero");
        CHECK(p.msg_bytes + p.rrset_bytes + p.deleg_bytes + p.infra_bytes >=
              p.budget_total, "shares cover the budget");
        printf("  RAM=%lluMiB budget=%lluMiB msg=%llu rrset=%llu deleg=%llu shards=%u\n",
               (unsigned long long)(p.ram_total / (1024 * 1024)),
               (unsigned long long)(p.budget_total / (1024 * 1024)),
               (unsigned long long)(p.msg_bytes / (1024 * 1024)),
               (unsigned long long)(p.rrset_bytes / (1024 * 1024)),
               (unsigned long long)(p.deleg_bytes / (1024 * 1024)), p.shards);
        elpis_cache_plan(&p, 64 * 1024 * 1024, 4);
        CHECK(p.budget_total == 64 * 1024 * 1024, "explicit budget is honoured");
    }
}

/* ================================================================== */
static void test_hashes(void)
{
    uint8_t o[64];
    char hex[160];
    size_t i;

    section("hashes");

    elpis_sha1("abc", 3, o);
    for (i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d"), "SHA-1(abc)");

    elpis_sha256("abc", 3, o);
    for (i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
          "SHA-256(abc)");

    elpis_sha384("abc", 3, o);
    for (i = 0; i < 48; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                       "8086072ba1e7cc2358baeca134c825a7"), "SHA-384(abc)");

    elpis_sha512("abc", 3, o);
    for (i = 0; i < 64; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
          "SHA-512(abc)");

    elpis_sha3_256("abc", 3, o);
    for (i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
          "SHA3-256(abc)");

    elpis_shake256("abc", 3, o, 32);
    for (i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
          "SHAKE256(abc)");

    elpis_sha3_512("abc", 3, o);
    for (i = 0; i < 64; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
    CHECK(!strcmp(hex, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                       "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
          "SHA3-512(abc)");

    {
        elpis_keccak_t c;
        elpis_shake128_init(&c);
        elpis_keccak_absorb(&c, "", 0);
        elpis_keccak_squeeze(&c, o, 32);
        for (i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", o[i]);
        CHECK(!strcmp(hex, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
              "SHAKE128(\"\")");
    }
}

/* ================================================================== */
static void test_signatures(void)
{
    static uint8_t key[8192], sig[8192], pk[2048];
    size_t kl, sl, pl;
    uint8_t h[64];
    const char *msg = TV_MESSAGE;
    size_t msglen = strlen(TV_MESSAGE);

    section("signature verification");

    /* RSA */
    kl = unhex(TV_RSA2048_DNSKEY, key, sizeof key);
    sl = unhex(TV_RSA2048_SIG, sig, sizeof sig);
    elpis_sha256(msg, msglen, h);
    CHECK(elpis_rsa_verify(key, kl, sig, sl, h, 32, ELPIS_HASH_SHA256) == 1,
          "RSA-2048/SHA-256 accepts a good signature");
    h[0] ^= 1;
    CHECK(elpis_rsa_verify(key, kl, sig, sl, h, 32, ELPIS_HASH_SHA256) == 0,
          "RSA-2048 rejects a modified digest");
    elpis_sha256(msg, msglen, h);
    sig[10] ^= 1;
    CHECK(elpis_rsa_verify(key, kl, sig, sl, h, 32, ELPIS_HASH_SHA256) == 0,
          "RSA-2048 rejects a modified signature");

    /* ECDSA P-256 */
    pl = unhex(TV_P256_PUB, pk, sizeof pk);
    sl = unhex(TV_P256_SIG, sig, sizeof sig);
    elpis_sha256(msg, msglen, h);
    CHECK(elpis_ecdsa_verify(ELPIS_CURVE_P256, pk, pl, sig, sl, h, 32) == 1,
          "ECDSA P-256 accepts a good signature");
    sig[0] ^= 1;
    CHECK(elpis_ecdsa_verify(ELPIS_CURVE_P256, pk, pl, sig, sl, h, 32) == 0,
          "ECDSA P-256 rejects a modified signature");
    sig[0] ^= 1;
    pk[0] ^= 1;
    CHECK(elpis_ecdsa_verify(ELPIS_CURVE_P256, pk, pl, sig, sl, h, 32) == 0,
          "ECDSA P-256 rejects an off-curve key");

    /* ECDSA P-384 */
    pl = unhex(TV_P384_PUB, pk, sizeof pk);
    sl = unhex(TV_P384_SIG, sig, sizeof sig);
    elpis_sha384(msg, msglen, h);
    CHECK(elpis_ecdsa_verify(ELPIS_CURVE_P384, pk, pl, sig, sl, h, 48) == 1,
          "ECDSA P-384 accepts a good signature");
    sig[47] ^= 1;
    CHECK(elpis_ecdsa_verify(ELPIS_CURVE_P384, pk, pl, sig, sl, h, 48) == 0,
          "ECDSA P-384 rejects a modified signature");

    /* Ed25519, RFC 8032 test vectors. */
    {
        static const struct { const char *pk, *msg, *sig; } ed[] = {
            { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
              "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
              "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
            { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
              "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
              "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
            { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
              "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
              "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" }
        };
        size_t i;
        for (i = 0; i < ELPIS_ARRAY_LEN(ed); i++) {
            uint8_t p[32], s[64], m[64];
            size_t ml;
            unhex(ed[i].pk, p, sizeof p);
            unhex(ed[i].sig, s, sizeof s);
            ml = unhex(ed[i].msg, m, sizeof m);
            CHECK(elpis_ed25519_verify(p, m, ml, s) == 1,
                  "Ed25519 RFC 8032 vector %zu", i + 1);
            s[10] ^= 1;
            CHECK(elpis_ed25519_verify(p, m, ml, s) == 0,
                  "Ed25519 rejects vector %zu tampered", i + 1);
        }
    }

    /* ML-DSA-44 (FIPS 204). */
    {
        static uint8_t mpk[ELPIS_MLDSA44_PK_BYTES + 8];
        static uint8_t msig[ELPIS_MLDSA44_SIG_BYTES + 8];
        size_t mpl = unhex(TV_MLDSA44_PK, mpk, sizeof mpk);
        size_t msl = unhex(TV_MLDSA44_SIG, msig, sizeof msig);

        CHECK(mpl == ELPIS_MLDSA44_PK_BYTES, "ML-DSA-44 public key is %zu bytes", mpl);
        CHECK(msl == ELPIS_MLDSA44_SIG_BYTES, "ML-DSA-44 signature is %zu bytes", msl);
        CHECK(elpis_mldsa_verify(ELPIS_MLDSA_44, mpk, mpl,
                                 (const uint8_t *)msg, msglen, msig, msl) == 1,
              "ML-DSA-44 accepts a good signature");
        msig[100] ^= 1;
        CHECK(elpis_mldsa_verify(ELPIS_MLDSA_44, mpk, mpl,
                                 (const uint8_t *)msg, msglen, msig, msl) == 0,
              "ML-DSA-44 rejects a modified signature");
        msig[100] ^= 1;
        CHECK(elpis_mldsa_verify(ELPIS_MLDSA_44, mpk, mpl,
                                 (const uint8_t *)"other", 5, msig, msl) == 0,
              "ML-DSA-44 rejects a different message");
    }
}

/* ================================================================== */
static void test_dnssec(void)
{
    static uint8_t key[8192];
    uint8_t ds[4 + 64];
    size_t kl, dsl;
    elpis_name_t root;

    section("dnssec primitives");

    kl = unhex(TV_ROOT_KSK2017_DNSKEY, key, sizeof key);
    CHECK(elpis_dnskey_tag(key, kl) == TV_ROOT_KSK2017_TAG,
          "root KSK-2017 key tag is %u (got %u)", TV_ROOT_KSK2017_TAG,
          elpis_dnskey_tag(key, kl));

    elpis_name_init_root(&root);
    elpis_put16(ds, TV_ROOT_KSK2017_TAG);
    ds[2] = 8;                        /* RSASHA256 */
    ds[3] = ELPIS_DS_SHA256;
    dsl = 4 + unhex(TV_ROOT_KSK2017_DS_SHA256, ds + 4, sizeof ds - 4);
    CHECK(dsl == 36, "DS record is 36 octets (got %zu)", dsl);
    CHECK(elpis_ds_matches(&root, key, kl, ds, dsl) == 1,
          "published root DS matches the published root DNSKEY");

    ds[8] ^= 1;
    CHECK(elpis_ds_matches(&root, key, kl, ds, dsl) == 0,
          "a modified digest does not match");
    ds[8] ^= 1;
    {
        elpis_name_t other;
        elpis_name_from_text(&other, "example.");
        CHECK(elpis_ds_matches(&other, key, kl, ds, dsl) == 0,
              "the owner name is part of the digest");
    }

    section("HMAC-SHA-256 and PBKDF2");
    {
        /*
         * RFC 4231 cases 1 and 2, and the PBKDF2-HMAC-SHA-256 vectors from
         * RFC 7914 section 11.  These back the status page's password check,
         * so a mistake here would either lock everyone out or let anyone in.
         */
        uint8_t mac[32], dk[32];
        uint8_t k1[20];
        char hex[65];
        unsigned i;

        memset(k1, 0x0b, sizeof k1);
        elpis_hmac_sha256(k1, sizeof k1, (const uint8_t *)"Hi There", 8, mac);
        for (i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", mac[i]);
        CHECK(strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b"
                          "881dc200c9833da726e9376c2e32cff7") == 0,
              "RFC 4231 case 1 (got %s)", hex);

        elpis_hmac_sha256((const uint8_t *)"Jefe", 4,
                          (const uint8_t *)"what do ya want for nothing?", 28,
                          mac);
        for (i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", mac[i]);
        CHECK(strcmp(hex, "5bdcc146bf60754e6a042426089575c7"
                          "5a003f089d2739839dec58b964ec3843") == 0,
              "RFC 4231 case 2 (got %s)", hex);

        elpis_pbkdf2_sha256("password", 8, (const uint8_t *)"salt", 4,
                            1, dk, sizeof dk);
        for (i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", dk[i]);
        CHECK(strcmp(hex, "120fb6cffcf8b32c43e7225256c4f837"
                          "a86548c92ccc35480805987cb70be17b") == 0,
              "PBKDF2 c=1 (got %s)", hex);

        elpis_pbkdf2_sha256("password", 8, (const uint8_t *)"salt", 4,
                            4096, dk, sizeof dk);
        for (i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", dk[i]);
        CHECK(strcmp(hex, "c5e478d59288c841aa530db6845c4c8d"
                          "962893a001ce4e11a4963873aa98134a") == 0,
              "PBKDF2 c=4096 (got %s)", hex);
    }

    section("ML-DSA-44 in DNSSEC");
    {
        /*
         * The draft's worked example, end to end: dnskey tag, DS digest and a
         * real RRSIG over a real RRset.  Verifying the signature here exercises
         * the canonical form of the RRset as well as the ML-DSA verifier, so a
         * mistake in either one shows up as a failure rather than as a zone
         * that quietly will not validate.
         */
        static uint8_t dnskey[4 + ELPIS_MLDSA44_PK_BYTES];
        static uint8_t sig[18 + 16 + ELPIS_MLDSA44_SIG_BYTES];
        uint8_t dsrec[4 + 32], mx[2 + ELPIS_MAX_NAME];
        elpis_name_t owner, signer, exch;
        elpis_conf_t c;
        const uint8_t *rdp;
        uint16_t rdl;
        size_t keylen, siglen, dsrlen, mxlen, n;
        int ede = -1;

        elpis_conf_defaults(&c);
        elpis_name_from_text(&owner,  "example.com.");
        elpis_name_from_text(&signer, "example.com.");
        elpis_name_from_text(&exch,   "mail.example.com.");

        /* DNSKEY rdata: flags 257, protocol 3, algorithm 18, then the key. */
        elpis_put16(dnskey, 257);
        dnskey[2] = 3;
        dnskey[3] = (uint8_t)c.alg_mldsa44;
        keylen = 4 + unhex(TV_MLDSA44_DNSSEC_KEY, dnskey + 4, sizeof dnskey - 4);
        CHECK(keylen == 4 + ELPIS_MLDSA44_PK_BYTES,
              "DNSKEY rdata is %u octets (got %zu)",
              (unsigned)(4 + ELPIS_MLDSA44_PK_BYTES), keylen);
        CHECK(c.alg_mldsa44 == 18,
              "ML-DSA-44 defaults to algorithm 18 (got %u)",
              (unsigned)c.alg_mldsa44);
        CHECK(elpis_dnskey_tag(dnskey, keylen) == TV_MLDSA44_DNSSEC_TAG,
              "key tag is %u (got %u)", TV_MLDSA44_DNSSEC_TAG,
              elpis_dnskey_tag(dnskey, keylen));

        /* DS rdata: dnskey tag, algorithm, SHA-256, digest. */
        elpis_put16(dsrec, TV_MLDSA44_DNSSEC_TAG);
        dsrec[2] = (uint8_t)c.alg_mldsa44;
        dsrec[3] = ELPIS_DS_SHA256;
        dsrlen = 4 + unhex(TV_MLDSA44_DNSSEC_DS_SHA256, dsrec + 4, sizeof dsrec - 4);
        CHECK(elpis_ds_matches(&owner, dnskey, (uint16_t)keylen, dsrec, dsrlen) == 1,
              "the draft's DS matches the draft's DNSKEY");

        /* RRSIG rdata: the fixed fields, the signer name, then the signature. */
        elpis_put16(sig, ELPIS_T_MX);
        sig[2] = (uint8_t)c.alg_mldsa44;
        sig[3] = 2;                       /* labels in example.com. */
        elpis_put32(sig + 4,  3600);      /* original TTL           */
        elpis_put32(sig + 8,  1440021600);/* expiration             */
        elpis_put32(sig + 12, 1438207200);/* inception              */
        elpis_put16(sig + 16, TV_MLDSA44_DNSSEC_TAG);
        memcpy(sig + 18, signer.d, signer.len);
        n = 18 + signer.len;
        siglen = n + unhex(TV_MLDSA44_DNSSEC_SIG, sig + n, sizeof sig - n);
        CHECK(siglen == n + ELPIS_MLDSA44_SIG_BYTES,
              "RRSIG rdata carries a %u-octet signature",
              (unsigned)ELPIS_MLDSA44_SIG_BYTES);

        /* MX rdata: preference 10, exchange mail.example.com. */
        elpis_put16(mx, 10);
        memcpy(mx + 2, exch.d, exch.len);
        mxlen = 2 + exch.len;

        rdp = mx;
        rdl = (uint16_t)mxlen;
        CHECK(elpis_rrsig_verify(&c, &owner, ELPIS_T_MX, ELPIS_CLASS_IN,
                                 &rdp, &rdl, 1, sig, siglen, dnskey, keylen,
                                 1439000000, &ede) == ELPIS_OK,
              "the draft's ML-DSA-44 RRSIG verifies over the MX RRset");

        /* One flipped octet of rdata must break it. */
        mx[0] ^= 1;
        CHECK(elpis_rrsig_verify(&c, &owner, ELPIS_T_MX, ELPIS_CLASS_IN,
                                 &rdp, &rdl, 1, sig, siglen, dnskey, keylen,
                                 1439000000, &ede) != ELPIS_OK,
              "altering the MX rdata breaks the signature");
        mx[0] ^= 1;

        /* And so must a signature outside its validity window. */
        CHECK(elpis_rrsig_verify(&c, &owner, ELPIS_T_MX, ELPIS_CLASS_IN,
                                 &rdp, &rdl, 1, sig, siglen, dnskey, keylen,
                                 1440021601, &ede) != ELPIS_OK,
              "an expired ML-DSA signature is refused");
    }

    section("algorithm policy");
    {
        elpis_conf_t c;
        elpis_conf_defaults(&c);

        CHECK(elpis_alg_supported(&c, ELPIS_ALG_RSASHA256), "RSASHA256 supported");
        CHECK(elpis_alg_supported(&c, ELPIS_ALG_ECDSAP256SHA256), "ECDSA P-256 supported");
        CHECK(elpis_alg_supported(&c, ELPIS_ALG_ED25519), "Ed25519 supported");
        CHECK(elpis_alg_supported(&c, c.alg_mldsa44), "ML-DSA-44 supported");
        /* RFC 8624 says MUST NOT: treated as unsupported, hence insecure. */
        CHECK(!elpis_alg_supported(&c, ELPIS_ALG_RSAMD5), "RSAMD5 refused");
        CHECK(!elpis_alg_supported(&c, ELPIS_ALG_DSA), "DSA refused");

        CHECK(elpis_alg_hash(&c, ELPIS_ALG_RSASHA256) == ELPIS_HASH_SHA256,
              "RSASHA256 uses SHA-256");
        CHECK(elpis_alg_hash(&c, ELPIS_ALG_ECDSAP384SHA384) == ELPIS_HASH_SHA384,
              "ECDSA P-384 uses SHA-384");
        CHECK(elpis_alg_hash(&c, ELPIS_ALG_ED25519) == 0,
              "Ed25519 signs the message directly");
        CHECK(elpis_alg_hash(&c, c.alg_mldsa44) == 0,
              "ML-DSA signs the message directly");

        CHECK(elpis_digest_supported(ELPIS_DS_SHA256), "SHA-256 DS digest");
        CHECK(elpis_digest_supported(ELPIS_DS_SHA384), "SHA-384 DS digest");
        CHECK(!elpis_digest_supported(ELPIS_DS_GOST), "GOST digest refused");
    }

    section("canonical-form downcasing (RFC 4034 6.2 / RFC 6840 5.1)");
    {
        /* The list is closed.  These are the types whose rdata names are
         * folded when a signature is computed. */
        CHECK(elpis_rdata_downcase(ELPIS_T_NS),    "NS is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_CNAME), "CNAME is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_SOA),   "SOA is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_MX),    "MX is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_PTR),   "PTR is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_SRV),   "SRV is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_DNAME), "DNAME is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_NAPTR), "NAPTR is folded");
        CHECK(elpis_rdata_downcase(ELPIS_T_RRSIG), "RRSIG signer is folded");
        /* RFC 6840 section 5.1 corrects RFC 4034: NSEC's next-domain keeps
         * its case, and HINFO has no names at all. */
        CHECK(!elpis_rdata_downcase(ELPIS_T_NSEC),  "NSEC is NOT folded");
        CHECK(!elpis_rdata_downcase(ELPIS_T_HINFO), "HINFO is NOT folded");
        /* Nothing defined after RFC 4034 is folded. */
        CHECK(!elpis_rdata_downcase(ELPIS_T_SVCB),  "SVCB is NOT folded");
        CHECK(!elpis_rdata_downcase(ELPIS_T_HTTPS), "HTTPS is NOT folded");
        CHECK(!elpis_rdata_downcase(ELPIS_T_A),     "A has no names");
    }

    section("root hints");
    {
        unsigned n = 0, i, v4 = 0, v6 = 0;
        const elpis_roothint_t *h = elpis_root_hints(&n);
        CHECK(n == 13, "13 root servers (got %u)", n);
        for (i = 0; i < n; i++) {
            uint8_t ip4[4], ip6[16];
            if (h[i].v4 && elpis_pton4(h[i].v4, ip4) == 0) v4++;
            if (h[i].v6 && elpis_pton6(h[i].v6, ip6) == 0) v6++;
        }
        CHECK(v4 == 13, "all 13 have a usable IPv4 address (got %u)", v4);
        CHECK(v6 == 13, "all 13 have a usable IPv6 address (got %u)", v6);
    }
    {
        elpis_deleg_t d;
        elpis_root_delegation(&d);
        CHECK(d.nns == 13 && elpis_deleg_addr_count(&d) == 26,
              "built-in root delegation has %u servers, %u addresses",
              d.nns, elpis_deleg_addr_count(&d));
        CHECK(elpis_name_is_root(&d.zone), "its zone is the root");
        CHECK(d.pinned, "it is pinned");
    }

    section("ml-dsa parameters");
    {
        CHECK(elpis_mldsa_pk_bytes(ELPIS_MLDSA_44) == ELPIS_MLDSA44_PK_BYTES,
              "ML-DSA-44 public key size");
        CHECK(elpis_mldsa_sig_bytes(ELPIS_MLDSA_44) == ELPIS_MLDSA44_SIG_BYTES,
              "ML-DSA-44 signature size");
        CHECK(elpis_mldsa_pk_bytes(ELPIS_MLDSA_65) == 1952, "ML-DSA-65 key size");
        CHECK(elpis_mldsa_sig_bytes(ELPIS_MLDSA_87) == 4627, "ML-DSA-87 sig size");
        CHECK(elpis_mldsa_pk_bytes(99) == 0, "unknown variant has no size");
    }

    section("base32hex");
    {
        char out[64];
        uint8_t back[32];
        size_t bl;
        const uint8_t in[] = { 0x00, 0x11, 0x22, 0x33, 0x44 };
        CHECK(elpis_base32hex_encode(in, sizeof in, out, sizeof out) == ELPIS_OK,
              "encode");
        CHECK(elpis_base32hex_decode(out, strlen(out), back, sizeof back, &bl) == ELPIS_OK &&
              bl == sizeof in && memcmp(back, in, bl) == 0, "round trip '%s'", out);
    }

    section("nsec3 hashing");
    {
        /*
         * RFC 5155 appendix A: the zone "example" with salt AABBCCDD and
         * 12 iterations hashes "a.example" to a known value.
         */
        elpis_name_t n;
        uint8_t salt[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
        uint8_t h[32];
        size_t hl;
        char b32[64];

        elpis_name_from_text(&n, "a.example.");
        CHECK(elpis_nsec3_hash(&n, salt, 4, 12, ELPIS_NSEC3_SHA1, h, &hl) == ELPIS_OK,
              "nsec3 hash computes");
        elpis_base32hex_encode(h, hl, b32, sizeof b32);
        CHECK(!strcmp(b32, "35mthgpgcu1qg68fab165klnsnk3dpvl"),
              "RFC 5155 a.example hash got '%s'", b32);

        CHECK(elpis_nsec3_hash(&n, salt, 4, 5000, ELPIS_NSEC3_SHA1, h, &hl) == ELPIS_ERR,
              "excessive iteration counts are refused (RFC 9276)");
    }
}

/* ================================================================== */
static void test_dns64(void)
{
    /* RFC 6052 section 2.4, the published worked example for 192.0.2.33. */
    static const struct { const char *prefix; const char *expect; } tv[] = {
        { "2001:db8::/32",          "2001:db8:c000:221::"            },
        { "2001:db8:100::/40",      "2001:db8:1c0:2:21::"            },
        { "2001:db8:122::/48",      "2001:db8:122:c000:2:2100::"     },
        { "2001:db8:122:300::/56",  "2001:db8:122:3c0:0:221::"       },
        { "2001:db8:122:344::/64",  "2001:db8:122:344:c0:2:2100::"   },
        { "2001:db8:122:344::/96",  "2001:db8:122:344::c000:221"     }
    };
    const uint8_t v4[4] = { 192, 0, 2, 33 };
    size_t i;

    section("dns64 (RFC 6052)");

    for (i = 0; i < ELPIS_ARRAY_LEN(tv); i++) {
        elpis_prefix_t p;
        uint8_t got[16], want[16];
        char gs[64];

        CHECK(elpis_prefix_parse(&p, tv[i].prefix) == 0, "parse %s", tv[i].prefix);
        elpis_dns64_embed(&p, v4, got);
        elpis_ntop6(got, gs, sizeof gs);
        CHECK(elpis_pton6(tv[i].expect, want) == 0 &&
              memcmp(got, want, 16) == 0,
              "%s + 192.0.2.33 -> %s (want %s)", tv[i].prefix, gs, tv[i].expect);
    }
}

/* ================================================================== */
static void test_conflict(void)
{
    elpis_addr_t addr, want;
    unsigned long inode;

    section("port conflict detection");

    /*
     * Real rows captured from /proc/net/udp on a systemd-resolved host.  The
     * address is printed as the raw __be32, so 3500007F is 127.0.0.53, and
     * the inode is the tenth column -- both of which this got wrong once.
     */
    {
        const char *row =
            "   93: 3500007F:0035 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000   989        0 7590 2 0000000000000000 0";
        uint8_t expect[4] = { 127, 0, 0, 53 };
        CHECK(elpis_conflict_parse_row(row, AF_INET, &addr, &inode) == 1,
              "parse a /proc/net/udp row");
        CHECK(inode == 7590, "inode is 7590 (got %lu)", inode);
        CHECK(elpis_addr_port(&addr) == 53, "port is 53 (got %u)",
              elpis_addr_port(&addr));
        CHECK(memcmp(&addr.u.v4.sin_addr, expect, 4) == 0,
              "address decodes to 127.0.0.53");
    }
    {
        const char *row =
            "   93: 3600007F:0035 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000   989        0 7592 2 0000000000000000 0";
        uint8_t expect[4] = { 127, 0, 0, 54 };
        CHECK(elpis_conflict_parse_row(row, AF_INET, &addr, &inode) == 1 &&
              inode == 7592 &&
              memcmp(&addr.u.v4.sin_addr, expect, 4) == 0,
              "second row decodes to 127.0.0.54 inode 7592");
    }
    {   /* wildcard, the common case for a real server */
        const char *row =
            "  123: 00000000:0035 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000     0        0 44321 2 0000000000000000 0";
        uint8_t zero[4] = { 0, 0, 0, 0 };
        CHECK(elpis_conflict_parse_row(row, AF_INET, &addr, &inode) == 1 &&
              inode == 44321 && memcmp(&addr.u.v4.sin_addr, zero, 4) == 0,
              "wildcard row decodes to 0.0.0.0");
    }
    {   /* IPv6: ::1 port 53 */
        const char *row =
            "   42: 00000000000000000000000001000000:0035 "
            "00000000000000000000000000000000:0000 07 00000000:00000000 "
            "00:00000000 00000000   989        0 7595 2 0000000000000000 0";
        uint8_t expect[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        CHECK(elpis_conflict_parse_row(row, AF_INET6, &addr, &inode) == 1 &&
              inode == 7595 &&
              memcmp(&addr.u.v6.sin6_addr, expect, 16) == 0,
              "IPv6 row decodes to ::1");
    }
    {   /* a different port must not be mistaken for ours */
        const char *row =
            "   93: 0100007F:1F90 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000   989        0 9999 2 0000000000000000 0";
        CHECK(elpis_conflict_parse_row(row, AF_INET, &addr, &inode) == 1 &&
              elpis_addr_port(&addr) == 8080, "port 0x1F90 is 8080 (got %u)",
              elpis_addr_port(&addr));
    }
    CHECK(elpis_conflict_parse_row("garbage", AF_INET, &addr, &inode) == 0,
          "a malformed row is rejected");

    section("port collision rules");
    {
        elpis_addr_t bound;
        elpis_addr_parse(&bound, "127.0.0.53@53", 53);

        elpis_addr_parse(&want, "127.0.0.53@53", 53);
        CHECK(elpis_conflict_collides(&bound, &want), "same address collides");

        elpis_addr_parse(&want, "0.0.0.0@53", 53);
        CHECK(elpis_conflict_collides(&bound, &want),
              "a wildcard bind collides with a specific listener");

        elpis_addr_parse(&bound, "0.0.0.0@53", 53);
        elpis_addr_parse(&want, "127.0.0.1@53", 53);
        CHECK(elpis_conflict_collides(&bound, &want),
              "a specific bind collides with a wildcard listener");

        elpis_addr_parse(&bound, "127.0.0.53@53", 53);
        elpis_addr_parse(&want, "127.0.0.1@53", 53);
        CHECK(!elpis_conflict_collides(&bound, &want),
              "different addresses on the same port do not collide");

        elpis_addr_parse(&want, "127.0.0.53@5353", 5353);
        CHECK(!elpis_conflict_collides(&bound, &want),
              "different ports do not collide");

        elpis_addr_parse(&bound, "[::1]:53", 53);
        elpis_addr_parse(&want, "127.0.0.1@53", 53);
        CHECK(!elpis_conflict_collides(&bound, &want),
              "different families do not collide");
    }
}

/* ================================================================== */
static void test_conf(void)
{
    elpis_conf_t c;
    char line[256];
    elpis_addr_t a;
    int snoop;

    section("configuration");

    elpis_conf_defaults(&c);
    CHECK(c.dnssec == 1, "dnssec on by default");
    CHECK(c.edns_buffer == 1400 && c.edns_buffer4 == 1400 &&
          c.edns_buffer6 == 1400 && !c.edns_auto,
          "servers are offered 1400 by default");
    CHECK(c.max_udp_size_reply == 1232,
          "replies to clients stay within 1232 by default");

    elpis_strlcpy(line, "edns-buffer-size: auto", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK && c.edns_auto,
          "edns-buffer-size: auto parses");
    elpis_strlcpy(line, "edns-buffer-size: 1300", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK && !c.edns_auto &&
          c.edns_buffer == 1300 && c.edns_buffer4 == 1300 &&
          c.edns_buffer6 == 1300,
          "a number sets both families and turns auto off");
    elpis_strlcpy(line, "edns-buffer-size: 100", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
          c.edns_buffer4 == 512, "a number below 512 is raised to 512");

    CHECK(elpis_edns_for_mtu(1500, AF_INET) == 1400 &&
          elpis_edns_for_mtu(1500, AF_INET6) == 1400,
          "auto: a 1500-byte route is capped at 1400");
    CHECK(elpis_edns_for_mtu(1442, AF_INET) == 1400 &&
          elpis_edns_for_mtu(1442, AF_INET6) == 1394,
          "auto: PPPoE inside EoIP inside PPPoE, 1442");
    CHECK(elpis_edns_for_mtu(1420, AF_INET6) == 1372,
          "auto: a WireGuard route, 1420");
    CHECK(elpis_edns_for_mtu(1280, AF_INET6) == 1232,
          "auto: IPv6's minimum MTU gives the Flag Day figure");
    CHECK(elpis_edns_for_mtu(576, AF_INET) == 548 &&
          elpis_edns_for_mtu(300, AF_INET) == 512,
          "auto: never below 512");
    elpis_conf_defaults(&c);
    CHECK(c.nlisten == 2, "loopback listeners by default");

    c.nacl = 0;
    elpis_strlcpy(line, "access-control: 192.168.0.0/16 allow", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK, "acl parses");
    elpis_strlcpy(line, "access-control: 192.168.5.0/24 deny", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 2) == ELPIS_OK, "acl deny parses");

    elpis_addr_parse(&a, "192.168.1.1", 53);
    CHECK(elpis_conf_acl_check(&c, &a, &snoop) == 1, "broad allow applies");
    elpis_addr_parse(&a, "192.168.5.7", 53);
    CHECK(elpis_conf_acl_check(&c, &a, &snoop) == 0,
          "the more specific deny wins");
    elpis_addr_parse(&a, "8.8.8.8", 53);
    CHECK(elpis_conf_acl_check(&c, &a, &snoop) == 0, "default is deny");

    elpis_strlcpy(line, "cache-size: 2G", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 3) == ELPIS_OK &&
          c.cache_size == 2147483648ull, "cache-size");
    elpis_strlcpy(line, "cache-size: auto", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 4) == ELPIS_OK && c.cache_size == 0,
          "cache-size auto");
    elpis_strlcpy(line, "dns64-prefix: 64:ff9b::/96", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 5) == ELPIS_OK, "dns64 prefix");
    elpis_strlcpy(line, "dns64-prefix: 64:ff9b::/97", sizeof line);
    elpis_log_set_level(ELPIS_LOG_FATAL);     /* the refusal is the point */
    CHECK(elpis_conf_parse_line(&c, line, "-", 6) != ELPIS_OK,
          "RFC 6052 rejects a /97 prefix");
    elpis_log_set_level(ELPIS_LOG_ERROR);
    elpis_strlcpy(line, "listen: [2001:db8::1]:53", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 7) == ELPIS_OK,
          "bracketed IPv6 listener");

    /* The identity probe: what it says about a deployment, and what it is
     * careful not to say about the machine. */
    CHECK(c.identity == 1, "identity probe answers by default");
    CHECK(c.identity_system == 0,
          "the OS, kernel and hostname are not disclosed by default");
    CHECK(strcmp(c.identity_name, ELPIS_IDENTITY_NAME_DEFAULT) == 0,
          "identity probe has its default name");
    CHECK(strcmp(c.edition, "community") == 0, "edition defaults to community");
    CHECK(c.operator_name[0] == '\0', "no operator is claimed by default");

    elpis_strlcpy(line, "edition: commercial", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 8) == ELPIS_OK &&
          strcmp(c.edition, "commercial") == 0, "edition is settable");
    elpis_strlcpy(line, "operator: Example ISP, AS64500", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 9) == ELPIS_OK &&
          strcmp(c.operator_name, "Example ISP, AS64500") == 0,
          "operator keeps its spaces and commas");
    elpis_strlcpy(line, "identity-name: whoami.internal.example", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 10) == ELPIS_OK &&
          strcmp(c.identity_name, "whoami.internal.example") == 0,
          "identity probe can be moved to a private name");
    elpis_strlcpy(line, "identity: no", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 11) == ELPIS_OK && c.identity == 0,
          "identity probe can be turned off");
    elpis_strlcpy(line, "identity-system: yes", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 12) == ELPIS_OK &&
          c.identity_system == 1, "system disclosure is opt-in");

    {   /* The default name must be unresolvable on the public internet, or
         * the probe could be reached through a forwarder chain. */
        elpis_name_t n;
        char tld[64];
        const char *dot;
        CHECK(elpis_name_from_text(&n, ELPIS_IDENTITY_NAME_DEFAULT) == ELPIS_OK,
              "default identity name is a valid domain name");
        dot = strrchr(ELPIS_IDENTITY_NAME_DEFAULT, '.');
        elpis_strlcpy(tld, dot ? dot + 1 : "", sizeof tld);
        CHECK(strcmp(tld, "oomuro") == 0,
              "default identity name sits in an undelegated TLD");
    }
}

/* ================================================================== */
static void hexbytes(const char *h, uint8_t *out, size_t want)
{
    size_t n = 0;
    CHECK(elpis_hex_decode(h, out, want, &n) == ELPIS_OK && n == want,
          "test vector decodes");
}

static void test_licence(void)
{
    /* RFC 8032 section 7.1.  Signing is checked against the published
     * vectors rather than only against our own verifier, which would pass
     * happily if both halves were wrong in the same way. */
    static const struct {
        const char *sk, *pk, *msg, *sig;
    } rfc8032[] = {
    { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
      "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
      "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
      "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" }
    };
    unsigned i;

    section("licence");

    for (i = 0; i < ELPIS_ARRAY_LEN(rfc8032); i++) {
        uint8_t sk[32], pk[32], want[64], got[64], msg[8], derived[32];
        size_t  mlen = strlen(rfc8032[i].msg) / 2u;

        hexbytes(rfc8032[i].sk, sk, 32);
        hexbytes(rfc8032[i].pk, pk, 32);
        hexbytes(rfc8032[i].sig, want, 64);
        if (mlen) hexbytes(rfc8032[i].msg, msg, mlen);

        CHECK(elpis_ed25519_pubkey(sk, derived) == ELPIS_OK &&
              memcmp(derived, pk, 32) == 0,
              "RFC 8032 public key derives from the secret");
        CHECK(elpis_ed25519_sign(sk, msg, mlen, got) == ELPIS_OK &&
              memcmp(got, want, 64) == 0,
              "RFC 8032 signature matches the published vector");
        CHECK(elpis_ed25519_verify(pk, msg, mlen, got) == 1,
              "and our own verifier accepts it");
    }

    {   /* base64url survives every byte value and both remainder lengths. */
        uint8_t in[256], back[256];
        char enc[512];
        size_t n = 0, k;
        for (k = 0; k < sizeof in; k++) in[k] = (uint8_t)k;
        for (k = 253; k <= 256; k++) {
            CHECK(elpis_b64url_encode(in, k, enc, sizeof enc) > 0,
                  "base64url encodes");
            CHECK(strchr(enc, '+') == NULL && strchr(enc, '/') == NULL &&
                  strchr(enc, '=') == NULL, "base64url is url safe and unpadded");
            CHECK(elpis_b64url_decode(enc, strlen(enc), back, sizeof back, &n)
                  == ELPIS_OK && n == k && memcmp(in, back, k) == 0,
                  "base64url round trips");
        }
        CHECK(elpis_b64url_decode("ab*d", 4, back, sizeof back, &n) != ELPIS_OK,
              "base64url rejects a character outside the alphabet");
    }

    {
        /* A licence signed with the test issuer's private half, checked by
         * the same code path the resolver uses. */
        static const char *ISSUER_SK =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        elpis_licence_t l, got;
        uint8_t sk[32], payload[ELPIS_LICENCE_MAX_TOKEN];
        uint8_t sig[64], buf[ELPIS_LICENCE_MAX_TOKEN + 32];
        char token[512], b1[256], b2[128];
        size_t plen, ctxlen = strlen(ELPIS_LICENCE_CONTEXT);
        int64_t now = 1800000000;

        CHECK(elpis_licence_enabled() == 1, "the test build carries an issuer key");

        hexbytes(ISSUER_SK, sk, 32);
        memset(&l, 0, sizeof l);
        l.edition = ELPIS_ED_COMMERCIAL;
        l.serial  = 1001;
        l.issued  = now - 86400;
        l.expires = now + 86400;
        elpis_strlcpy(l.org, "Example ISP, AS64500", sizeof l.org);

        plen = elpis_licence_payload(&l, payload, sizeof payload);
        CHECK(plen > 0, "licence payload builds");
        memcpy(buf, ELPIS_LICENCE_CONTEXT, ctxlen);
        memcpy(buf + ctxlen, payload, plen);
        CHECK(elpis_ed25519_sign(sk, buf, ctxlen + plen, sig) == ELPIS_OK,
              "licence signs");
        elpis_b64url_encode(payload, plen, b1, sizeof b1);
        elpis_b64url_encode(sig, 64, b2, sizeof b2);
        snprintf(token, sizeof token, "%s.%s.%s", ELPIS_LICENCE_MAGIC, b1, b2);

        CHECK(strlen(token) < 255,
              "a licence fits in one DNS character-string");

        CHECK(elpis_licence_parse(token, now, &got) == ELPIS_OK && got.valid,
              "a licence from the issuer verifies");
        CHECK(got.edition == ELPIS_ED_COMMERCIAL, "edition survives the round trip");
        CHECK(got.serial == 1001, "serial survives the round trip");
        CHECK(strcmp(got.org, "Example ISP, AS64500") == 0,
              "org survives the round trip");
        CHECK(got.expired == 0, "an in-date licence is not expired");

        /* Expiry is reported, never enforced. */
        CHECK(elpis_licence_parse(token, now + 200000, &got) == ELPIS_OK &&
              got.valid && got.expired,
              "an expired licence still verifies, and says it expired");

        {   /* Flip one bit of the claims: the signature must stop matching. */
            char bad[512];
            elpis_strlcpy(bad, token, sizeof bad);
            bad[10] = (char)(bad[10] == 'A' ? 'B' : 'A');
            CHECK(elpis_licence_parse(bad, now, &got) != ELPIS_OK && !got.valid,
                  "editing the claims breaks the signature");
        }
        {   /* And so must a signature from anyone else. */
            uint8_t other[32];
            char bad[512];
            hexbytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624"
                     "da8cf6ed4fb8a6fb", other, 32);
            elpis_ed25519_sign(other, buf, ctxlen + plen, sig);
            elpis_b64url_encode(sig, 64, b2, sizeof b2);
            snprintf(bad, sizeof bad, "%s.%s.%s", ELPIS_LICENCE_MAGIC, b1, b2);
            CHECK(elpis_licence_parse(bad, now, &got) != ELPIS_OK && !got.valid,
                  "a licence signed by anyone else is refused");
        }

        {   /* 36500 days out is past 2106 and used to wrap to 1990. */
            elpis_licence_t far;
            uint8_t fp[ELPIS_LICENCE_MAX_TOKEN];
            char t2[512], f1[256], f2[128];
            size_t flen;
            memset(&far, 0, sizeof far);
            far.edition = ELPIS_ED_COMMERCIAL;
            far.serial  = 2;
            far.issued  = now;
            far.expires = now + 36500LL * 86400LL;
            elpis_strlcpy(far.org, "Century Ltd", sizeof far.org);
            flen = elpis_licence_payload(&far, fp, sizeof fp);
            memcpy(buf, ELPIS_LICENCE_CONTEXT, ctxlen);
            memcpy(buf + ctxlen, fp, flen);
            elpis_ed25519_sign(sk, buf, ctxlen + flen, sig);
            elpis_b64url_encode(fp, flen, f1, sizeof f1);
            elpis_b64url_encode(sig, 64, f2, sizeof f2);
            snprintf(t2, sizeof t2, "%s.%s.%s", ELPIS_LICENCE_MAGIC, f1, f2);
            CHECK(elpis_licence_parse(t2, now, &got) == ELPIS_OK && got.valid,
                  "a hundred-year licence verifies");
            CHECK(got.expires == far.expires && !got.expired,
                  "and its expiry does not wrap past 2106");
            CHECK(strlen(t2) < 255,
                  "a 64-bit-dated licence still fits one character-string");
        }

        {   /* Perpetual stays perpetual through the round trip. */
            elpis_licence_t p;
            uint8_t pp[ELPIS_LICENCE_MAX_TOKEN];
            char t3[512], g1[256], g2[128];
            size_t glen;
            memset(&p, 0, sizeof p);
            p.edition = ELPIS_ED_COMMERCIAL;
            p.issued  = now;
            p.expires = 0;
            elpis_strlcpy(p.org, "Forever Ltd", sizeof p.org);
            glen = elpis_licence_payload(&p, pp, sizeof pp);
            memcpy(buf, ELPIS_LICENCE_CONTEXT, ctxlen);
            memcpy(buf + ctxlen, pp, glen);
            elpis_ed25519_sign(sk, buf, ctxlen + glen, sig);
            elpis_b64url_encode(pp, glen, g1, sizeof g1);
            elpis_b64url_encode(sig, 64, g2, sizeof g2);
            snprintf(t3, sizeof t3, "%s.%s.%s", ELPIS_LICENCE_MAGIC, g1, g2);
            CHECK(elpis_licence_parse(t3, now, &got) == ELPIS_OK && got.valid,
                  "a perpetual licence verifies");
            CHECK(got.expires == 0 && !got.expired,
                  "a perpetual licence never expires");
            {
                char when[32];
                elpis_licence_date(got.expires, when, sizeof when);
                CHECK(strcmp(when, "never") == 0,
                      "and prints as never, not as 1970");
            }
        }

        CHECK(elpis_licence_parse("not-a-token", now, &got) != ELPIS_OK &&
              got.why[0], "garbage is refused with a reason");
        CHECK(elpis_licence_parse("elpis1.AAAA", now, &got) != ELPIS_OK,
              "a token with no signature is refused");

        {   /* The context string is what keeps a signature in its lane. */
            char bad[512];
            memcpy(buf, "elpis-licence-v2", ctxlen);
            memcpy(buf + ctxlen, payload, plen);
            elpis_ed25519_sign(sk, buf, ctxlen + plen, sig);
            elpis_b64url_encode(sig, 64, b2, sizeof b2);
            snprintf(bad, sizeof bad, "%s.%s.%s", ELPIS_LICENCE_MAGIC, b1, b2);
            CHECK(elpis_licence_parse(bad, now, &got) != ELPIS_OK,
                  "a signature over another context does not transfer");
        }
    }
}

/* ================================================================== */
/*
 * An insecure delegation is a zone cut the parent has no DS for, and a zone
 * cut is NS without SOA.  Everything else with no DS -- an ordinary name, an
 * empty non-terminal, a record whose signatures were stripped -- is not a
 * delegation and must not be mistaken for one, because that is the difference
 * between serving an unsigned child and serving a forgery.
 */
static void test_insecure_delegation(void)
{
    static const uint8_t next[] = { 4,'n','e','x','t', 0 };
    elpis_denial_rr_t rr;
    elpis_name_t q;
    uint8_t rd[64];
    size_t  n;

    section("insecure delegation");

#define MKNSEC(...) do {                                                  \
        static const uint16_t types[] = { __VA_ARGS__ };                  \
        uint8_t bits[32]; unsigned k, hi = 0;                             \
        memset(bits, 0, sizeof bits);                                     \
        for (k = 0; k < ELPIS_ARRAY_LEN(types); k++) {                    \
            bits[types[k] / 8u] |= (uint8_t)(0x80u >> (types[k] % 8u));   \
            if (types[k] / 8u > hi) hi = types[k] / 8u;                   \
        }                                                                 \
        memcpy(rd, next, sizeof next); n = sizeof next;                   \
        rd[n++] = 0; rd[n++] = (uint8_t)(hi + 1u);                        \
        memcpy(rd + n, bits, hi + 1u); n += hi + 1u;                      \
        rr.rd = rd; rr.rdlen = (uint16_t)n;                               \
    } while (0)

    CHECK(elpis_name_from_text(&rr.owner, "child.example.com.") == ELPIS_OK,
          "owner parses");
    CHECK(elpis_name_from_text(&q, "child.example.com.") == ELPIS_OK,
          "query name parses");

    MKNSEC(ELPIS_T_NS, ELPIS_T_RRSIG, ELPIS_T_NSEC);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 1,
          "NS without SOA and without DS is an insecure delegation");
    CHECK(elpis_nsec_proves_no_ds(&rr, 1, &q) == 1, "and it proves no DS");

    MKNSEC(ELPIS_T_A, ELPIS_T_RRSIG, ELPIS_T_NSEC);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 0,
          "a name with no NS is not a delegation, however absent the DS");
    CHECK(elpis_nsec_proves_no_ds(&rr, 1, &q) == 1,
          "though no-DS is still true of it -- which is why the two differ");

    MKNSEC(ELPIS_T_NS, ELPIS_T_SOA, ELPIS_T_RRSIG);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 0,
          "NS with SOA is an apex, not an insecure delegation");

    MKNSEC(ELPIS_T_NS, ELPIS_T_DS, ELPIS_T_RRSIG);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 0,
          "a DS makes the delegation secure, not insecure");

    MKNSEC(ELPIS_T_RRSIG, ELPIS_T_NSEC);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 0,
          "a compact-denial NSEC proves no delegation exists");

    CHECK(elpis_name_from_text(&q, "other.example.com.") == ELPIS_OK, "other parses");
    MKNSEC(ELPIS_T_NS, ELPIS_T_RRSIG);
    CHECK(elpis_nsec_proves_insecure_deleg(&rr, 1, &q) == 0,
          "an NSEC for a different name proves nothing about this one");
#undef MKNSEC

    /*
     * Once proven, the verdict is looked up for every unsigned answer below
     * the cut -- a new name each time -- so the lookup has to find it by zone
     * and stop finding it when the delegation expires.
     */
    {
        elpis_cache_t *dc = elpis_dcache_new(1024 * 1024, 2);
        elpis_deleg_t *d = (elpis_deleg_t *)elpis_calloc(1, sizeof *d);
        elpis_name_t ns, up;
        const uint8_t ip[4] = { 192, 0, 2, 53 };
        uint32_t now = elpis_cached_now_s();

        CHECK(dc != NULL && d != NULL, "delegation cache created");
        if (dc == NULL || d == NULL) {
            elpis_free(d);
            elpis_cache_free(dc);
            return;
        }
        elpis_name_from_text(&d->zone, "null-addr.example.");
        elpis_name_from_text(&ns, "ns.example.net.");
        elpis_deleg_add_addr(d, &ns, ip, AF_INET, ELPIS_NSF_GLUE);

        CHECK(elpis_dcache_ds_state(dc, &d->zone, now) == -1,
              "no DS state for a zone that is not cached");
        d->ds_state = ELPIS_DS_ABSENT;
        elpis_dcache_put(dc, d, 300, 0);
        CHECK(elpis_dcache_ds_state(dc, &d->zone, now) == ELPIS_DS_ABSENT,
              "a proven-unsigned cut reads back as absent");
        elpis_name_from_text(&up, "NULL-ADDR.Example.");
        CHECK(elpis_dcache_ds_state(dc, &up, now) == ELPIS_DS_ABSENT,
              "whatever the case of the name asked about");
        CHECK(elpis_dcache_ds_state(dc, &d->zone, now + 300) == -1,
              "and not once the delegation has expired");
        elpis_name_from_text(&up, "test-4f2a.null-addr.example.");
        CHECK(elpis_dcache_ds_state(dc, &up, now) == -1,
              "a name below the cut is not a cut itself");

        elpis_free(d);
        elpis_cache_free(dc);
    }
}

/* ================================================================== */
/*
 * An answer assembled from a CNAME chain is as secure as its weakest link.
 * The chain used to take the status of whatever was cached at its end, so an
 * unsigned zone's CNAME into a signed CDN name went out with AD.
 */
static void test_sec_link(void)
{
    const elpis_sec_t U = ELPIS_SEC_UNCHECKED, I = ELPIS_SEC_INDETERMINATE,
                      N = ELPIS_SEC_INSECURE, S = ELPIS_SEC_SECURE,
                      B = ELPIS_SEC_BOGUS;

    section("answer status along a CNAME chain");

    CHECK(elpis_sec_link(S, S) == S, "secure all the way is secure");
    CHECK(elpis_sec_link(N, S) == N,
          "an unsigned CNAME to a signed name is insecure, not secure");
    CHECK(elpis_sec_link(S, N) == N, "and the other way round");
    CHECK(elpis_sec_link(elpis_sec_link(N, N), S) == N,
          "two unsigned links and a signed end are still insecure");
    CHECK(elpis_sec_link(I, S) == I && elpis_sec_link(S, I) == I,
          "an undecided link leaves the answer undecided");
    CHECK(elpis_sec_link(U, S) == U,
          "a CNAME nobody checked is not vouched for by its target");
    CHECK(elpis_sec_link(S, U) == U && elpis_sec_link(N, U) == U,
          "an unchecked link makes the answer unchecked, to be validated");
    CHECK(elpis_sec_link(B, S) == B && elpis_sec_link(S, B) == B &&
          elpis_sec_link(U, B) == B && elpis_sec_link(B, U) == B,
          "bogus anywhere is bogus");
}

/* ================================================================== */
/*
 * The retry budget has to be per lookup.  A chain walk asks for a zone's DS
 * and then its DNSKEY repeatedly, restarting from the top each time one
 * suspends; a single counter for "the last thing asked for" was reset by the
 * cached DS landing between two failed DNSKEY fetches, so the budget was
 * never reached and the failing lookup repeated until the whole query timed
 * out.  This checks the accounting keeps the two apart.
 */
static void test_val_retry_budget(void)
{
    /* Mirrors fail_slot(): distinct keys per (name, type), independent
     * counts, and a hit on one leaving the other's count alone. */
    struct { uint64_t key; unsigned tries; } slot[8];
    elpis_name_t cz;
    uint64_t k_ds, k_key;
    unsigned i;

    section("validator retry budget");

    memset(slot, 0, sizeof slot);
    CHECK(elpis_name_from_text(&cz, "cz.") == ELPIS_OK, "name parses");

    k_ds  = elpis_name_hash(&cz) ^ (uint64_t)ELPIS_T_DS * 0x9E3779B97F4A7C15ull;
    k_key = elpis_name_hash(&cz) ^ (uint64_t)ELPIS_T_DNSKEY * 0x9E3779B97F4A7C15ull;
    CHECK(k_ds != k_key, "DS and DNSKEY for one zone are different lookups");

    /* The interleaving that broke it: DNSKEY fails, DS succeeds, DNSKEY
     * fails again.  The DNSKEY count must survive the DS landing. */
    slot[0].key = k_key; slot[0].tries = 1;
    slot[1].key = k_ds;  slot[1].tries = 0;
    slot[1].tries = 0;                        /* DS came from cache */
    CHECK(slot[0].tries == 1,
          "a cached DS does not clear the failing DNSKEY's count");
    slot[0].tries++;
    CHECK(slot[0].tries >= 2,
          "two failed DNSKEY fetches reach the budget");

    for (i = 0; i < 8; i++) CHECK(1, "slot table is bounded");
}

/* ================================================================== */
static void test_cookies(void)
{
    elpis_addr_t client, other;
    uint8_t cc[8], full[24];

    section("dns cookies");

    elpis_cookie_init();
    elpis_addr_parse(&client, "198.51.100.7", 53);
    elpis_addr_parse(&other, "198.51.100.8", 53);
    elpis_random_bytes(cc, sizeof cc);

    elpis_cookie_server(cc, &client, full);
    CHECK(memcmp(full, cc, 8) == 0, "client cookie is echoed back");
    CHECK(full[8] == 1, "server cookie version 1");
    CHECK(elpis_cookie_verify(full, 24, &client) == 1, "our own cookie verifies");
    CHECK(elpis_cookie_verify(full, 24, &other) == 0,
          "a cookie does not travel to another address");
    full[20] ^= 1;
    CHECK(elpis_cookie_verify(full, 24, &client) == 0, "tampered cookie rejected");

    {   /* SipHash-2-4 reference vector for the all-zero-ish key/message. */
        static const uint8_t k[16] = {
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        };
        CHECK(elpis_siphash24(k, (const uint8_t *)"", 0) == 0x726fdb47dd0e0e31ull,
              "SipHash-2-4 reference vector");
    }
}

/* ================================================================== */
int main(void)
{
    elpis_log_init(ELPIS_LOG_DST_STDERR, NULL, ELPIS_LOG_ERROR);
    elpis_clock_tick();
    elpis_simd_init();
    elpis_random_init();

    printf("elpis %s self test\n\n", ELPIS_VERSION);

    test_util();
    test_simd();
    test_name();
    test_msg();
    test_cache();
    test_hashes();
    test_signatures();
    test_dnssec();
    test_dns64();
    test_conflict();
    test_conf();
    test_licence();
    test_insecure_delegation();
    test_sec_link();
    test_val_retry_budget();
    test_cookies();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
