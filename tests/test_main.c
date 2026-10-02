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
#include "elpis/ctx.h"
#include "elpis/deleg.h"
#include "elpis/infra.h"
#include "elpis/conflict.h"
#include "elpis/quirks.h"
#include "simd/simd_internal.h"
#include "crypto/bn.h"

#include "vectors.h"

#include <stdio.h>
#include <unistd.h>

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

/*
 * The hash as it was first written: each 16-byte block, and then the tail,
 * case-folded a byte at a time into a zeroed buffer.  Every kernel shares
 * elpis_hash_tail(), the scalar one included, so comparing them with each
 * other cannot catch a mistake in it; this can.
 */
static uint64_t ref_hash_ci(const uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t h = elpis_hash_seed(seed);
    uint8_t t[16];
    size_t i = 0, j, k;

    for (;;) {
        k = n - i < 16 ? n - i : 16;
        memset(t, 0, sizeof t);
        for (j = 0; j < k; j++) {
            uint8_t c = p[i + j];
            t[j] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
        }
        if (k < 16)
            return elpis_hash_finish(h, elpis_load64(t), elpis_load64(t + 8), n);
        h = elpis_hash_step(h, elpis_load64(t), elpis_load64(t + 8));
        i += 16;
    }
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

    /*
     * The hash must match the byte-at-a-time reference at every length and
     * alignment.  Each name ends exactly where its allocation does, so a
     * kernel reading past it trips ASan; at offset 0 so does one reading
     * before it.
     */
    {
        uint8_t src[300 + 16];
        uint32_t x = 0x9E3779B9u;
        size_t off;
        int ok = 1;

        for (i = 0; i < sizeof src; i++) {
            x = x * 1664525u + 1013904223u;
            src[i] = (uint8_t)(x >> 24);
            if ((x & 0x300u) == 0)                /* plenty of A-Z and a-z */
                src[i] = (uint8_t)("AZaz@[`{"[(x >> 12) & 7u]);
            else if ((x & 0x300u) == 0x100u)
                src[i] = (uint8_t)('A' + (x >> 12) % 26u + ((x >> 20) & 1u) * 32u);
        }
        for (n = 0; n <= 300 && ok; n++)
            for (off = 0; off < 16 && ok; off++) {
                uint8_t *buf = (uint8_t *)elpis_malloc(off + n);
                uint64_t want;

                memcpy(buf + off, src + off, n);
                want = ref_hash_ci(buf + off, n, n * 131u + off);
                if (elpis_scalar_hash_ci(buf + off, n, n * 131u + off) != want ||
                    elpis_simd_hash_ci(buf + off, n, n * 131u + off) != want) {
                    CHECK(0, "hash differs from the reference at n=%zu off=%zu", n, off);
                    ok = 0;
                }
                elpis_free(buf);
            }
        if (ok)
            g_pass++;
    }

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
/*
 * Holding down a silent server (infra.h).  What matters is what does not
 * hold: a burst, a silence nobody else broke either, and a type the server
 * still answers.
 */
static void test_infra_hold(void)
{
    elpis_cache_t *c;
    elpis_addr_t a, b;
    elpis_infra_info_t inf;
    const uint32_t t0 = 100000;

    section("infra hold-down");

    c = elpis_infra_new(2 * 1024 * 1024, 4);
    CHECK(c != NULL, "infra cache created");
    if (c == NULL)
        return;
    elpis_addr_parse(&a, "192.0.2.53", 53);
    elpis_addr_parse(&b, "198.51.100.53", 53);

    /* Three at once, as when a path blips with queries in flight. */
    elpis_infra_timeout(c, &a, ELPIS_T_A, t0, 30);
    elpis_infra_timeout(c, &a, ELPIS_T_A, t0, 30);
    elpis_infra_timeout(c, &a, ELPIS_T_A, t0 + 1, 30);
    elpis_infra_get(c, &a, &inf);
    CHECK(inf.timeouts == 3 && elpis_infra_cost(&inf) == ELPIS_RTT_BAN,
          "three timeouts ban the server as before");
    CHECK(!elpis_infra_held(&inf, ELPIS_T_A, t0 + 1),
          "but a burst inside a second does not hold it");

    /* Silent for ten seconds, but nobody else was answering either. */
    elpis_infra_timeout(c, &a, ELPIS_T_A, t0 + 10, 0);
    elpis_infra_get(c, &a, &inf);
    CHECK(!elpis_infra_held(&inf, ELPIS_T_A, t0 + 10),
          "a silence nobody else broke does not hold it");

    elpis_infra_timeout(c, &a, ELPIS_T_A, t0 + 11, 30);
    elpis_infra_get(c, &a, &inf);
    CHECK(elpis_infra_held(&inf, ELPIS_T_A, t0 + 11),
          "silent 11 s while others answered: held for A");
    CHECK(!elpis_infra_held(&inf, ELPIS_T_AAAA, t0 + 11) &&
          !elpis_infra_held(&inf, ELPIS_T_HTTPS, t0 + 11) &&
          !elpis_infra_held(&inf, ELPIS_T_DNSKEY, t0 + 11),
          "and only for A");
    CHECK(elpis_infra_held(&inf, ELPIS_T_A, t0 + 40) &&
          !elpis_infra_held(&inf, ELPIS_T_A, t0 + 41),
          "for server-hold-down seconds");
    CHECK(!elpis_infra_probe_due(&inf, ELPIS_T_A, t0 + 40) &&
          elpis_infra_probe_due(&inf, ELPIS_T_A, t0 + 41) &&
          !elpis_infra_probe_due(&inf, ELPIS_T_AAAA, t0 + 41),
          "then the next A query is the probe");

    elpis_infra_hold(c, &a, t0 + 71);
    elpis_infra_get(c, &a, &inf);
    CHECK(elpis_infra_held(&inf, ELPIS_T_A, t0 + 42),
          "the probe takes the next hold as it goes out");

    /* Still silent, so another type times out once and is held with it. */
    elpis_infra_timeout(c, &a, ELPIS_T_HTTPS, t0 + 50, 30);
    elpis_infra_get(c, &a, &inf);
    CHECK(elpis_infra_held(&inf, ELPIS_T_HTTPS, t0 + 50) &&
          elpis_infra_held(&inf, ELPIS_T_SVCB, t0 + 50) &&
          !elpis_infra_held(&inf, ELPIS_T_AAAA, t0 + 50),
          "HTTPS and SVCB share a hold; AAAA is still asked");

    elpis_infra_rtt_ok(c, &a, 20);
    elpis_infra_get(c, &a, &inf);
    CHECK(!elpis_infra_held(&inf, ELPIS_T_A, t0 + 51) &&
          !elpis_infra_held(&inf, ELPIS_T_HTTPS, t0 + 51) &&
          inf.timeouts == 0 && inf.silent_types == 0 && inf.hold_until == 0,
          "one answer clears every hold");
    elpis_infra_hold(c, &a, t0 + 200);
    elpis_infra_get(c, &a, &inf);
    CHECK(inf.hold_until == 0,
          "a probe that lost the race to an answer takes no hold");

    /* A server that drops HTTPS and answers A: its HTTPS silence runs on
     * while A comes from the cache, and A must still be asked. */
    elpis_infra_rtt_ok(c, &b, 20);
    elpis_infra_timeout(c, &b, ELPIS_T_HTTPS, t0, 30);
    elpis_infra_timeout(c, &b, ELPIS_T_HTTPS, t0 + 5, 30);
    elpis_infra_timeout(c, &b, ELPIS_T_HTTPS, t0 + 12, 30);
    elpis_infra_get(c, &b, &inf);
    CHECK(elpis_infra_held(&inf, ELPIS_T_HTTPS, t0 + 12) &&
          !elpis_infra_held(&inf, ELPIS_T_A, t0 + 12) &&
          !elpis_infra_held(&inf, ELPIS_T_AAAA, t0 + 12),
          "a server silent only on HTTPS is held only for HTTPS");
    CHECK(!elpis_infra_probe_due(&inf, ELPIS_T_A, t0 + 60),
          "and an A query to it is not taken for a probe");

    elpis_cache_free(c);
}

/* ================================================================== */
/*
 * The status page's list of held servers: one row per server and silence,
 * the query that set the hold off kept apart from the latest one, and the
 * zone written the way the turned-away tally writes it so the two join up.
 */
static void test_held_rows(void)
{
    static elpis_tmheld_t rows[ELPIS_TM_HELD];
    elpis_tmrow_t top[4];
    elpis_wtm_t *w;
    elpis_tmhold_t h;
    elpis_addr_t s1, s2, cl, extra;
    elpis_name_t zone, qn;
    unsigned n, i;
    int found;

    section("held servers on the status page");

    elpis_tm_init(1);
    elpis_addr_parse(&s1, "24.216.90.1", 53);
    elpis_addr_parse(&s2, "24.216.90.2", 53);
    elpis_addr_parse(&cl, "10.1.2.3@40000", 53);
    elpis_name_from_text(&zone, "Spectrum.COM.");
    elpis_name_from_text(&qn, "024-231-165-138.res.spectrum.com.");

    memset(&h, 0, sizeof h);
    h.server = &s1;
    h.zone   = &zone;
    h.qname  = &qn;
    h.qtype  = ELPIS_T_A;
    h.client = &cl;
    h.streak = 1000;
    h.types  = ELPIS_QC_A;
    h.now    = 1010;
    elpis_tm_held(&h);
    n = elpis_tm_held_rows(rows, ELPIS_TM_HELD);
    CHECK(n == 1 && rows[0].holds == 1 && rows[0].first.is_client &&
          !strcmp(rows[0].first.client, "10.1.2.3") &&
          rows[0].first.qtype == ELPIS_T_A && rows[0].first.at == 1010,
          "a hold is listed with the client that set it off, without its port");
    CHECK(strstr(rows[0].zone, "spectrum.com") == rows[0].zone &&
          strstr(rows[0].first.qname, "024-231-165-138.res.spectrum.com") ==
          rows[0].first.qname,
          "zone and question are kept, in lowercase");

    h.client = NULL;
    h.who    = "prefetch";
    h.types  = ELPIS_QC_A | ELPIS_QC_OTHER;
    h.now    = 1040;
    elpis_tm_held(&h);
    n = elpis_tm_held_rows(rows, ELPIS_TM_HELD);
    CHECK(n == 1 && rows[0].holds == 2 &&
          !strcmp(rows[0].first.client, "10.1.2.3") &&
          !strcmp(rows[0].last.client, "prefetch") && !rows[0].last.is_client &&
          rows[0].types == (ELPIS_QC_A | ELPIS_QC_OTHER),
          "held again in the same silence: the first trigger stays, the latest moves");

    h.client = &cl;
    h.streak = 2000;
    h.now    = 2010;
    elpis_tm_held(&h);
    n = elpis_tm_held_rows(rows, ELPIS_TM_HELD);
    CHECK(n == 1 && rows[0].holds == 1 && rows[0].first.at == 2010,
          "a new silence starts the row afresh");

    h.server = &s2;
    h.now    = 2020;
    elpis_tm_held(&h);
    n = elpis_tm_held_rows(rows, ELPIS_TM_HELD);
    CHECK(n == 2 && elpis_addr_eq(&rows[0].server, &s2) &&
          elpis_addr_eq(&rows[1].server, &s1),
          "rows come most recently held first");

    for (i = 0; i < ELPIS_TM_HELD - 1u; i++) {
        uint8_t ip[4] = { 192, 0, 2, (uint8_t)(i + 1u) };
        elpis_addr_from4(&extra, ip, 53);
        h.server = &extra;
        h.now    = 3000 + i;
        elpis_tm_held(&h);
    }
    n = elpis_tm_held_rows(rows, ELPIS_TM_HELD);
    found = 0;
    for (i = 0; i < n; i++)
        if (elpis_addr_eq(&rows[i].server, &s1))
            found = 1;
    CHECK(n == ELPIS_TM_HELD && !found,
          "when the list is full, the server held longest ago gives way");

    w = (elpis_wtm_t *)elpis_calloc(1, sizeof *w);
    CHECK(w != NULL, "worker tallies allocated");
    if (w != NULL) {
        elpis_tm_turned_away(w, &zone);
        elpis_tm_turned_away(w, &zone);
        elpis_tm_turned_away(w, &zone);
        elpis_tm_publish(w);
        n = elpis_tm_top(ELPIS_TOP_HELD_ZONE, top, 4);
        CHECK(n == 1 && top[0].count == 3 && !strcmp(top[0].key, rows[0].zone),
              "lookups turned away are counted by zone, keyed as the rows are");
        elpis_free(w);
    }

    elpis_tm_init(0);
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
    CHECK(buf->zone_labels == 0, "a plain put records no serving zone");

    /*
     * The serving zone has to survive the cache.  Without it a replayed
     * RRset is one the validator declines to judge, and a copy stripped of
     * its signatures was served as merely unsigned to whoever asked while
     * the first copy was still being validated.
     */
    {
        elpis_name_t zn;
        elpis_name_from_text(&zn, "stamped.example.");
        elpis_rrset_buf_init(buf, &zn, ELPIS_T_A, ELPIS_CLASS_IN, 300);
        buf->zone_labels = 2;
        elpis_rrset_buf_add(buf, rd, 4);
        CHECK(elpis_rcache_put_buf(rc, buf, 0, 0) == ELPIS_OK, "put with a zone");
        elpis_rrset_buf_init(buf, &n, ELPIS_T_A, ELPIS_CLASS_IN, 0);
        CHECK(elpis_rcache_get(rc, &zn, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_OK &&
              buf->zone_labels == 2, "the serving zone comes back out");
    }

    /*
     * The root is a zone like any other.  As a bare label count it was 0,
     * which is also "unknown", and everything under "forward-zone: ." -- where
     * the root is the zone we asked -- went out unjudged, stripped or not.
     */
    {
        elpis_name_t root, zn;
        elpis_name_init_root(&root);
        elpis_name_from_text(&zn, "via-forwarder.example.");
        CHECK(ELPIS_ZONE_STAMP(&root) != 0, "the root has a stamp of its own");
        elpis_rrset_buf_init(buf, &zn, ELPIS_T_A, ELPIS_CLASS_IN, 300);
        buf->zone_labels = ELPIS_ZONE_STAMP(&root);
        elpis_rrset_buf_add(buf, rd, 4);
        elpis_rcache_put_buf(rc, buf, 0, 0);
        CHECK(elpis_rcache_get(rc, &zn, ELPIS_T_A, ELPIS_CLASS_IN,
                               elpis_now_s(), 0, buf) == ELPIS_OK &&
              buf->zone_labels == ELPIS_ZONE_STAMP(&root),
              "and it survives the cache");
    }

    /*
     * The verdict on a DS denial, read without copying the proof out: under
     * a forward-zone it is the only record that a zone was proven unsigned.
     */
    {
        elpis_name_t zn;
        uint8_t sec = 0xFF, flags = 0;
        const uint8_t soa = 0;
        elpis_name_from_text(&zn, "unsigned-child.example.");
        elpis_rrset_buf_init(buf, &zn, ELPIS_T_DS, ELPIS_CLASS_IN, 300);
        buf->flags = ELPIS_RRF_NODATA;
        buf->sec = (uint8_t)ELPIS_SEC_INSECURE;
        elpis_rrset_buf_add(buf, &soa, 1);
        elpis_rcache_put_buf(rc, buf, 0, 0);
        CHECK(elpis_rcache_state(rc, &zn, ELPIS_T_DS, ELPIS_CLASS_IN,
                                 elpis_now_s(), &sec, &flags) == ELPIS_OK &&
              sec == ELPIS_SEC_INSECURE && (flags & ELPIS_RRF_NODATA),
              "state reads the verdict and flags of a live entry");
        CHECK(elpis_rcache_state(rc, &zn, ELPIS_T_A, ELPIS_CLASS_IN,
                                 elpis_now_s(), &sec, &flags) == ELPIS_ENOTFOUND,
              "state misses a type that is not there");
        CHECK(elpis_rcache_state(rc, &zn, ELPIS_T_DS, ELPIS_CLASS_IN,
                                 elpis_now_s() + 301u, &sec, &flags) ==
                  ELPIS_ENOTFOUND,
              "and one that has expired, stale or not");
    }

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

    CHECK(c.server_hold_s == 30, "servers are held for 30 s by default");
    elpis_strlcpy(line, "server-hold-down: 0", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
          c.server_hold_s == 0, "server-hold-down: 0 turns holds off");
    elpis_strlcpy(line, "server-hold-down: 86400", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
          c.server_hold_s == 3600, "server-hold-down is capped at an hour");

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
    elpis_strlcpy(line, "dns64-strip-a: yes", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 5) == ELPIS_OK &&
          c.dns64_strip_a == 1, "dns64-strip-a");
    c.dns64 = 1;
    CHECK(elpis_dns64_strips(&c, ELPIS_T_A, 0, 0) &&
          elpis_dns64_strips(&c, ELPIS_T_ANY, 1, 0) &&
          !elpis_dns64_strips(&c, ELPIS_T_AAAA, 0, 0) &&
          !elpis_dns64_strips(&c, ELPIS_T_A, 1, 1),
          "strips A and ANY, not AAAA, not for a validating DO+CD client");
    c.dns64 = 0;
    CHECK(!elpis_dns64_strips(&c, ELPIS_T_A, 0, 0), "and nothing with dns64 off");
    c.dns64_strip_a = 0;
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

/*
 * A trust-anchor-file is what an operator edits in the middle of a key
 * rollover, in whatever form they have to hand: root.key as unbound-anchor
 * writes it, or a saved dig.  Both put a TTL before the class, and dig splits
 * a key into chunks.  Neither was read: the TTL was taken for the type and the
 * file loaded nothing, and past eight tokens a key was cut short.  Here the
 * root's two KSKs, exactly as dig prints them, must come out as the very DS
 * records compiled in -- a byte astray in the key and they would not.
 */
static void test_ta_file(void)
{
    static const char text[] =
        "; saved from: dig . DNSKEY\n"
        ". 172800 IN DNSKEY 257 3 8"
        " AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
        " +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv"
        " ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF"
        " 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e"
        " oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd"
        " RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN"
        " R1AkUTV74bU=\n"
        ". 172800 IN DNSKEY 257 3 8"
        " AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/c"
        " idltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHb"
        " GiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+s"
        " iFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp"
        " dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ"
        " 1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUe"
        " ayffKC73PYc=\n"
        /* class before TTL; the REVOKE bit set, so never an anchor */
        ". IN 172800 DNSKEY 385 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTO\n"
        /* more tokens than fit: refused, not loaded cut short */
        "example. 3600 IN DS 1 8 2 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15"
        " 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31\n"
        /* not an anchor at all */
        ". 172800 IN RRSIG DNSKEY 8 0 172800 20260101000000 20251201000000 1 . AA\n";
    char path[] = "/tmp/elpis-ta-XXXXXX";
    elpis_ta_store_t *want = elpis_ta_new(), *got = elpis_ta_new();
    const elpis_ta_t *w[8], *g[8];
    elpis_name_t root, ex;
    unsigned nw, ng, i, j, same = 0;
    FILE *fp;
    int fd;

    section("trust-anchor-file");
    fd = mkstemp(path);
    CHECK(fd >= 0 && want != NULL && got != NULL, "set up");
    if (fd < 0 || want == NULL || got == NULL)
        goto out;
    fp = fdopen(fd, "w");
    fputs(text, fp);
    fclose(fp);

    elpis_log_init(ELPIS_LOG_DST_NONE, NULL, ELPIS_LOG_FATAL);
    elpis_ta_add_builtin(want);
    CHECK(elpis_ta_load_file(got, path) == ELPIS_OK, "the file loads");
    unlink(path);

    elpis_name_init_root(&root);
    nw = elpis_ta_for(want, &root, w, 8);
    ng = elpis_ta_for(got, &root, g, 8);
    CHECK(nw == 2 && ng == 2, "two root anchors, as compiled in (%u of %u)",
          ng, nw);
    for (i = 0; i < nw; i++)
        for (j = 0; j < ng; j++)
            if (w[i]->keytag == g[j]->keytag && w[i]->alg == g[j]->alg &&
                w[i]->digest_type == g[j]->digest_type &&
                w[i]->digest_len == g[j]->digest_len &&
                memcmp(w[i]->digest, g[j]->digest, w[i]->digest_len) == 0)
                same++;
    CHECK(same == 2, "each is byte for byte the built-in DS (%u of 2)", same);

    elpis_name_from_text(&ex, "example.");
    CHECK(elpis_ta_for(got, &ex, g, 8) == 0,
          "an over-long line is refused, not cut short");

out:
    if (want != NULL) elpis_ta_free(want);
    if (got != NULL)  elpis_ta_free(got);
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
/*
 * handle_query() caps the client queries admitted at max-pending, but a
 * resolution spawns children (glueless nameserver addresses, the DNSSEC chain
 * walk) and background refreshes that the intake guard never sees.  Nothing
 * counted them, and a flood of uncacheable names once fanned the child trees
 * out to ~100x max-pending -- half a million tasks, a five-gigabyte heap.
 * elpis_task_new() now refuses past ELPIS_TASK_CEILING_MULT x max-pending, so
 * the table can never grow past the memory the config budgets for, and a
 * refused task is a NULL every caller already handles.
 */
static void test_task_ceiling(void)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)elpis_calloc(1, sizeof *ctx);
    elpis_worker_t *w = (elpis_worker_t *)elpis_calloc(1, sizeof *w);
    unsigned ceiling, i, made = 0;

    section("task ceiling");
    CHECK(ctx != NULL && w != NULL, "set up");
    if (ctx == NULL || w == NULL) {
        elpis_free(ctx);
        elpis_free(w);
        return;
    }

    ctx->conf.max_pending = 3;
    w->ctx  = ctx;
    w->loop = NULL;                 /* no task is started, so no timer fires */
    ceiling = ctx->conf.max_pending * ELPIS_TASK_CEILING_MULT;

    for (i = 0; i < ceiling + 8u; i++)
        if (elpis_task_new(w) != NULL)
            made++;

    CHECK(made == ceiling, "task creation stops at the ceiling (%u of %u)",
          made, ceiling);
    CHECK(w->n_tasks == ceiling, "and n_tasks never passes it (%u)", w->n_tasks);
    CHECK(elpis_task_new(w) == NULL, "a task past the ceiling is refused");
    CHECK(w->stats.overload >= 8u + 1u,
          "each refusal counts as overload (%llu)",
          (unsigned long long)w->stats.overload);

    elpis_resolver_fini(w);         /* frees every task still linked */
    CHECK(w->n_tasks == 0, "and they all free again");

    elpis_free(ctx);
    elpis_free(w);
}


/* ================================================================== */
/*
 * Montgomery multiplication against schoolbook multiply-and-reduce, for
 * moduli of every width from one limb to nine: the odd ones take the portable
 * 32-bit path, the even ones the 64-bit one where the compiler has it, and no
 * signature vector here has an odd width to exercise the first.
 */
static void test_bignum(void)
{
    unsigned k, round, bad = 0, runs = 0;

    section("bignum");
    for (k = 1; k <= 9; k++) {
        for (round = 0; round < 40; round++) {
            bn_t m, a, b, am, bm, r, want, prod;
            mont_t c;
            unsigned i;

            m.n = k;
            for (i = 0; i < k; i++)
                m.d[i] = elpis_random_u32();
            m.d[0] |= 1u;
            m.d[k - 1] |= 0x80000000u;
            if (mont_init(&c, &m) != ELPIS_OK) {
                bad++;
                continue;
            }
            a.n = b.n = k;
            for (i = 0; i < k; i++) {
                a.d[i] = elpis_random_u32();
                b.d[i] = elpis_random_u32();
            }
            a.d[k - 1] &= 0x7FFFFFFFu;       /* a, b < m */
            b.d[k - 1] &= 0x7FFFFFFFu;
            if (round == 0) {                /* the edges: m - 1 squared */
                bn_t one;
                bn_set_u32(&one, 1);
                bn_sub(&a, &m, &one);
                bn_copy(&b, &a);
            }
            bn_trim(&a);
            bn_trim(&b);

            mont_to(&am, &a, &c);
            mont_to(&bm, &b, &c);
            mont_mul(&r, &am, &bm, &c);
            mont_from(&r, &r, &c);

            bn_mul(&prod, &a, &b);
            bn_mod(&want, &prod, &m);
            if (bn_cmp(&r, &want) != 0)
                bad++;
            runs++;
        }
    }
    CHECK(bad == 0, "Montgomery products match a*b mod m (%u of %u wrong)",
          bad, runs);
}

/* ================================================================== */
/* An Ed25519 DNSKEY whose key bytes at even offsets can be swapped
 * without changing the key tag: RFC 4034 appendix B sums those bytes. */
static void keytrap_key(uint8_t rd[36], unsigned variant)
{
    unsigned i, a, b;
    uint8_t t;

    rd[0] = 0x01; rd[1] = 0x01;        /* flags 257: zone key, SEP */
    rd[2] = 3;
    rd[3] = ELPIS_ALG_ED25519;
    for (i = 0; i < 32; i++)
        rd[4 + i] = (uint8_t)(0x10 + i * 7);
    a = 4 + 2u * (variant % 16u);
    b = 4 + 2u * ((variant / 16u + variant % 16u + 1u) % 16u);
    t = rd[a]; rd[a] = rd[b]; rd[b] = t;
}

static void test_keytrap(void)
{
    static elpis_rrset_buf_t keys, set, ds;
    elpis_conf_t c;
    elpis_name_t zone;
    uint8_t rd[256];
    uint16_t tag = 0;
    unsigned i, nkeys = 0;
    uint64_t n;
    int64_t now = elpis_wall_s();
    int ede = -1, rc;

    section("keytrap");
    elpis_conf_defaults(&c);
    elpis_name_from_text(&zone, "keytrap.test.");

    /* Twenty keys, all with one key tag. */
    elpis_rrset_buf_init(&keys, &zone, ELPIS_T_DNSKEY, ELPIS_CLASS_IN, 3600);
    for (i = 0; nkeys < 20 && i < 64; i++) {
        uint8_t k[36];
        unsigned j, dup = 0;
        keytrap_key(k, i);
        for (j = 0; j < keys.count; j++)
            if (memcmp(keys.data + keys.off[j], k, 36) == 0)
                dup = 1;
        if (dup)
            continue;
        if (nkeys == 0)
            tag = elpis_dnskey_tag(k, 36);
        else if (elpis_dnskey_tag(k, 36) != tag)
            continue;
        elpis_rrset_buf_add(&keys, k, 36);
        nkeys++;
    }
    CHECK(nkeys == 20, "twenty distinct keys share key tag %u (%u)", tag, nkeys);

    /* One A record under twenty signatures naming that tag, none good. */
    elpis_rrset_buf_init(&set, &zone, ELPIS_T_A, ELPIS_CLASS_IN, 3600);
    rd[0] = 192; rd[1] = 0; rd[2] = 2; rd[3] = 1;
    elpis_rrset_buf_add(&set, rd, 4);
    for (i = 0; i < 20; i++) {
        size_t o = 0;
        elpis_put16(rd + o, ELPIS_T_A); o += 2;
        rd[o++] = ELPIS_ALG_ED25519;
        rd[o++] = 2;                               /* labels */
        elpis_put32(rd + o, 3600); o += 4;
        elpis_put32(rd + o, (uint32_t)(now + 86400)); o += 4;
        elpis_put32(rd + o, (uint32_t)(now - 86400)); o += 4;
        elpis_put16(rd + o, tag); o += 2;
        memcpy(rd + o, zone.d, zone.len); o += zone.len;
        memset(rd + o, (int)(0x40 + i), 64); o += 64;
        elpis_rrset_buf_add_sig(&set, rd, (uint16_t)o);
    }

    (void)elpis_dnssec_take_verifies();
    rc = elpis_rrset_validate(&c, &set, &keys, now, NULL, &ede);
    n = elpis_dnssec_take_verifies();
    CHECK(rc == ELPIS_EBOGUS, "twenty bad signatures are bogus");
    CHECK(n >= 1 && n <= 8, "and cost 1 to 8 verifications, not 400 (%llu)",
          (unsigned long long)n);

    /* The DNSKEY set signed the same way, with a DS for every key. */
    for (i = 0; i < set.sigcount; i++) {
        uint8_t *sig = set.data + set.off[set.count + i];
        elpis_put16(sig, ELPIS_T_DNSKEY);
        sig[3] = 2;
        elpis_rrset_buf_add_sig(&keys, sig, set.len[set.count + i]);
    }
    elpis_rrset_buf_init(&ds, &zone, ELPIS_T_DS, ELPIS_CLASS_IN, 3600);
    for (i = 0; i < keys.count; i++) {
        uint8_t buf[ELPIS_MAX_NAME + 64];
        uint8_t dsr[4 + 32];
        size_t bl = 0;
        memcpy(buf, zone.d, zone.len); bl = zone.len;
        memcpy(buf + bl, keys.data + keys.off[i], keys.len[i]); bl += keys.len[i];
        elpis_put16(dsr, tag);
        dsr[2] = ELPIS_ALG_ED25519;
        dsr[3] = 2;                                /* SHA-256 */
        elpis_sha256(buf, bl, dsr + 4);
        elpis_rrset_buf_add(&ds, dsr, sizeof dsr);
    }
    ede = -1;
    (void)elpis_dnssec_take_verifies();
    rc = elpis_dnskey_validate_ds(&c, &keys, &ds, now, &ede);
    n = elpis_dnssec_take_verifies();
    CHECK(rc == ELPIS_EBOGUS, "a DNSKEY set nobody signed is bogus");
    CHECK(n >= 1 && n <= 4u * 8u, "every DS matching tried at most 4 keys, 8 "
          "checks each (%llu, not 400)", (unsigned long long)n);

    /* RSA with a 72-bit exponent is refused before any arithmetic. */
    {
        static uint8_t key[1024], sig[1024], big[1100];
        size_t kl = unhex(TV_RSA2048_DNSKEY, key, sizeof key);
        size_t sl = unhex(TV_RSA2048_SIG, sig, sizeof sig);
        size_t off = key[0] ? 1u : 3u, elen = key[0] ? key[0] : elpis_get16(key + 1);
        uint8_t h[32];

        elpis_sha256(TV_MESSAGE, strlen(TV_MESSAGE), h);
        big[0] = 9;
        memset(big + 1, 0x01, 9);
        big[9] = key[off + elen - 1];              /* odd, like a real e */
        memcpy(big + 10, key + off + elen, kl - off - elen);
        CHECK(elpis_rsa_verify(big, 10 + kl - off - elen, sig, sl, h, 32,
                               ELPIS_HASH_SHA256) == 0,
              "an RSA key with an exponent over 64 bits is refused");
        CHECK(elpis_rsa_verify(key, kl, sig, sl, h, 32, ELPIS_HASH_SHA256) == 1,
              "the same key with its own exponent still verifies");
    }
}

/* ================================================================== */
/*
 * The reason a bogus verdict is logged with.  A resolver in production logged
 * bursts of "bogus answer for x (alg ECDSAP256SHA256)" with nothing to say
 * which RRset had failed or why, so each signature is now described: the tag
 * it names, and whether that key is missing, may not sign, is out of date, or
 * simply failed the arithmetic.
 */
static void why_sig(elpis_rrset_buf_t *set, const elpis_name_t *signer,
                    uint16_t tag, int64_t incep, int64_t expire, uint8_t fill)
{
    uint8_t rd[18 + ELPIS_MAX_NAME + 64];
    size_t o = 0;

    elpis_put16(rd + o, set->type); o += 2;
    rd[o++] = ELPIS_ALG_ED25519;
    rd[o++] = (uint8_t)set->name.labels;
    elpis_put32(rd + o, 3600); o += 4;
    elpis_put32(rd + o, (uint32_t)expire); o += 4;
    elpis_put32(rd + o, (uint32_t)incep); o += 4;
    elpis_put16(rd + o, tag); o += 2;
    memcpy(rd + o, signer->d, signer->len); o += signer->len;
    memset(rd + o, fill, 64); o += 64;
    elpis_rrset_buf_add_sig(set, rd, (uint16_t)o);
}

static void test_rrset_why(void)
{
    static elpis_rrset_buf_t keys, set;
    elpis_conf_t c;
    elpis_name_t zone, other;
    uint8_t key[36], revoked[36], a[4] = { 192, 0, 2, 1 };
    char why[640], want[64];
    uint16_t tag, rtag;
    int64_t now = elpis_wall_s();

    section("why a signature failed");
    elpis_conf_defaults(&c);
    elpis_name_from_text(&zone, "why.test.");
    elpis_name_from_text(&other, "elsewhere.test.");

    keytrap_key(key, 0);
    tag = elpis_dnskey_tag(key, sizeof key);
    keytrap_key(revoked, 1);
    elpis_put16(revoked, 0x0101u | ELPIS_DNSKEY_REVOKE);
    rtag = elpis_dnskey_tag(revoked, sizeof revoked);
    elpis_rrset_buf_init(&keys, &zone, ELPIS_T_DNSKEY, ELPIS_CLASS_IN, 3600);
    elpis_rrset_buf_add(&keys, key, sizeof key);
    elpis_rrset_buf_add(&keys, revoked, sizeof revoked);

    elpis_rrset_buf_init(&set, &zone, ELPIS_T_A, ELPIS_CLASS_IN, 3600);
    elpis_rrset_buf_add(&set, a, sizeof a);
    elpis_rrset_why(&c, &set, &keys, now, why, sizeof why);
    CHECK(strstr(why, "why.test. A, 1 record, no signature") != NULL,
          "an unsigned set says so (%s)", why);

    why_sig(&set, &zone, tag, now - 3600, now + 3600, 0x41);
    why_sig(&set, &zone, (uint16_t)(tag + 1u), now - 3600, now + 3600, 0x42);
    why_sig(&set, &zone, tag, now - 7200, now - 3600, 0x43);
    why_sig(&set, &zone, tag, now + 3600, now + 7200, 0x44);
    elpis_rrset_why(&c, &set, &keys, now, why, sizeof why);

    snprintf(want, sizeof want, "RRSIG %u/ED25519 by why.test.: failed the "
             "signature check", tag);
    CHECK(strstr(why, want) != NULL, "a bad signature by a good key (%s)", why);
    snprintf(want, sizeof want, "RRSIG %u/ED25519 by why.test.: no key with "
             "that tag", (unsigned)(uint16_t)(tag + 1u));
    CHECK(strstr(why, want) != NULL, "a tag the key set lacks (%s)", why);
    CHECK(strstr(why, ": expired 3600 s ago") != NULL,
          "an expired signature, and by how much (%s)", why);
    CHECK(strstr(why, ": not valid for another 3600 s") != NULL,
          "a signature not yet valid (%s)", why);
    snprintf(want, sizeof want, "; keys why.test.: %u %u", tag, rtag);
    CHECK(strstr(why, want) != NULL, "and the tags the key set holds (%s)",
          why);

    elpis_rrset_buf_init(&set, &zone, ELPIS_T_A, ELPIS_CLASS_IN, 3600);
    elpis_rrset_buf_add(&set, a, sizeof a);
    why_sig(&set, &zone, rtag, now - 3600, now + 3600, 0x45);
    why_sig(&set, &other, tag, now - 3600, now + 3600, 0x46);
    elpis_rrset_why(&c, &set, &keys, now, why, sizeof why);
    CHECK(strstr(why, "the key is revoked") != NULL,
          "a revoked key may not sign (%s)", why);
    CHECK(strstr(why, "by elsewhere.test.: not the key set's zone") != NULL,
          "a signer that is not the keys' zone (%s)", why);

    (void)elpis_dnssec_take_verifies();
    elpis_rrset_why(&c, &set, &keys, now, why, sizeof why);
    CHECK(elpis_dnssec_take_verifies() == 0,
          "describing costs no signature check");

    elpis_rrset_why(&c, &set, &keys, now, why, 24);
    CHECK(strlen(why) == 23, "a short buffer is filled and terminated (%zu)",
          strlen(why));
}

/* ================================================================== */
/*
 * Keys and DS records that come with TTL 0.  The RRset cache keeps nothing
 * with TTL 0, and the validator used to read keys and DS from nowhere else.
 * So a chain through such a zone ended in SERVFAIL, EDE 9, every time, though
 * each fetch had worked: mldsa44.dnstest.dev serves its DNSKEY that way.
 * Here the validator's own lookups are answered with replies off the wire,
 * through the resolver's real path: a DS and a DNSKEY both at TTL 0, and a
 * denial of DS at TTL 0.  Each must settle, and none may be left cached.
 */

/* Sign `set` as an authority would: the RRSIG rdata, then the RRset in
 * canonical form, under Ed25519.  Every set here holds one record, so there
 * is no order to sort. */
static void ttl0_sign(elpis_rrset_buf_t *set, const elpis_name_t *signer,
                      const uint8_t sk[32], uint16_t tag)
{
    static uint8_t msg[2048];
    uint8_t rd[18 + ELPIS_MAX_NAME + 64];
    int64_t now = elpis_wall_s();
    size_t o = 0, m;
    unsigned i;

    elpis_put16(rd + o, set->type); o += 2;
    rd[o++] = ELPIS_ALG_ED25519;
    rd[o++] = (uint8_t)set->name.labels;
    elpis_put32(rd + o, set->ttl); o += 4;
    elpis_put32(rd + o, (uint32_t)(now + 86400)); o += 4;
    elpis_put32(rd + o, (uint32_t)(now - 86400)); o += 4;
    elpis_put16(rd + o, tag); o += 2;
    memcpy(rd + o, signer->d, signer->len); o += signer->len;

    memcpy(msg, rd, o);
    m = o;
    for (i = 0; i < set->count; i++) {
        memcpy(msg + m, set->name.d, set->name.len); m += set->name.len;
        elpis_put16(msg + m, set->type); m += 2;
        elpis_put16(msg + m, set->klass); m += 2;
        elpis_put32(msg + m, set->ttl); m += 4;
        elpis_put16(msg + m, set->len[i]); m += 2;
        memcpy(msg + m, set->data + set->off[i], set->len[i]);
        m += set->len[i];
    }
    elpis_ed25519_sign(sk, msg, m, rd + o);
    elpis_rrset_buf_add_sig(set, rd, (uint16_t)(o + 64));
}

/* A zone's DNSKEY set: one Ed25519 key, signing itself.  Returns its tag. */
static uint16_t ttl0_keys(elpis_rrset_buf_t *keys, const elpis_name_t *zone,
                          const uint8_t sk[32], uint32_t ttl)
{
    uint8_t rd[4 + 32];
    uint16_t tag;

    elpis_put16(rd, 257);
    rd[2] = 3;
    rd[3] = ELPIS_ALG_ED25519;
    elpis_ed25519_pubkey(sk, rd + 4);
    tag = elpis_dnskey_tag(rd, sizeof rd);
    elpis_rrset_buf_init(keys, zone, ELPIS_T_DNSKEY, ELPIS_CLASS_IN, ttl);
    elpis_rrset_buf_add(keys, rd, sizeof rd);
    ttl0_sign(keys, zone, sk, tag);
    return tag;
}

/* The SHA-256 DS rdata for the one key in `keys`. */
static void ttl0_ds(uint8_t dsr[4 + 32], const elpis_name_t *zone,
                    const elpis_rrset_buf_t *keys, uint16_t tag)
{
    uint8_t buf[ELPIS_MAX_NAME + 64];

    memcpy(buf, zone->d, zone->len);
    memcpy(buf + zone->len, keys->data + keys->off[0], keys->len[0]);
    elpis_put16(dsr, tag);
    dsr[2] = ELPIS_ALG_ED25519;
    dsr[3] = ELPIS_DS_SHA256;
    elpis_sha256(buf, zone->len + keys->len[0], dsr + 4);
}

/* An authoritative reply to (q, qtype): `sets` and their signatures in one
 * section, every record at its set's TTL. */
static size_t ttl0_reply(uint8_t *out, const elpis_name_t *q, uint16_t qtype,
                         elpis_section_t sec,
                         const elpis_rrset_buf_t *const *sets, unsigned nsets)
{
    size_t o = 12;
    unsigned i, j, n = 0;

    memset(out, 0, 12);
    elpis_put16(out, 0x5a5a);
    elpis_put16(out + 2, (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_AA));
    elpis_put16(out + 4, 1);
    memcpy(out + o, q->d, q->len); o += q->len;
    elpis_put16(out + o, qtype); o += 2;
    elpis_put16(out + o, ELPIS_CLASS_IN); o += 2;
    for (i = 0; i < nsets; i++) {
        const elpis_rrset_buf_t *s = sets[i];
        for (j = 0; j < (unsigned)s->count + s->sigcount; j++) {
            memcpy(out + o, s->name.d, s->name.len); o += s->name.len;
            elpis_put16(out + o, j < s->count ? s->type
                                              : (uint16_t)ELPIS_T_RRSIG);
            o += 2;
            elpis_put16(out + o, ELPIS_CLASS_IN); o += 2;
            elpis_put32(out + o, s->ttl); o += 4;
            elpis_put16(out + o, s->len[j]); o += 2;
            memcpy(out + o, s->data + s->off[j], s->len[j]);
            o += s->len[j];
            n++;
        }
    }
    elpis_put16(out + (sec == ELPIS_SEC_ANSWER ? 6 : 8), (uint16_t)n);
    return o;
}

/* Answer the lookup `p` is waiting on, if it is for (name, type). */
static int ttl0_feed(elpis_task_t *p, const char *name, uint16_t type,
                     const uint8_t *wire, size_t len)
{
    elpis_task_t *c = p != NULL ? p->children : NULL;
    elpis_name_t n;
    elpis_outq_t q;
    elpis_msg_t m;
    int drop = 0;

    elpis_name_from_text(&n, name);
    if (c == NULL || c->qtype != type || !elpis_name_eq(&c->qname, &n))
        return 0;
    if (elpis_msg_parse(&m, wire, len, ELPIS_PARSE_RESPONSE, &drop) != ELPIS_OK)
        return 0;
    memset(&q, 0, sizeof q);
    elpis_addr_parse(&q.server, "192.0.2.53", 53);
    elpis_resolver_on_response(c, &q, &m);
    return 1;
}

/* -2 for unverifiable, otherwise the verdict. */
static void ttl0_done(elpis_task_t *t, void *ctx)
{
    *(int *)ctx = t->val_unavailable ? -2 : (int)t->sec;
}

/* Start validating `ans`, served by `zone`, as a resolution with no client
 * would.  NULL once it has settled; otherwise it is waiting on a lookup. */
static elpis_task_t *ttl0_validate(elpis_worker_t *w,
                                   const elpis_rrset_buf_t *ans,
                                   const elpis_name_t *zone, int *verdict)
{
    elpis_task_t *t = elpis_task_new(w);
    unsigned i;

    *verdict = -1;
    if (t == NULL)
        return NULL;
    t->qname = t->orig_qname = ans->name;
    t->qtype = t->orig_qtype = ans->type;
    t->rcode = ELPIS_RC_NOERROR;
    t->state = ELPIS_TS_VALIDATE;
    t->done_cb  = ttl0_done;
    t->done_ctx = verdict;
    t->ans.zone_labels = ELPIS_ZONE_STAMP(zone);
    for (i = 0; i < (unsigned)ans->count + ans->sigcount; i++)
        elpis_rrlist_add(&t->ans, ELPIS_SEC_ANSWER, &ans->name,
                         i < ans->count ? ans->type : (uint16_t)ELPIS_T_RRSIG,
                         ELPIS_CLASS_IN, ans->ttl, ans->data + ans->off[i],
                         ans->len[i]);
    if (elpis_val_start(t) != 0)
        return t;
    t->state = ELPIS_TS_FINISH;
    elpis_task_step(t);
    return NULL;
}

static void test_ttl0_material(void)
{
    static elpis_rrset_buf_t top_keys, keys, ds, ans, soa, nsec, got;
    static uint8_t wire[4096];
    elpis_ctx_t *ctx = (elpis_ctx_t *)elpis_calloc(1, sizeof *ctx);
    elpis_worker_t *w = (elpis_worker_t *)elpis_calloc(1, sizeof *w);
    uint8_t sk_top[32], sk_low[32], dsr[4 + 32], rd[128];
    const elpis_rrset_buf_t *sets[2];
    elpis_name_t top, low, www, nods, wwwn, next;
    elpis_task_t *t1, *t2, *t3;
    char path[] = "/tmp/elpis-ta-XXXXXX";
    char hex[65];
    uint16_t top_tag, low_tag;
    uint32_t now = elpis_cached_now_s();
    int v1, v2, v3, fd;
    unsigned i;
    uint64_t n;
    size_t len, o;
    FILE *fp;

    section("validation material with TTL 0");
    CHECK(ctx != NULL && w != NULL, "set up");
    if (ctx == NULL || w == NULL)
        goto out;

    elpis_conf_defaults(&ctx->conf);
    ctx->conf.max_pending = 64;
    ctx->rcache = elpis_rcache_new(4u << 20, 2);
    ctx->dcache = elpis_dcache_new(1u << 20, 2);
    ctx->ta     = elpis_ta_new();
    w->ctx   = ctx;
    w->loop  = elpis_loop_new(16);      /* never run: lookups get no further
                                         * than their first timer */
    w->rrbuf = (elpis_rrset_buf_t *)elpis_malloc(sizeof *w->rrbuf);
    w->rd1   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->rd2   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->txbuf = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    CHECK(ctx->rcache != NULL && ctx->dcache != NULL && ctx->ta != NULL &&
          w->loop != NULL && w->rrbuf != NULL && w->rd1 != NULL &&
          w->rd2 != NULL && w->txbuf != NULL, "caches, loop and buffers");
    if (ctx->rcache == NULL || ctx->dcache == NULL || ctx->ta == NULL ||
        w->loop == NULL || w->rrbuf == NULL || w->rd1 == NULL ||
        w->rd2 == NULL || w->txbuf == NULL)
        goto out;

    for (i = 0; i < 32; i++) {
        sk_top[i] = (uint8_t)(0x10 + i);
        sk_low[i] = (uint8_t)(0x80 + i);
    }
    elpis_name_from_text(&top,  "test.");
    elpis_name_from_text(&low,  "ttl0.test.");
    elpis_name_from_text(&www,  "www.ttl0.test.");
    elpis_name_from_text(&nods, "nods.test.");
    elpis_name_from_text(&wwwn, "www.nods.test.");
    elpis_name_from_text(&next, "zz.test.");

    /* test. is the trust anchor; its keys are cached the ordinary way. */
    top_tag = ttl0_keys(&top_keys, &top, sk_top, 3600);
    ttl0_ds(dsr, &top, &top_keys, top_tag);
    for (i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", dsr[4 + i]);
    fd = mkstemp(path);
    CHECK(fd >= 0, "trust anchor file");
    if (fd < 0)
        goto out;
    fp = fdopen(fd, "w");
    fprintf(fp, "test. 3600 IN DS %u 15 2 %s\n", top_tag, hex);
    fclose(fp);
    CHECK(elpis_ta_load_file(ctx->ta, path) == ELPIS_OK, "the anchor loads");
    unlink(path);
    elpis_rcache_put_buf(ctx->rcache, &top_keys, 0, 0);

    /* ttl0.test.: its DS, its DNSKEY and its answer all at TTL 0, as the
     * ML-DSA-44 test zone publishes them. */
    low_tag = ttl0_keys(&keys, &low, sk_low, 0);
    ttl0_ds(dsr, &low, &keys, low_tag);
    elpis_rrset_buf_init(&ds, &low, ELPIS_T_DS, ELPIS_CLASS_IN, 0);
    elpis_rrset_buf_add(&ds, dsr, sizeof dsr);
    ttl0_sign(&ds, &top, sk_top, top_tag);
    elpis_rrset_buf_init(&ans, &www, ELPIS_T_A, ELPIS_CLASS_IN, 0);
    rd[0] = 192; rd[1] = 0; rd[2] = 2; rd[3] = 1;
    elpis_rrset_buf_add(&ans, rd, 4);
    ttl0_sign(&ans, &low, sk_low, low_tag);

    (void)elpis_dnssec_take_verifies();
    t1 = ttl0_validate(w, &ans, &low, &v1);
    t2 = ttl0_validate(w, &ans, &low, &v2);
    CHECK(t1 != NULL && t2 != NULL, "two validations wait for the DS");
    CHECK(t1 != NULL && t1->children != NULL && t2 != NULL &&
          t2->children == NULL, "on one lookup between them");

    sets[0] = &ds;
    len = ttl0_reply(wire, &low, ELPIS_T_DS, ELPIS_SEC_ANSWER, sets, 1);
    CHECK(ttl0_feed(t1, "ttl0.test.", ELPIS_T_DS, wire, len),
          "the DS lookup is answered, TTL 0");
    CHECK(v1 == -1 && v2 == -1, "and both go on to wait for the DNSKEY");

    sets[0] = &keys;
    len = ttl0_reply(wire, &low, ELPIS_T_DNSKEY, ELPIS_SEC_ANSWER, sets, 1);
    CHECK(ttl0_feed(t1, "ttl0.test.", ELPIS_T_DNSKEY, wire, len),
          "the DNSKEY lookup is answered, TTL 0, with the DS still needed");
    n = elpis_dnssec_take_verifies();
    CHECK(v1 == (int)ELPIS_SEC_SECURE && v2 == (int)ELPIS_SEC_SECURE,
          "both validations are secure, not EDE 9 (%d, %d)", v1, v2);
    /* The anchor's keys, the DS and the DNSKEY once between them, and each
     * answer once: a held set keeps its verdict like a cached one. */
    CHECK(n == 5, "every signature checked once (%llu)",
          (unsigned long long)n);

    CHECK(elpis_rcache_get(ctx->rcache, &low, ELPIS_T_DS, ELPIS_CLASS_IN,
                           now, 86400, &got) == ELPIS_ENOTFOUND &&
          elpis_rcache_get(ctx->rcache, &low, ELPIS_T_DNSKEY, ELPIS_CLASS_IN,
                           now, 86400, &got) == ELPIS_ENOTFOUND,
          "neither TTL-0 set is in the cache, stale or otherwise");
    t3 = ttl0_validate(w, &ans, &low, &v3);
    CHECK(t3 != NULL && t3->children != NULL &&
          t3->children->qtype == ELPIS_T_DS,
          "and the next validation fetches them again");
    elpis_task_free(t3);

    /*
     * nods.test. is an unsigned delegation, and test. says so in a denial of
     * its DS at TTL 0.  The validator reads that only as the cache's denial
     * marker, which was never built at TTL 0.
     */
    elpis_rrset_buf_init(&soa, &top, ELPIS_T_SOA, ELPIS_CLASS_IN, 0);
    {
        static const uint8_t mname[] = { 2,'n','s',4,'t','e','s','t',0 };
        static const uint8_t rname[] = { 5,'a','d','m','i','n',4,'t','e','s','t',0 };
        o = 0;
        memcpy(rd + o, mname, sizeof mname); o += sizeof mname;
        memcpy(rd + o, rname, sizeof rname); o += sizeof rname;
        elpis_put32(rd + o, 1); o += 4;
        elpis_put32(rd + o, 3600); o += 4;
        elpis_put32(rd + o, 600); o += 4;
        elpis_put32(rd + o, 1209600); o += 4;
        elpis_put32(rd + o, 0); o += 4;
        elpis_rrset_buf_add(&soa, rd, (uint16_t)o);
    }
    elpis_rrset_buf_init(&nsec, &nods, ELPIS_T_NSEC, ELPIS_CLASS_IN, 0);
    o = 0;
    memcpy(rd + o, next.d, next.len); o += next.len;
    rd[o++] = 0;                        /* window 0: NS, RRSIG, NSEC */
    rd[o++] = 6;
    memset(rd + o, 0, 6);
    rd[o] = 0x20;
    rd[o + 5] = 0x03;
    o += 6;
    elpis_rrset_buf_add(&nsec, rd, (uint16_t)o);
    ttl0_sign(&nsec, &top, sk_top, top_tag);
    elpis_rrset_buf_init(&ans, &wwwn, ELPIS_T_A, ELPIS_CLASS_IN, 0);
    rd[0] = 192; rd[1] = 0; rd[2] = 2; rd[3] = 2;
    elpis_rrset_buf_add(&ans, rd, 4);

    t1 = ttl0_validate(w, &ans, &nods, &v1);
    CHECK(t1 != NULL && t1->children != NULL &&
          t1->children->qtype == ELPIS_T_DS,
          "an unsigned answer waits on the DS of its zone");
    sets[0] = &soa;
    sets[1] = &nsec;
    len = ttl0_reply(wire, &nods, ELPIS_T_DS, ELPIS_SEC_AUTHORITY, sets, 2);
    CHECK(ttl0_feed(t1, "nods.test.", ELPIS_T_DS, wire, len),
          "which is denied, TTL 0");
    CHECK(v1 == (int)ELPIS_SEC_INSECURE,
          "the denial proves it unsigned, not unverifiable (%d)", v1);
    CHECK(elpis_rcache_get(ctx->rcache, &nods, ELPIS_T_DS, ELPIS_CLASS_IN,
                           now, 86400, &got) == ELPIS_ENOTFOUND,
          "and the denial is not cached either");

out:
    if (w != NULL) {
        if (w->loop != NULL) {
            elpis_resolver_fini(w);     /* the lookups left waiting */
            elpis_loop_free(w->loop);
        }
        elpis_free(w->rrbuf);
        elpis_free(w->rd1);
        elpis_free(w->rd2);
        elpis_free(w->txbuf);
    }
    if (ctx != NULL) {
        elpis_cache_free(ctx->rcache);
        elpis_cache_free(ctx->dcache);
        elpis_ta_free(ctx->ta);
    }
    elpis_free(ctx);
    elpis_free(w);
}

/* ================================================================== */
/*
 * A denial whose proof does not fit the client's UDP size.  To a client that
 * set DO the authority section is the proof, so the reply is truncated -- TC,
 * nothing in it -- rather than sent with AD and no proof.  The message cache
 * already did this; a reply built fresh dropped the proof and said nothing,
 * so nosuchname.mldsa44.dnstest.dev, never cached at TTL 0, always lost it.
 * Here the two paths are held to the same answer.
 */
static void test_reply_fit(void)
{
    static uint8_t full[ELPIS_MAX_MSG];
    /* Wire names; the literal's own terminator is the root label. */
    static const uint8_t qn[] = "\6nosuch\3big\4test";
    static const uint8_t zone[] = "\3big\4test";
    elpis_ctx_t *ctx = (elpis_ctx_t *)elpis_calloc(1, sizeof *ctx);
    elpis_worker_t *w = (elpis_worker_t *)elpis_calloc(1, sizeof *w);
    elpis_cache_t *mc = elpis_mcache_new(4u << 20, 2);
    elpis_task_t *t = NULL;
    elpis_name_t owner, q;
    elpis_mkey_t k;
    elpis_mserve_t info;
    elpis_msg_t m;
    int drop = 0;
    uint8_t rd[700], out[1500];
    uint32_t toff[1] = { 0 }, tval[1] = { 0 };
    size_t len, fulllen, outlen = 0, qend = 12 + sizeof qn + 4;
    unsigned i, sigsize;

    section("a proof that does not fit");
    CHECK(ctx != NULL && w != NULL && mc != NULL, "set up");
    if (ctx == NULL || w == NULL || mc == NULL)
        goto out;
    elpis_conf_defaults(&ctx->conf);
    ctx->conf.max_pending = 8;
    w->ctx   = ctx;
    w->txbuf = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->ctab  = (elpis_cslot_t *)elpis_calloc(ELPIS_BLD_CTAB, sizeof(elpis_cslot_t));
    if (w->txbuf == NULL || w->ctab == NULL)
        goto out;

    elpis_name_from_text(&q, "nosuch.big.test.");
    elpis_name_from_text(&owner, "big.test.");
    for (sigsize = 16; sigsize <= 600; sigsize += 584) {
        if (t != NULL)
            elpis_task_free(t);
        t = elpis_task_new(w);
        if (t == NULL)
            goto out;
        memcpy(t->client_qname, qn, sizeof qn);
        t->client_qnamelen = (uint8_t)sizeof qn;
        t->client_id = 0x1234;
        t->orig_qname = q;
        t->orig_qtype = ELPIS_T_A;
        t->rcode = ELPIS_RC_NXDOMAIN;
        t->sec = ELPIS_SEC_SECURE;
        t->client_edns = 1;
        t->client_bufsize = 1232;
        t->client_do = 1;

        /* An SOA, an NSEC and a signature over each.  Only the size of the
         * signatures matters here: 2 x 16 bytes fit, 2 x 600 do not. */
        memset(rd, 0, sizeof rd);
        memcpy(rd, zone, sizeof zone);
        memcpy(rd + sizeof zone, zone, sizeof zone);
        elpis_rrlist_add(&t->ans, ELPIS_SEC_AUTHORITY, &owner, ELPIS_T_SOA,
                         ELPIS_CLASS_IN, 0, rd, (uint16_t)(2 * sizeof zone + 20));
        rd[sizeof zone] = 0;            /* NSEC bitmap: window 0, 1 octet */
        rd[sizeof zone + 1] = 1;
        rd[sizeof zone + 2] = 0x40;     /* A */
        elpis_rrlist_add(&t->ans, ELPIS_SEC_AUTHORITY, &owner, ELPIS_T_NSEC,
                         ELPIS_CLASS_IN, 0, rd, (uint16_t)(sizeof zone + 3));
        for (i = 0; i < 2; i++) {
            memset(rd, 0, sizeof rd);
            elpis_put16(rd, i == 0 ? ELPIS_T_SOA : ELPIS_T_NSEC);
            rd[2] = ELPIS_ALG_ED25519;
            memcpy(rd + 18, zone, sizeof zone);
            elpis_rrlist_add(&t->ans, ELPIS_SEC_AUTHORITY, &owner, ELPIS_T_RRSIG,
                             ELPIS_CLASS_IN, 0, rd, (uint16_t)(18 + sizeof zone + sigsize));
        }

        len = elpis_task_build_reply(t);
        if (sigsize == 16) {
            CHECK(len > 0 && !(elpis_get16(w->txbuf + 2) & ELPIS_FLAG_TC) &&
                  elpis_get16(w->txbuf + 8) == 4,
                  "a proof that fits goes out whole (%zu bytes)", len);
        }
    }
    if (t == NULL)
        goto out;

    CHECK(len > 0 && len <= 1232, "over UDP the reply fits (%zu bytes)", len);
    CHECK((elpis_get16(w->txbuf + 2) & ELPIS_FLAG_TC) != 0,
          "and is truncated, to a client that set DO");
    CHECK(elpis_get16(w->txbuf + 6) == 0 && elpis_get16(w->txbuf + 8) == 0,
          "with nothing in it, not AD and no proof");
    CHECK((elpis_get16(w->txbuf + 2) & ELPIS_RCODE_MASK) == ELPIS_RC_NXDOMAIN &&
          elpis_get16(w->txbuf + 10) == 1, "still NXDOMAIN, with its OPT");
    CHECK(elpis_msg_parse(&m, w->txbuf, len, ELPIS_PARSE_RESPONSE, &drop) ==
              ELPIS_OK && m.qtype == ELPIS_T_A && m.have_opt && m.do_bit,
          "and a well-formed reply to the question asked");

    t->from_tcp = 1;
    len = elpis_task_build_reply(t);
    CHECK(!(elpis_get16(w->txbuf + 2) & ELPIS_FLAG_TC) &&
          elpis_get16(w->txbuf + 8) == 4 &&
          elpis_msg_parse(&m, w->txbuf, len, ELPIS_PARSE_RESPONSE, &drop) ==
              ELPIS_OK,
          "over TCP the whole proof goes (%zu bytes)", len);

    /* The same reply, whole and without OPT, as the message cache keeps it. */
    t->client_edns = 0;
    fulllen = elpis_task_build_reply(t);
    memcpy(full, w->txbuf, fulllen);
    memset(&k, 0, sizeof k);
    k.qname = qn; k.qnamelen = sizeof qn; k.qtype = ELPIS_T_A;
    k.qclass = ELPIS_CLASS_IN;
    k.kflags = ELPIS_MK_DO;
    elpis_mkey_hash(&k);
    CHECK(elpis_mcache_store(mc, &k, full, fulllen, qend, toff, tval, 0,
                             qend, fulllen, ELPIS_RC_NXDOMAIN, ELPIS_FLAG_AD,
                             ELPIS_SEC_SECURE, 300, 0, 0, 0) == ELPIS_OK,
          "the reply is cached");
    CHECK(elpis_mcache_serve(mc, &k, 0x1234, qn, ELPIS_FLAG_QR, 1232 - 48, 0,
                             30, 0, out, sizeof out, &outlen, &info) == ELPIS_OK &&
          info.truncated && (elpis_get16(out + 2) & ELPIS_FLAG_TC) &&
          elpis_get16(out + 8) == 0,
          "and from the cache it is truncated the same way");

    /* Without DO there is no proof to lose: the SOA alone would do, and the
     * section is dropped as before, on both paths. */
    t->client_do = 0;
    t->client_edns = 1;
    t->from_tcp = 0;
    len = elpis_task_build_reply(t);
    CHECK(!(elpis_get16(w->txbuf + 2) & ELPIS_FLAG_TC) &&
          elpis_get16(w->txbuf + 8) == 0,
          "a client without DO gets it without the section, untruncated");
    k.kflags = 0;
    elpis_mkey_hash(&k);
    elpis_mcache_store(mc, &k, full, fulllen, qend, toff, tval, 0, qend,
                       fulllen, ELPIS_RC_NXDOMAIN, ELPIS_FLAG_AD,
                       ELPIS_SEC_SECURE, 300, 0, 0, 0);
    CHECK(elpis_mcache_serve(mc, &k, 0x1234, qn, ELPIS_FLAG_QR, 1232 - 48, 0,
                             30, 0, out, sizeof out, &outlen, &info) == ELPIS_OK &&
          !info.truncated && info.dropped_ns,
          "as the cache does");

out:
    if (t != NULL)
        elpis_task_free(t);
    if (w != NULL) {
        elpis_free(w->txbuf);
        elpis_free(w->ctab);
    }
    elpis_cache_free(mc);
    elpis_free(ctx);
    elpis_free(w);
}

/* ================================================================== */
/*
 * RFC 8509 root key sentinels: how anyone outside can tell which root keys a
 * resolver trusts, and so whether it will survive the KSK-2024 rollover on
 * 2026-10-11.  Without them dnstest.dev's check could not tell, though both
 * root keys are compiled in.
 */
static void ttl0_done_rcode(elpis_task_t *t, void *ctx)
{
    int *r = (int *)ctx;
    r[0] = (int)t->rcode;
    r[1] = (int)t->sec;
    r[2] = (int)t->ans.n;
}

static void test_root_sentinel(void)
{
    static const struct { const char *name; int want; } cases[] = {
        { "root-key-sentinel-is-ta-20326.example.",  1 },
        { "root-key-sentinel-is-ta-38696.example.",  1 },
        { "root-key-sentinel-not-ta-20326.example.", -1 },
        { "root-key-sentinel-not-ta-38696.example.", -1 },
        { "root-key-sentinel-is-ta-12345.example.",  -1 },
        { "root-key-sentinel-not-ta-12345.example.", 1 },
        { "Root-Key-Sentinel-IS-TA-38696.example.",  1 },
        { "root-key-sentinel-is-ta-99999.example.",  -1 },
        /* Not sentinels: five digits exactly, and the leftmost label only. */
        { "root-key-sentinel-is-ta-2032.example.",   0 },
        { "root-key-sentinel-is-ta-203260.example.", 0 },
        { "root-key-sentinel-is-ta-2032x.example.",  0 },
        { "root-key-sentinel-is-ta.example.",        0 },
        { "x.root-key-sentinel-not-ta-20326.example.", 0 },
        { "www.example.", 0 },
    };
    static elpis_rrset_buf_t keys, ans;
    elpis_ta_store_t *ta = elpis_ta_new(), *none = elpis_ta_new();
    elpis_ctx_t *ctx = (elpis_ctx_t *)elpis_calloc(1, sizeof *ctx);
    elpis_worker_t *w = (elpis_worker_t *)elpis_calloc(1, sizeof *w);
    char path[] = "/tmp/elpis-ta-XXXXXX";
    char hex[65];
    uint8_t sk[32], dsr[4 + 32], rd[4] = { 192, 0, 2, 7 };
    elpis_name_t n, top;
    uint16_t tag;
    unsigned i, ok = 0;
    int r[3], fd;
    FILE *fp;

    section("root key sentinels (RFC 8509)");
    CHECK(ta != NULL && none != NULL && ctx != NULL && w != NULL, "set up");
    if (ta == NULL || none == NULL || ctx == NULL || w == NULL)
        goto out;
    elpis_ta_add_builtin(ta);
    for (i = 0; i < ELPIS_ARRAY_LEN(cases); i++) {
        int got;
        elpis_name_from_text(&n, cases[i].name);
        got = elpis_root_sentinel(ta, &n);
        if (got == cases[i].want)
            ok++;
        else
            printf("  %s: %d, want %d\n", cases[i].name, got, cases[i].want);
    }
    CHECK(ok == ELPIS_ARRAY_LEN(cases),
          "both root keys trusted, others not, and only exact labels (%u of %u)",
          ok, (unsigned)ELPIS_ARRAY_LEN(cases));
    elpis_name_from_text(&n, "root-key-sentinel-is-ta-38696.example.");
    CHECK(elpis_root_sentinel(none, &n) == -1,
          "with no root anchor at all, is-ta fails");
    elpis_name_from_text(&n, "root-key-sentinel-not-ta-38696.example.");
    CHECK(elpis_root_sentinel(none, &n) == 1, "and not-ta passes");

    /*
     * Through the validator: a signed answer under test., an anchor of its
     * own, with the root's built-in anchors beside it for the sentinel.
     */
    elpis_conf_defaults(&ctx->conf);
    ctx->conf.max_pending = 16;
    ctx->rcache = elpis_rcache_new(4u << 20, 2);
    ctx->dcache = elpis_dcache_new(1u << 20, 2);
    ctx->ta     = elpis_ta_new();
    w->ctx   = ctx;
    w->loop  = elpis_loop_new(16);
    w->rrbuf = (elpis_rrset_buf_t *)elpis_malloc(sizeof *w->rrbuf);
    w->rd1   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->rd2   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    if (ctx->rcache == NULL || ctx->dcache == NULL || ctx->ta == NULL ||
        w->loop == NULL || w->rrbuf == NULL || w->rd1 == NULL ||
        w->rd2 == NULL)
        goto out;
    elpis_ta_add_builtin(ctx->ta);
    for (i = 0; i < 32; i++)
        sk[i] = (uint8_t)(0x20 + i);
    elpis_name_from_text(&top, "test.");
    tag = ttl0_keys(&keys, &top, sk, 3600);
    ttl0_ds(dsr, &top, &keys, tag);
    for (i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", dsr[4 + i]);
    fd = mkstemp(path);
    if (fd < 0)
        goto out;
    fp = fdopen(fd, "w");
    fprintf(fp, "test. 3600 IN DS %u 15 2 %s\n", tag, hex);
    fclose(fp);
    elpis_ta_load_file(ctx->ta, path);
    unlink(path);
    elpis_rcache_put_buf(ctx->rcache, &keys, 0, 0);

    for (i = 0; i < 5; i++) {
        static const char *const qn[] = {
            "root-key-sentinel-not-ta-20326.test.",
            "root-key-sentinel-is-ta-38696.test.",
            "root-key-sentinel-is-ta-12345.test.",
            "root-key-sentinel-not-ta-20326.test.",
            "root-key-sentinel-not-ta-20326.test.",
        };
        static const char *const what[] = {
            "not-ta-20326 for a trusted key is an empty SERVFAIL, no AD",
            "is-ta-38696 is the signed answer: KSK-2024 is trusted",
            "is-ta for a key not trusted is SERVFAIL",
            "with CD set the answer goes out untouched",
            "and a TXT question is no sentinel",
        };
        elpis_task_t *t = elpis_task_new(w);
        unsigned j;

        if (t == NULL)
            break;
        elpis_name_from_text(&n, qn[i]);
        elpis_rrset_buf_init(&ans, &n, i == 4 ? ELPIS_T_TXT : ELPIS_T_A,
                             ELPIS_CLASS_IN, 300);
        elpis_rrset_buf_add(&ans, rd, sizeof rd);
        ttl0_sign(&ans, &top, sk, tag);
        t->qname = t->orig_qname = n;
        t->qtype = t->orig_qtype = ans.type;
        t->rcode = ELPIS_RC_NOERROR;
        t->state = ELPIS_TS_VALIDATE;
        t->client_cd = i == 3;
        t->done_cb  = ttl0_done_rcode;
        t->done_ctx = r;
        t->ans.zone_labels = ELPIS_ZONE_STAMP(&top);
        for (j = 0; j < (unsigned)ans.count + ans.sigcount; j++)
            elpis_rrlist_add(&t->ans, ELPIS_SEC_ANSWER, &n,
                             j < ans.count ? ans.type : (uint16_t)ELPIS_T_RRSIG,
                             ELPIS_CLASS_IN, 300, ans.data + ans.off[j],
                             ans.len[j]);
        r[0] = r[1] = r[2] = -1;
        if (elpis_val_start(t) != 0) {
            CHECK(0, "%s: the validator should need nothing fetched", qn[i]);
            elpis_task_free(t);
            continue;
        }
        t->state = ELPIS_TS_FINISH;
        elpis_task_step(t);
        if (i == 0 || i == 2)
            CHECK(r[0] == ELPIS_RC_SERVFAIL && r[2] == 0 &&
                  r[1] != (int)ELPIS_SEC_SECURE, "%s (rcode %d, %d records)",
                  what[i], r[0], r[2]);
        else
            CHECK(r[0] == ELPIS_RC_NOERROR && r[2] == 2 &&
                  (i == 3 || r[1] == (int)ELPIS_SEC_SECURE),
                  "%s (rcode %d, sec %d)", what[i], r[0], r[1]);
    }

out:
    if (w != NULL) {
        if (w->loop != NULL) {
            elpis_resolver_fini(w);
            elpis_loop_free(w->loop);
        }
        elpis_free(w->rrbuf);
        elpis_free(w->rd1);
        elpis_free(w->rd2);
    }
    if (ctx != NULL) {
        elpis_cache_free(ctx->rcache);
        elpis_cache_free(ctx->dcache);
        elpis_ta_free(ctx->ta);
    }
    elpis_ta_free(ta);
    elpis_ta_free(none);
    elpis_free(ctx);
    elpis_free(w);
}

/* ================================================================== */
static void test_quirks(void)
{
    elpis_conf_t c;
    elpis_name_t n;
    char line[256], fb[64];

    section("quirks");
    elpis_conf_defaults(&c);

    elpis_name_from_text(&n, "cimb.com.my.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) & ELPIS_QUIRK_DROPS_SVCB,
          "cimb.com.my drops HTTPS and SVCB (built in)");
    elpis_name_from_text(&n, "WWW.Cimb.COM.my.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) & ELPIS_QUIRK_DROPS_SVCB,
          "and so does a zone below it, whatever the case");
    elpis_name_from_text(&n, "notcimb.com.my.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) == 0,
          "a name that only ends in the same letters does not");
    elpis_name_from_text(&n, "com.my.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) == 0, "nor does the parent");
    elpis_name_from_text(&n, "www.kemenkeu.go.id.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) == ELPIS_QUIRK_SELFREF_NODATA,
          "www.kemenkeu.go.id refers other types back to itself");

    elpis_strlcpy(line, "quirk: example.net drops-svcb, empty-nodata", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK && c.nquirk == 1,
          "a quirk: line parses");
    elpis_name_from_text(&n, "a.example.net.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) ==
              (ELPIS_QUIRK_DROPS_SVCB | ELPIS_QUIRK_EMPTY_NODATA),
          "and covers the zone's children with both flags");
    elpis_quirk_flags_str(c.quirk[0].flags, fb, sizeof fb);
    CHECK(strcmp(fb, "drops-svcb empty-nodata") == 0, "and prints back (%s)", fb);

    elpis_strlcpy(line, "quirk: com.my none", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK, "none parses");
    elpis_name_from_text(&n, "cimb.com.my.");
    CHECK(elpis_quirks_for(c.quirk, c.nquirk, &n) & ELPIS_QUIRK_DROPS_SVCB,
          "a parent's none does not cancel a deeper built-in");
    elpis_strlcpy(line, "quirk: cimb.com.my none", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
          elpis_quirks_for(c.quirk, c.nquirk, &n) == 0,
          "the zone's own none does");

    elpis_strlcpy(line, "quirk: example.org drops-everything", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) != ELPIS_OK,
          "an unknown flag is an error");
    elpis_strlcpy(line, "quirk: example.org", sizeof line);
    CHECK(elpis_conf_parse_line(&c, line, "-", 1) != ELPIS_OK,
          "a zone with no flag is an error");
}

/* ================================================================== */
/* The special names answered before anything is cached or resolved. */
static int local_answer(elpis_worker_t *w, const char *name, uint16_t qtype,
                        unsigned *rcode, unsigned *ancount)
{
    uint8_t q[512];
    size_t ql = 12, outlen = 0;
    elpis_name_t n;
    elpis_msg_t m;
    int drop = 0, hit;

    memset(q, 0, 12);
    q[2] = 0x01;                        /* RD */
    q[5] = 1;
    elpis_name_from_text(&n, name);
    memcpy(q + ql, n.d, n.len); ql += n.len;
    elpis_put16(q + ql, qtype); ql += 2;
    elpis_put16(q + ql, ELPIS_CLASS_IN); ql += 2;
    if (elpis_msg_parse(&m, q, ql, ELPIS_PARSE_QUERY, &drop) != ELPIS_OK)
        return -1;
    hit = elpis_localzone_static(w, &m, w->txbuf, ELPIS_MAX_MSG, &outlen);
    if (hit && outlen >= 12) {
        *rcode   = elpis_get16(w->txbuf + 2) & 0x0Fu;
        *ancount = elpis_get16(w->txbuf + 6);
    }
    return hit;
}

static void test_localzone(void)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)elpis_calloc(1, sizeof *ctx);
    elpis_worker_t *w = (elpis_worker_t *)elpis_calloc(1, sizeof *w);
    unsigned rc = 99, an = 99;

    section("local names");
    if (ctx == NULL || w == NULL) {
        CHECK(0, "set up");
        elpis_free(ctx);
        elpis_free(w);
        return;
    }
    elpis_conf_defaults(&ctx->conf);
    w->ctx   = ctx;
    w->txbuf = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->ctab  = (elpis_cslot_t *)elpis_calloc(ELPIS_BLD_CTAB, sizeof(elpis_cslot_t));

    CHECK(local_answer(w, "localhost.", ELPIS_T_A, &rc, &an) == 1 &&
          rc == ELPIS_RC_NOERROR && an == 1, "localhost has an address");
    CHECK(local_answer(w, "a.b.LocalHost.", ELPIS_T_AAAA, &rc, &an) == 1 &&
          rc == ELPIS_RC_NOERROR && an == 1, "and so does a name under it");
    CHECK(local_answer(w, "10.1.168.192.in-addr.arpa.", ELPIS_T_PTR, &rc, &an) == 1 &&
          rc == ELPIS_RC_NXDOMAIN, "private reverse space is NXDOMAIN");
    CHECK(local_answer(w, "8.8.8.8.in-addr.arpa.", ELPIS_T_PTR, &rc, &an) == 0,
          "public reverse space is resolved");
    CHECK(local_answer(w, "x.Onion.", ELPIS_T_A, &rc, &an) == 1 &&
          rc == ELPIS_RC_NXDOMAIN, ".onion is NXDOMAIN");
    CHECK(local_answer(w, "localhost.arpa.", ELPIS_T_A, &rc, &an) == 1 &&
          rc == ELPIS_RC_NXDOMAIN, "localhost.arpa is NXDOMAIN");
    CHECK(local_answer(w, "www.example.com.", ELPIS_T_A, &rc, &an) == 0,
          "an ordinary name is not answered locally");
    CHECK(local_answer(w, "arpa.", ELPIS_T_SOA, &rc, &an) == 0,
          "nor is arpa itself");
    CHECK(local_answer(w, ELPIS_IDENTITY_NAME_DEFAULT ".", ELPIS_T_TXT, &rc, &an) == 1 &&
          rc == ELPIS_RC_NOERROR && an == 1, "the identity probe answers");
    CHECK(local_answer(w, "ELPIS.Sakurako.OOMURO", ELPIS_T_TXT, &rc, &an) == 1 &&
          an == 1, "in any case");
    CHECK(local_answer(w, "x." ELPIS_IDENTITY_NAME_DEFAULT ".", ELPIS_T_TXT,
                       &rc, &an) == 0, "but not below itself");
    CHECK(local_answer(w, "sakurako.oomuro.", ELPIS_T_TXT, &rc, &an) == 0,
          "nor above");

    elpis_free(w->txbuf);
    elpis_free(w->ctab);
    elpis_free(ctx);
    elpis_free(w);
}

/* ================================================================== */
/*
 * EDNS Client Subnet (RFC 7871): the option on the wire, the subnets that are
 * worth sending, the configuration, and the message cache keeping a tailored
 * answer to the subnet it was made for.
 */
/* A query whose OPT rdata is `rdata` verbatim: any number of options. */
static void ecs_query_raw(uint8_t *buf, size_t cap, const uint8_t *rdata,
                          size_t rdlen, size_t *len)
{
    elpis_bld_t b;
    elpis_name_t qn, root;
    size_t rdpos;

    elpis_name_from_text(&qn, "www.example.com.");
    elpis_name_init_root(&root);
    elpis_bld_init(&b, buf, cap, NULL, 0);
    elpis_bld_header(&b, 0, ELPIS_FLAG_RD);
    elpis_bld_question(&b, &qn, ELPIS_T_A, ELPIS_CLASS_IN);
    elpis_bld_rr_begin(&b, &root, ELPIS_T_OPT, 4096, 0, &rdpos);
    elpis_bld_bytes(&b, rdata, rdlen);
    elpis_bld_rr_end(&b, rdpos);
    elpis_bld_count(&b, ELPIS_SEC_ADDITIONAL, 1);
    elpis_bld_finish(&b);
    *len = b.len;
}

static uint8_t ecs_query(uint8_t *buf, size_t cap, const uint8_t *opt,
                         size_t optlen, size_t *len)
{
    elpis_bld_t b;
    elpis_name_t qn, root;
    size_t rdpos;

    elpis_name_from_text(&qn, "www.example.com.");
    elpis_name_init_root(&root);
    elpis_bld_init(&b, buf, cap, NULL, 0);
    elpis_bld_header(&b, 7, ELPIS_FLAG_RD);
    elpis_bld_question(&b, &qn, ELPIS_T_A, ELPIS_CLASS_IN);
    elpis_bld_rr_begin(&b, &root, ELPIS_T_OPT, 1232, 0, &rdpos);
    elpis_bld_u16(&b, ELPIS_OPT_ECS);
    elpis_bld_u16(&b, (uint16_t)optlen);
    elpis_bld_bytes(&b, opt, optlen);
    elpis_bld_rr_end(&b, rdpos);
    elpis_bld_count(&b, ELPIS_SEC_ADDITIONAL, 1);
    elpis_bld_finish(&b);
    *len = b.len;
    return 1;
}

static void test_ecs(void)
{
    elpis_ecs_t e, t;
    elpis_addr_t a;
    uint8_t wire[64];
    char sb[64];

    section("edns client subnet");

    {   /* 198.51.100.0/24, scope 0 */
        static const uint8_t opt[] = { 0, 1, 24, 0, 198, 51, 100 };
        CHECK(elpis_ecs_parse(&e, opt, sizeof opt) == ELPIS_OK &&
              e.family == ELPIS_ECS_IPV4 && e.source == 24 && e.scope == 0 &&
              e.addr[0] == 198 && e.addr[2] == 100 && e.addr[3] == 0,
              "an IPv4 /24 parses");
        CHECK(elpis_ecs_encode(&e, wire, sizeof wire) == sizeof opt &&
              memcmp(wire, opt, sizeof opt) == 0, "and encodes back the same");
        CHECK(strcmp(elpis_ecs_str(&e, sb, sizeof sb), "198.51.100.0/24") == 0,
              "and prints as a prefix (%s)", sb);
    }
    {
        static const uint8_t extra[] = { 0, 1, 24, 0, 198, 51, 100, 0 };
        static const uint8_t trail[] = { 0, 1, 20, 0, 198, 51, 101 };
        static const uint8_t fam[]   = { 0, 3, 8, 0, 10 };
        static const uint8_t wide[]  = { 0, 1, 33, 0, 1, 2, 3, 4, 5 };
        static const uint8_t zero[]  = { 0, 0, 0, 0 };
        static const uint8_t v6[]    = { 0, 2, 56, 0, 0x24, 0x02, 0x4e, 0x20,
                                         0x0b, 0x00, 0xb0 };
        CHECK(elpis_ecs_parse(&e, extra, sizeof extra) == ELPIS_EFORMAT,
              "more address octets than the prefix needs are refused");
        CHECK(elpis_ecs_parse(&e, trail, sizeof trail) == ELPIS_EFORMAT,
              "bits set past the prefix are refused");
        CHECK(elpis_ecs_parse(&e, fam, sizeof fam) == ELPIS_EFORMAT,
              "an unknown family is refused");
        CHECK(elpis_ecs_parse(&e, wide, sizeof wide) == ELPIS_EFORMAT,
              "a prefix longer than the family is refused");
        CHECK(elpis_ecs_parse(&e, zero, sizeof zero) == ELPIS_OK &&
              e.family == 0 && e.source == 0, "family 0 /0 means no subnet");
        CHECK(elpis_ecs_parse(&e, v6, sizeof v6) == ELPIS_OK &&
              e.family == ELPIS_ECS_IPV6 && e.source == 56, "an IPv6 /56 parses");
    }

    /* From a client address, cut to the configured prefix. */
    elpis_addr_parse(&a, "203.0.113.77", 53);
    CHECK(elpis_ecs_from_addr(&e, &a, 24, 56) && e.family == ELPIS_ECS_IPV4 &&
          e.source == 24 && e.addr[2] == 113 && e.addr[3] == 0,
          "an IPv4 client is cut to /24");
    elpis_addr_parse(&a, "::ffff:198.51.100.9", 53);
    CHECK(elpis_ecs_from_addr(&e, &a, 24, 56) && e.family == ELPIS_ECS_IPV4 &&
          e.addr[0] == 198 && e.addr[3] == 0,
          "an IPv4-mapped client counts as IPv4");
    elpis_addr_parse(&a, "2402:4e20:b00b:1234:5678::1", 53);
    CHECK(elpis_ecs_from_addr(&e, &a, 24, 56) && e.family == ELPIS_ECS_IPV6 &&
          e.source == 56 && e.addr[6] == 0x12 && e.addr[7] == 0 &&
          e.addr[8] == 0, "an IPv6 client is cut to /56");
    elpis_ecs_truncate(&t, &e, 24, 48);
    CHECK(t.source == 48 && t.addr[6] == 0 && t.addr[5] == 0x0b,
          "a client's own option is cut to our prefix");
    elpis_ecs_truncate(&t, &e, 24, 64);
    CHECK(t.source == 56, "but never lengthened");

    /* Only subnets that say where a client is are worth sending. */
    {
        static const char *const private_[] = {
            "10.1.2.3", "192.168.1.9", "172.20.0.1", "100.64.3.4", "127.0.0.1",
            "169.254.1.1", "192.0.2.1", "::1", "fd00::1", "fe80::1",
            "2001:db8::1",
        };
        static const char *const public_[] = {
            "151.158.198.49", "8.8.8.8", "2402:4e20:b00b::1", "2001:4860::1",
        };
        unsigned i;
        int ok = 1;
        for (i = 0; i < ELPIS_ARRAY_LEN(private_); i++) {
            elpis_addr_parse(&a, private_[i], 53);
            elpis_ecs_from_addr(&e, &a, 32, 128);
            elpis_ecs_from_addr(&t, &a, 24, 56);
            if (elpis_ecs_is_public(&e) || elpis_ecs_is_public(&t)) {
                printf("  %s counted as public\n", private_[i]);
                ok = 0;
            }
        }
        CHECK(ok, "private, loopback and documentation ranges are not sent");
        ok = 1;
        for (i = 0; i < ELPIS_ARRAY_LEN(public_); i++) {
            elpis_addr_parse(&a, public_[i], 53);
            elpis_ecs_from_addr(&e, &a, 24, 56);
            if (!elpis_ecs_is_public(&e)) {
                printf("  %s counted as private\n", public_[i]);
                ok = 0;
            }
        }
        CHECK(ok, "public addresses are");
        elpis_addr_parse(&a, "8.8.8.8", 53);
        elpis_ecs_from_addr(&e, &a, 0, 0);
        CHECK(!elpis_ecs_is_public(&e), "and a /0 says nothing");
    }

    /* In a message: parsed, kept, and a malformed one flagged, not dropped. */
    {
        static const uint8_t good[] = { 0, 1, 24, 0, 198, 51, 100 };
        static const uint8_t bad[]  = { 0, 1, 20, 0, 198, 51, 101 };
        uint8_t buf[512];
        size_t len;
        elpis_msg_t m;
        int drop = 0;

        ecs_query(buf, sizeof buf, good, sizeof good, &len);
        CHECK(elpis_msg_parse(&m, buf, len, ELPIS_PARSE_QUERY, &drop) == ELPIS_OK &&
              m.have_ecs && !m.ecs_bad && m.ecs.source == 24,
              "a query's ECS option is read");
        ecs_query(buf, sizeof buf, bad, sizeof bad, &len);
        CHECK(elpis_msg_parse(&m, buf, len, ELPIS_PARSE_QUERY, &drop) == ELPIS_OK &&
              m.have_ecs && m.ecs_bad,
              "a malformed one is flagged for the server to refuse");
    }
    /*
     * Two of them, as AdGuard Home sends: it appends the client's /24 to the
     * 0.0.0.0/0 Firefox puts on every DoH query.  That was refused FORMERR,
     * and Firefox in TRR-only mode could resolve nothing through it.
     */
    {
        static const uint8_t two[] = { 0, 8, 0, 4, 0, 1, 0, 0,
                                       0, 8, 0, 7, 0, 1, 24, 0, 175, 139, 1 };
        static const uint8_t onebad[] = { 0, 8, 0, 4, 0, 1, 0, 0,
                                          0, 8, 0, 7, 0, 1, 20, 0, 175, 139, 255 };
        uint8_t buf[512];
        size_t len;
        elpis_msg_t m;
        int drop = 0;

        ecs_query_raw(buf, sizeof buf, two, sizeof two, &len);
        CHECK(elpis_msg_parse(&m, buf, len, ELPIS_PARSE_QUERY, &drop) == ELPIS_OK &&
              m.have_ecs && !m.ecs_bad && m.ecs.family == ELPIS_ECS_IPV4 &&
              m.ecs.source == 24 && m.ecs.addr[0] == 175,
              "a forwarder's subnet after the client's /0 is taken, not refused");
        ecs_query_raw(buf, sizeof buf, onebad, sizeof onebad, &len);
        CHECK(elpis_msg_parse(&m, buf, len, ELPIS_PARSE_QUERY, &drop) == ELPIS_OK &&
              m.have_ecs && m.ecs_bad,
              "but a malformed one among them is still refused");
    }

    /* Written by the OPT builder and read back. */
    {
        uint8_t buf[512];
        elpis_bld_t b;
        elpis_edns_t ed;
        elpis_name_t qn;
        elpis_msg_t m;
        int drop = 0;

        elpis_name_from_text(&qn, "cdn.example.");
        elpis_bld_init(&b, buf, sizeof buf, NULL, 0);
        elpis_bld_header(&b, 9, ELPIS_FLAG_QR);
        elpis_bld_question(&b, &qn, ELPIS_T_A, ELPIS_CLASS_IN);
        elpis_edns_init(&ed, 1232, 1);
        ed.have_ecs = 1;
        elpis_addr_parse(&a, "203.0.113.77", 53);
        elpis_ecs_from_addr(&ed.ecs, &a, 24, 56);
        ed.ecs.scope = 20;
        elpis_edns_write(&b, &ed, 0);
        elpis_bld_finish(&b);
        CHECK(elpis_msg_parse(&m, buf, b.len, ELPIS_PARSE_RESPONSE, &drop) ==
                  ELPIS_OK && m.have_ecs && !m.ecs_bad &&
              elpis_ecs_same_subnet(&m.ecs, &ed.ecs) && m.ecs.scope == 20,
              "the OPT builder writes the option, SCOPE and all");
    }

    /* Configuration. */
    {
        elpis_conf_t c;
        char line[128];
        elpis_name_t n;

        elpis_conf_defaults(&c);
        CHECK(!c.ecs && c.ecs_ip_type == ELPIS_ECS_TYPE_CLIENT &&
              c.ecs_v4_bits == 24 && c.ecs_v6_bits == 56,
              "off by default; client, /24 and /56 when on");
        elpis_strlcpy(line, "ecs: yes", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK && c.ecs,
              "ecs: yes");
        elpis_strlcpy(line, "ecs-ip-type: this", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
              c.ecs_ip_type == ELPIS_ECS_TYPE_THIS, "ecs-ip-type: this");
        elpis_strlcpy(line, "ecs-ip-type: none", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
              c.ecs_ip_type == ELPIS_ECS_TYPE_NONE, "ecs-ip-type: none");
        elpis_strlcpy(line, "ecs-ip-type: somewhere", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) != ELPIS_OK,
              "anything else is an error");
        elpis_strlcpy(line, "ecs-ipv4-prefix: 20", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
              c.ecs_v4_bits == 20, "ecs-ipv4-prefix");
        elpis_strlcpy(line, "ecs-ipv4-prefix: 33", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) != ELPIS_OK &&
              c.ecs_v4_bits == 20, "an IPv4 prefix past 32 is an error");
        elpis_strlcpy(line, "ecs-ipv6-prefix: 129", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) != ELPIS_OK,
              "an IPv6 prefix past 128 is an error");

        elpis_name_from_text(&n, "www.shopee.com.my.");
        CHECK(elpis_conf_ecs_zone_ok(&c, &n), "no ecs-zone: every name");
        elpis_strlcpy(line, "ecs-zone: tbcache.com", sizeof line);
        CHECK(elpis_conf_parse_line(&c, line, "-", 1) == ELPIS_OK &&
              c.necs_zone == 1, "ecs-zone parses");
        CHECK(!elpis_conf_ecs_zone_ok(&c, &n), "then only names under it");
        elpis_name_from_text(&n, "www.taobao.com.danuoyi.TBCACHE.com.");
        CHECK(elpis_conf_ecs_zone_ok(&c, &n), "in any case");
        elpis_name_from_text(&n, "nottbcache.com.");
        CHECK(!elpis_conf_ecs_zone_ok(&c, &n), "on a label boundary");
    }

    /* The message cache keeps a tailored answer to its own subnet. */
    {
        elpis_cache_t *mc = elpis_mcache_new(4 * 1024 * 1024, 4);
        uint8_t msg[128], out[512];
        uint8_t qn[] = "\3cdn\7example\0";
        uint32_t toff[1], tval[1];
        size_t len, outlen = 0, qend;
        elpis_mkey_t k;
        elpis_mserve_t info;
        elpis_ecs_t s1, s2;

        CHECK(mc != NULL, "message cache created");
        if (mc == NULL)
            return;

        /* A bare NOERROR reply with one A record, question included. */
        memset(msg, 0, sizeof msg);
        elpis_put16(msg + 2, ELPIS_FLAG_QR);
        elpis_put16(msg + 4, 1);
        elpis_put16(msg + 6, 1);
        memcpy(msg + 12, qn, sizeof qn);
        len = 12 + sizeof qn;
        elpis_put16(msg + len, ELPIS_T_A); len += 2;
        elpis_put16(msg + len, ELPIS_CLASS_IN); len += 2;
        qend = len;
        msg[len++] = 0xC0; msg[len++] = 12;
        elpis_put16(msg + len, ELPIS_T_A); len += 2;
        elpis_put16(msg + len, ELPIS_CLASS_IN); len += 2;
        toff[0] = (uint32_t)len; tval[0] = 300;
        elpis_put32(msg + len, 300); len += 4;
        elpis_put16(msg + len, 4); len += 2;
        msg[len++] = 192; msg[len++] = 0; msg[len++] = 2; msg[len++] = 1;

        elpis_addr_parse(&a, "203.0.113.77", 53);
        elpis_ecs_from_addr(&s1, &a, 24, 56);
        elpis_addr_parse(&a, "198.51.100.77", 53);
        elpis_ecs_from_addr(&s2, &a, 24, 56);

        memset(&k, 0, sizeof k);
        k.qname = qn; k.qnamelen = sizeof qn; k.qtype = ELPIS_T_A;
        k.qclass = ELPIS_CLASS_IN;
        k.ecs = s1;
        elpis_mkey_hash(&k);
        CHECK(elpis_mcache_store(mc, &k, msg, len, qend, toff, tval, 1,
                                 len, len, ELPIS_RC_NOERROR, 0,
                                 ELPIS_SEC_INSECURE, 300, 0, 24, 0) == ELPIS_OK,
              "a tailored answer is stored");
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_OK &&
              info.ecs_scope == 24, "its own subnet is served it, with its SCOPE");

        k.ecs = s2;
        elpis_mkey_hash(&k);
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_ENOTFOUND,
              "another subnet is not");
        elpis_mkey_shared(&k);
        elpis_mkey_hash(&k);
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_ENOTFOUND,
              "nor is a client with no subnet");

        /* The view from here: shared, but not for a client with a subnet. */
        CHECK(elpis_mcache_store(mc, &k, msg, len, qend, toff, tval, 1,
                                 len, len, ELPIS_RC_NOERROR, 0,
                                 ELPIS_SEC_INSECURE, 300, 0, 0, 1) == ELPIS_OK,
              "a local answer is stored");
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_OK,
              "a client without a subnet is served it");
        k.shared_only = 1;
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_ENOTFOUND,
              "a client with one passes it over");
        k.shared_only = 0;
        CHECK(elpis_mcache_store(mc, &k, msg, len, qend, toff, tval, 1,
                                 len, len, ELPIS_RC_NOERROR, 0,
                                 ELPIS_SEC_INSECURE, 300, 0, 0, 0) == ELPIS_OK,
              "an answer that is the same for everyone replaces it");
        k.shared_only = 1;
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_OK &&
              info.ecs_scope == 0, "and every client is served that");

        k.ecs = s1;
        k.shared_only = 0;
        elpis_mkey_hash(&k);
        CHECK(elpis_mcache_serve(mc, &k, 1, qn, ELPIS_FLAG_QR, 512, 0, 30, 0,
                                 out, sizeof out, &outlen, &info) == ELPIS_OK,
              "the tailored one is still there beside it");
        elpis_cache_free(mc);
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
    test_infra_hold();
    test_held_rows();
    test_hashes();
    test_signatures();
    test_bignum();
    test_keytrap();
    test_rrset_why();
    test_ttl0_material();
    test_reply_fit();
    test_root_sentinel();
    test_dnssec();
    test_dns64();
    test_conflict();
    test_conf();
    test_licence();
    test_insecure_delegation();
    test_sec_link();
    test_ta_file();
    test_val_retry_budget();
    test_cookies();
    test_task_ceiling();
    test_quirks();
    test_localzone();
    test_ecs();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
