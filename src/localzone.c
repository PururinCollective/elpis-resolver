/*
 * localzone.c -- names that must never reach the public DNS.
 *
 * RFC 6761 reserves a handful of names for local use, RFC 6762 adds ".local",
 * RFC 7686 adds ".onion", and RFC 6303 lists the reverse zones for private
 * address space.  Forwarding any of these leaks internal topology to the root
 * servers and to AS112, so they are answered or refused here.
 */
#include "elpis/resolver.h"
#include "elpis/rdata.h"
#include "elpis/log.h"
#include "elpis/simd.h"

/* Reverse zones that describe address space which cannot appear on the
 * public internet (RFC 6303 section 4, RFC 6761 section 6.1). */
static const char *const k_private_reverse[] = {
    "10.in-addr.arpa.",
    "16.172.in-addr.arpa.", "17.172.in-addr.arpa.", "18.172.in-addr.arpa.",
    "19.172.in-addr.arpa.", "20.172.in-addr.arpa.", "21.172.in-addr.arpa.",
    "22.172.in-addr.arpa.", "23.172.in-addr.arpa.", "24.172.in-addr.arpa.",
    "25.172.in-addr.arpa.", "26.172.in-addr.arpa.", "27.172.in-addr.arpa.",
    "28.172.in-addr.arpa.", "29.172.in-addr.arpa.", "30.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    "254.169.in-addr.arpa.",
    "0.in-addr.arpa.",
    "127.in-addr.arpa.",
    "255.in-addr.arpa.",
    "64.100.in-addr.arpa.", "65.100.in-addr.arpa.", "66.100.in-addr.arpa.",
    "67.100.in-addr.arpa.", "68.100.in-addr.arpa.", "69.100.in-addr.arpa.",
    "70.100.in-addr.arpa.", "71.100.in-addr.arpa.",
    "d.f.ip6.arpa.",
    "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
};

/* Names that are defined to not exist in the global DNS. */
static const char *const k_nonexistent[] = {
    "invalid.", "onion.", "local.", "localhost.arpa.", "alt."
};

static int name_matches(const elpis_name_t *q, const char *text)
{
    elpis_name_t n;
    if (elpis_name_from_text(&n, text) != ELPIS_OK)
        return 0;
    return elpis_name_is_subdomain(q, &n);
}

/* Exactly this name, not anything beneath it. */
static int name_equals(const elpis_name_t *q, const char *text)
{
    elpis_name_t n;
    if (elpis_name_from_text(&n, text) != ELPIS_OK)
        return 0;
    return elpis_name_eq(q, &n);
}

/* Append one character-string to TXT rdata, silently dropping what will not
 * fit: a truncated identity is better than a malformed answer. */
static void txt_add(uint8_t *rd, size_t cap, size_t *len, const char *s)
{
    size_t l = strlen(s);
    if (l > 255) l = 255;
    if (*len + 1u + l > cap) return;
    rd[*len] = (uint8_t)l;
    memcpy(rd + *len + 1u, s, l);
    *len += 1u + l;
}

/*
 * Build a bare SOA-less negative answer.  A resolver is allowed to answer
 * from local data without an authority section; clients treat it as a normal
 * NXDOMAIN.
 */
static size_t build_simple(elpis_worker_t *w, const elpis_msg_t *m,
                           unsigned rcode, uint8_t *out, size_t cap,
                           const elpis_name_t *aname, uint16_t atype,
                           uint32_t attl, const uint8_t *ardata, uint16_t ardlen)
{
    elpis_bld_t b;
    uint16_t flags;
    size_t rdpos;

    elpis_bld_init(&b, out, cap, w->ctab, 1);
    flags = (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA | ELPIS_FLAG_AA |
                       (m->hdr.flags & ELPIS_FLAG_RD) |
                       (rcode & ELPIS_RCODE_MASK));
    if (elpis_bld_header(&b, m->hdr.id, flags) != ELPIS_OK)
        return 0;
    if (elpis_bld_question_raw(&b, m->qname.d, m->qname.len,
                               m->qtype, m->qclass) != ELPIS_OK)
        return 0;
    if (aname != NULL && ardata != NULL) {
        if (elpis_bld_rr_begin(&b, aname, atype, m->qclass, attl, &rdpos) != ELPIS_OK)
            return 0;
        if (elpis_bld_bytes(&b, ardata, ardlen) != ELPIS_OK)
            return 0;
        if (elpis_bld_rr_end(&b, rdpos) != ELPIS_OK)
            return 0;
        elpis_bld_count(&b, ELPIS_SEC_ANSWER, 1);
    }
    if (m->have_opt) {
        elpis_edns_t e;
        elpis_edns_init(&e, w->ctx->conf.edns_buffer, m->do_bit);
        if (w->ctx->conf.use_cookies && m->have_cookie && m->cookie_len >= 8) {
            /* The caller has the client address; cookies are added there for
             * the general path.  Local answers are cheap and unamplified, so
             * omitting the cookie here is harmless. */
            e.have_cookie = 0;
        }
        elpis_edns_write(&b, &e, rcode);
    }
    elpis_bld_finish(&b);
    return b.overflow ? 0 : b.len;
}

int elpis_localzone_static(elpis_worker_t *w, const elpis_msg_t *m,
                           uint8_t *out, size_t cap, size_t *outlen)
{
    const elpis_conf_t *c = &w->ctx->conf;
    size_t n;
    unsigned i;

    /* CHAOS: version.bind / hostname.bind / id.server. */
    if (m->qclass == ELPIS_CLASS_CH) {
        if (m->qtype == ELPIS_T_TXT) {
            const char *txt = NULL;
            if (name_matches(&m->qname, "version.bind.") ||
                name_matches(&m->qname, "version.server."))
                txt = c->answer_version_bind ? "elpis " ELPIS_VERSION : NULL;
            else if (name_matches(&m->qname, "hostname.bind.") ||
                     name_matches(&m->qname, "id.server."))
                txt = c->nsid[0] ? c->nsid : NULL;

            if (txt != NULL) {
                uint8_t rd[256];
                size_t l = strlen(txt);
                if (l > 255) l = 255;
                rd[0] = (uint8_t)l;
                memcpy(rd + 1, txt, l);
                n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, &m->qname,
                                 ELPIS_T_TXT, 0, rd, (uint16_t)(l + 1u));
                if (n == 0) return 0;
                *outlen = n;
                return 1;
            }
        }
        n = build_simple(w, m, ELPIS_RC_REFUSED, out, cap, NULL, 0, 0, NULL, 0);
        if (n == 0) return 0;
        *outlen = n;
        return 1;
    }

    /*
     * The identity probe.  One TXT name, answered only to a client the ACL
     * already let in, saying what this resolver IS rather than what it is
     * running on:
     *
     *   nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
     *
     * What is deliberately never in here is any address.  The resolver knows
     * its own public v4, v6 and AS -- the status page shows them -- and this
     * is exactly the wrong place to hand them out: a probe answered over UDP
     * with no authentication would let anyone who can reach the port map the
     * operator's upstream, and behind a forwarder it would disclose an
     * address the querier could not otherwise see.  Ask the status page,
     * which is authenticated, or the machine itself.
     *
     * The OS, kernel and hostname are behind identity-system: for the same
     * reason version banners are -- a kernel release is a CVE lookup key and
     * a hostname usually describes somebody's network.
     */
    if (c->identity && c->identity_name[0] &&
        name_equals(&m->qname, c->identity_name)) {
        uint8_t rd[512];
        size_t  rdlen = 0;
        char    tmp[256];

        if (m->qtype != ELPIS_T_TXT && m->qtype != ELPIS_T_ANY) {
            /* The name exists; it just has nothing of that type. */
            n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, NULL, 0, 0, NULL, 0);
            if (n == 0) return 0;
            *outlen = n;
            return 1;
        }

        snprintf(tmp, sizeof tmp, "elpis=%s", ELPIS_VERSION);
        txt_add(rd, sizeof rd, &rdlen, tmp);

        snprintf(tmp, sizeof tmp, "edition=%s",
                 c->edition[0] ? c->edition : "unspecified");
        txt_add(rd, sizeof rd, &rdlen, tmp);

        if (elpis_build_rev()[0]) {
            snprintf(tmp, sizeof tmp, "build=%s", elpis_build_rev());
            txt_add(rd, sizeof rd, &rdlen, tmp);
        }
        if (c->operator_name[0]) {
            snprintf(tmp, sizeof tmp, "operator=%s", c->operator_name);
            txt_add(rd, sizeof rd, &rdlen, tmp);
        }

        snprintf(tmp, sizeof tmp, "uptime=%lu",
                 (unsigned long)((elpis_now_ms() - w->ctx->start_ms) / 1000u));
        txt_add(rd, sizeof rd, &rdlen, tmp);

        snprintf(tmp, sizeof tmp, "workers=%u",
                 c->threads ? c->threads : elpis_cpu_count());
        txt_add(rd, sizeof rd, &rdlen, tmp);

        snprintf(tmp, sizeof tmp, "simd=%s", elpis_simd_backend());
        txt_add(rd, sizeof rd, &rdlen, tmp);

        snprintf(tmp, sizeof tmp, "dnssec=%s", c->dnssec ? "validating" : "off");
        txt_add(rd, sizeof rd, &rdlen, tmp);

        if (c->identity_system) {
            char sys[160];
            elpis_os_string(sys, sizeof sys);
            if (sys[0]) {
                snprintf(tmp, sizeof tmp, "system=%s", sys);
                txt_add(rd, sizeof rd, &rdlen, tmp);
            }
            elpis_host_name(sys, sizeof sys);
            if (sys[0]) {
                snprintf(tmp, sizeof tmp, "host=%s", sys);
                txt_add(rd, sizeof rd, &rdlen, tmp);
            }
        }

        n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, &m->qname,
                         ELPIS_T_TXT, 0, rd, (uint16_t)rdlen);
        if (n == 0) return 0;
        *outlen = n;
        return 1;
    }

    /*
     * RFC 8482: answering ANY with the whole zone is an amplification gift.
     * Return a single HINFO instead of enumerating.
     */
    if (m->qtype == ELPIS_T_ANY && c->refuse_any) {
        static const uint8_t hinfo[] = { 6, 'R','F','C','8','4','8','2', 0 };
        uint8_t rd[16];
        rd[0] = 7;
        memcpy(rd + 1, "RFC8482", 7);
        rd[8] = 0;                       /* empty OS field */
        (void)hinfo;
        n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, &m->qname,
                         ELPIS_T_HINFO, 3600, rd, 9);
        if (n == 0) return 0;
        *outlen = n;
        return 1;
    }

    /* localhost and friends (RFC 6761 section 6.3). */
    if (name_matches(&m->qname, "localhost.")) {
        if (m->qtype == ELPIS_T_A) {
            uint8_t rd[4] = { 127, 0, 0, 1 };
            n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, &m->qname,
                             ELPIS_T_A, 3600, rd, 4);
        } else if (m->qtype == ELPIS_T_AAAA) {
            uint8_t rd[16];
            memset(rd, 0, 16);
            rd[15] = 1;
            n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, &m->qname,
                             ELPIS_T_AAAA, 3600, rd, 16);
        } else {
            n = build_simple(w, m, ELPIS_RC_NOERROR, out, cap, NULL, 0, 0, NULL, 0);
        }
        if (n == 0) return 0;
        *outlen = n;
        return 1;
    }

    for (i = 0; i < ELPIS_ARRAY_LEN(k_nonexistent); i++) {
        if (name_matches(&m->qname, k_nonexistent[i])) {
            n = build_simple(w, m, ELPIS_RC_NXDOMAIN, out, cap, NULL, 0, 0, NULL, 0);
            if (n == 0) return 0;
            *outlen = n;
            return 1;
        }
    }

    if (c->block_private_reverse) {
        for (i = 0; i < ELPIS_ARRAY_LEN(k_private_reverse); i++) {
            if (name_matches(&m->qname, k_private_reverse[i])) {
                n = build_simple(w, m, ELPIS_RC_NXDOMAIN, out, cap, NULL, 0, 0,
                                 NULL, 0);
                if (n == 0) return 0;
                *outlen = n;
                return 1;
            }
        }
    }

    return 0;
}

/*
 * The in-resolution hook.  Everything the static path covers is handled
 * before a task is created, so this only has to catch names that appear
 * mid-chain (a CNAME pointing into a blocked zone, for instance).
 */
int elpis_localzone_answer(elpis_task_t *t)
{
    const elpis_conf_t *c = &t->w->ctx->conf;
    unsigned i;

    for (i = 0; i < ELPIS_ARRAY_LEN(k_nonexistent); i++) {
        if (name_matches(&t->qname, k_nonexistent[i])) {
            t->rcode = ELPIS_RC_NXDOMAIN;
            t->sec = ELPIS_SEC_INSECURE;
            return 1;
        }
    }
    if (c->block_private_reverse) {
        for (i = 0; i < ELPIS_ARRAY_LEN(k_private_reverse); i++) {
            if (name_matches(&t->qname, k_private_reverse[i])) {
                t->rcode = ELPIS_RC_NXDOMAIN;
                t->sec = ELPIS_SEC_INSECURE;
                return 1;
            }
        }
    }
    if (name_matches(&t->qname, "localhost.")) {
        uint8_t rd[16];
        if (t->qtype == ELPIS_T_A) {
            rd[0] = 127; rd[1] = 0; rd[2] = 0; rd[3] = 1;
            elpis_rrlist_add(&t->ans, ELPIS_SEC_ANSWER, &t->qname, ELPIS_T_A,
                             t->qclass, 3600, rd, 4);
        } else if (t->qtype == ELPIS_T_AAAA) {
            memset(rd, 0, 16);
            rd[15] = 1;
            elpis_rrlist_add(&t->ans, ELPIS_SEC_ANSWER, &t->qname, ELPIS_T_AAAA,
                             t->qclass, 3600, rd, 16);
        }
        t->rcode = ELPIS_RC_NOERROR;
        t->sec = ELPIS_SEC_INSECURE;
        return 1;
    }
    return 0;
}
