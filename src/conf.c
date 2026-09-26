/*
 * conf.c -- configuration file parsing.
 *
 * The format is deliberately boring: one "key: value" per line, '#' comments,
 * repeated keys build lists.  No includes, no macros, no nesting.  A resolver
 * config is read by people at 3am; it should not need a grammar reference.
 */
#include "elpis/conf.h"
#include "elpis/dns.h"

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

void elpis_conf_defaults(elpis_conf_t *c)
{
    memset(c, 0, sizeof *c);

    /*
     * Loopback only until told otherwise, on 5335 rather than 5353.
     *
     * 5353 is IANA-assigned to mDNS, and avahi-daemon binds 0.0.0.0:5353 on
     * most Linux hosts.  Because both sides set SO_REUSEADDR the two bind
     * without any error and the kernel then splits traffic between them, so
     * the clash is silent.  5335 is what the Pi-hole and unbound guides use
     * for exactly this reason.
     */
    elpis_addr_parse(&c->listen[0], "127.0.0.1@5335", 5335);
    elpis_addr_parse(&c->listen[1], "[::1]@5335", 5335);
    c->nlisten    = 2;
    c->listen_udp = 1;
    c->listen_tcp = 1;
    c->threads    = 0;
    c->tcp_max_conn = 512;
    c->tcp_idle_ms  = 10000;

    c->acl_default_allow = 0;
    elpis_prefix_parse(&c->acl[0].prefix, "127.0.0.0/8");
    c->acl[0].allow = 1;
    elpis_prefix_parse(&c->acl[1].prefix, "::1/128");
    c->acl[1].allow = 1;
    c->nacl = 2;

    c->cache_size         = 0;         /* auto */
    c->cache_min_ttl      = 0;
    c->cache_max_ttl      = 86400;
    c->cache_max_neg_ttl  = 3600;
    c->cache_min_neg_ttl  = 0;
    c->serve_stale        = 86400;
    c->serve_stale_reply_ttl = 30;
    c->prefetch           = 1;
    c->prefetch_pct       = 10;
    c->refresh_nx_confirm = 3;
    c->checkpoint[0]      = '\0';
    c->checkpoint_interval = 3600;
    c->checkpoint_names   = 50000;
    c->checkpoint_min_hits = 2;
    c->warm_rate          = 200;
    c->mesh               = 0;
    c->mesh_share         = 1;
    c->mesh_lsd           = 1;
    c->mesh_lookup        = 0;
    c->mesh_lookup_rtt    = 10;
    c->mesh_share_min_hits = 5;
    c->mesh_max_peers     = 16;
    c->web                = 0;
    elpis_addr_parse(&c->web_listen, "127.0.0.1@8082", 8082);
    elpis_strlcpy(c->web_user, "admin", sizeof c->web_user);
    c->web_pass[0]        = '\0';

    c->prime_root         = 1;
    c->probe_roots        = 1;
    c->probe_rounds       = 3;
    c->probe_interval     = 3600;
    c->warm_tlds          = 1;
    c->root_zone_transfer = 0;
    c->tld_refresh        = 86400;
    c->root_refresh       = 43200;
    /* xfr.dns.icann.org, the public AXFR source for the root zone. */
    elpis_addr_parse(&c->root_xfr_addr[0], "192.0.32.132@53", 53);
    elpis_addr_parse(&c->root_xfr_addr[1], "[2620:0:2830:202::132]@53", 53);
    c->n_root_xfr = 2;

    c->dnssec                 = 1;
    c->harden_dnssec_stripped = 1;
    c->harden_below_nxdomain  = 1;
    c->harden_referral_path   = 0;
    c->alg_mldsa44 = ELPIS_ALG_MLDSA44_DEFAULT;
    c->alg_mldsa65 = ELPIS_ALG_MLDSA65_DEFAULT;
    c->alg_mldsa87 = ELPIS_ALG_MLDSA87_DEFAULT;
    c->sig_skew    = 0;

    c->dns64 = 0;
    elpis_prefix_parse(&c->dns64_prefix, "64:ff9b::/96");

    c->edns_buffer      = ELPIS_EDNS_DEFAULT;
    c->edns_buffer4     = ELPIS_EDNS_DEFAULT;
    c->edns_buffer6     = ELPIS_EDNS_DEFAULT;
    c->edns_auto        = 0;
    c->port_lo          = 1024;
    c->port_hi          = 65535;
    c->out_sockets      = 32;
    c->query_timeout_ms = 1200;
    /*
     * The whole resolution, including any DNSSEC chain lookups it triggers.
     * A cold cache can need the root DNSKEY, a DS and a DNSKEY per zone cut
     * on top of the referral chain itself, so a budget sized for the referral
     * chain alone turns first-contact queries into SERVFAILs.
     */
    c->query_total_ms   = 20000;
    c->max_retries      = 3;
    c->max_pending_auto = 1;
    c->max_referrals    = ELPIS_MAX_REFERRALS;
    c->qname_minimisation = 1;
    c->qname_min_strict   = 0;
    c->use_cookies      = 1;
    c->require_cookie   = 0;
    c->use_0x20         = 1;
    c->do_ipv4          = 1;
    c->do_ipv6          = 1;
    c->prefer_ipv6      = 0;
    c->tcp_upstream     = 1;

    c->client_qps       = 0;
    c->nxdomain_qps     = 0;
    c->max_udp_size_reply = ELPIS_EDNS_SAFE;

    c->block_private_reverse = 1;
    c->refuse_any            = 1;
    c->answer_version_bind   = 1;
    c->identity              = 1;
    c->identity_system       = 0;
    elpis_strlcpy(c->identity_name, ELPIS_IDENTITY_NAME_DEFAULT,
                  sizeof c->identity_name);
    elpis_strlcpy(c->edition, "community", sizeof c->edition);

    c->stop_systemd_resolved = 1;

    c->log_level = ELPIS_LOG_INFO;
    c->log_dst   = ELPIS_LOG_DST_STDERR;
    c->log_drops = 1;

    c->stats_interval = 0;
}

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    elpis_conf_t *c;
    const char   *src;
    unsigned      lineno;
    unsigned      errors;
} pctx_t;

static void perr(pctx_t *p, const char *key, const char *val)
{
    elpis_error("%s:%u: bad value for '%s': '%s'", p->src, p->lineno, key,
                val ? val : "");
    p->errors++;
}

static int want_bool(pctx_t *p, const char *k, const char *v, uint8_t *dst)
{
    int b;
    if (elpis_parse_bool(v, &b) != 0) {
        perr(p, k, v);
        return -1;
    }
    *dst = (uint8_t)(b ? 1 : 0);
    return 0;
}

static int want_u32(pctx_t *p, const char *k, const char *v, uint32_t *dst)
{
    if (elpis_parse_u32(v, dst) != 0) {
        perr(p, k, v);
        return -1;
    }
    return 0;
}

static int want_dur(pctx_t *p, const char *k, const char *v, uint32_t *dst)
{
    if (elpis_parse_duration(v, dst) != 0) {
        perr(p, k, v);
        return -1;
    }
    return 0;
}

static int want_size(pctx_t *p, const char *k, const char *v, uint64_t *dst)
{
    if (!elpis_strcasecmp_ascii(v, "auto")) {
        *dst = 0;
        return 0;
    }
    if (elpis_parse_size(v, dst) != 0) {
        perr(p, k, v);
        return -1;
    }
    return 0;
}

#define KEY(s) (!elpis_strcasecmp_ascii(key, (s)))

int elpis_conf_parse_line(elpis_conf_t *c, char *line, const char *src,
                          unsigned lineno)
{
    pctx_t p;
    char *key, *val, *colon, *hash;

    p.c = c;
    p.src = src;
    p.lineno = lineno;
    p.errors = 0;

    hash = strchr(line, '#');
    if (hash != NULL)
        *hash = '\0';
    line = elpis_strtrim(line);
    if (*line == '\0')
        return ELPIS_OK;

    colon = strchr(line, ':');
    /*
     * A colon can also be part of an IPv6 literal, so only treat it as the
     * key separator when it comes before the first space.
     */
    {
        char *sp = strpbrk(line, " \t");
        if (colon != NULL && (sp == NULL || colon < sp)) {
            *colon = '\0';
            key = elpis_strtrim(line);
            val = elpis_strtrim(colon + 1);
        } else if (sp != NULL) {
            *sp = '\0';
            key = elpis_strtrim(line);
            val = elpis_strtrim(sp + 1);
        } else {
            key = line;
            val = (char *)"";
        }
    }

    /* ---- listening ---- */
    if (KEY("listen") || KEY("interface")) {
        if (c->nlisten >= ELPIS_MAX_LISTEN) {
            elpis_warn("%s:%u: too many listen addresses", src, lineno);
            return ELPIS_OK;
        }
        if (elpis_addr_parse(&c->listen[c->nlisten], val, 53) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        c->nlisten++;
        return ELPIS_OK;
    }
    if (KEY("webgui"))     return want_bool(&p, key, val, &c->web);
    if (KEY("webgui-listen")) {
        if (elpis_addr_parse(&c->web_listen, val, 8082) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        return ELPIS_OK;
    }
    if (KEY("webgui-username")) {
        elpis_strlcpy(c->web_user, val, sizeof c->web_user);
        return ELPIS_OK;
    }
    if (KEY("webgui-password")) {
        elpis_strlcpy(c->web_pass, val, sizeof c->web_pass);
        return ELPIS_OK;
    }
    if (KEY("listen-udp")) return want_bool(&p, key, val, &c->listen_udp);
    if (KEY("listen-tcp")) return want_bool(&p, key, val, &c->listen_tcp);
    if (KEY("threads")) {
        if (!elpis_strcasecmp_ascii(val, "auto")) {
            c->threads = 0;
            return ELPIS_OK;
        }
        return want_u32(&p, key, val, &c->threads);
    }
    if (KEY("tcp-max-connections")) return want_u32(&p, key, val, &c->tcp_max_conn);
    if (KEY("tcp-idle-timeout")) {
        /*
         * Durations parse to seconds; this one is kept in milliseconds.  It
         * was stored as parsed, so the shipped "10s" made a ten-millisecond
         * idle timeout: every TCP query not answered from the cache lost its
         * connection before the answer was ready, and the client waited in
         * vain.  Answers from the cache take microseconds, which is why TCP
         * looked as if it worked.
         */
        uint32_t secs;
        if (want_dur(&p, key, val, &secs) != 0) return ELPIS_ERR;
        c->tcp_idle_ms = (secs == 0 ? 1u : ELPIS_MIN(secs, 3600u)) * 1000u;
        return ELPIS_OK;
    }

    /* ---- access control ---- */
    if (KEY("access-control")) {
        char *sp = strpbrk(val, " \t");
        const char *act = "allow";
        if (sp != NULL) {
            *sp = '\0';
            act = elpis_strtrim(sp + 1);
        }
        if (c->nacl >= ELPIS_MAX_ACL) {
            elpis_warn("%s:%u: too many access-control entries", src, lineno);
            return ELPIS_OK;
        }
        if (elpis_prefix_parse(&c->acl[c->nacl].prefix, val) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        if (!elpis_strcasecmp_ascii(act, "allow")) {
            c->acl[c->nacl].allow = 1;
        } else if (!elpis_strcasecmp_ascii(act, "allow_snoop") ||
                   !elpis_strcasecmp_ascii(act, "allow-snoop")) {
            c->acl[c->nacl].allow = 1;
            c->acl[c->nacl].allow_snoop = 1;
        } else if (!elpis_strcasecmp_ascii(act, "deny") ||
                   !elpis_strcasecmp_ascii(act, "refuse")) {
            c->acl[c->nacl].allow = 0;
        } else {
            perr(&p, key, act);
            return ELPIS_ERR;
        }
        c->nacl++;
        return ELPIS_OK;
    }

    /* ---- cache ---- */
    if (KEY("cache-size"))           return want_size(&p, key, val, &c->cache_size);
    if (KEY("cache-min-ttl"))        return want_dur(&p, key, val, &c->cache_min_ttl);
    if (KEY("cache-max-ttl"))        return want_dur(&p, key, val, &c->cache_max_ttl);
    if (KEY("cache-max-negative-ttl")) return want_dur(&p, key, val, &c->cache_max_neg_ttl);
    if (KEY("cache-min-negative-ttl")) return want_dur(&p, key, val, &c->cache_min_neg_ttl);
    if (KEY("serve-stale"))          return want_dur(&p, key, val, &c->serve_stale);
    if (KEY("serve-stale-reply-ttl")) return want_dur(&p, key, val, &c->serve_stale_reply_ttl);
    if (KEY("prefetch"))             return want_bool(&p, key, val, &c->prefetch);
    if (KEY("refresh-nxdomain-confirmations")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->refresh_nx_confirm = (unsigned)ELPIS_CLAMP(v, 1u, 15u);
        return ELPIS_OK;
    }
    if (KEY("prefetch-threshold")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->prefetch_pct = (unsigned)ELPIS_CLAMP(v, 1u, 90u);
        return ELPIS_OK;
    }

    /* ---- checkpoint and warm-up ---- */
    if (KEY("checkpoint")) {
        int b;
        if (elpis_parse_bool(val, &b) == 0 && !b) {
            c->checkpoint[0] = '\0';
            return ELPIS_OK;
        }
        /*
         * An absolute path only.  The file is rewritten long after startup,
         * from wherever daemon() and chroot have left the working directory,
         * so a relative one would not stay the file that was meant.
         */
        if (val[0] != '/' || strlen(val) >= sizeof c->checkpoint) {
            elpis_error("%s:%u: 'checkpoint' takes an absolute path, or no",
                        src, lineno);
            return ELPIS_ERR;
        }
        elpis_strlcpy(c->checkpoint, val, sizeof c->checkpoint);
        return ELPIS_OK;
    }
    if (KEY("checkpoint-interval")) return want_dur(&p, key, val, &c->checkpoint_interval);
    if (KEY("checkpoint-names")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->checkpoint_names = ELPIS_CLAMP(v, 1u, 1000000u);
        return ELPIS_OK;
    }
    if (KEY("checkpoint-min-hits")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->checkpoint_min_hits = ELPIS_CLAMP(v, 1u, 1000000u);
        return ELPIS_OK;
    }
    if (KEY("warm-rate")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->warm_rate = ELPIS_MIN(v, 100000u);
        return ELPIS_OK;
    }

    /* ---- mesh ---- */
    if (KEY("mesh")) return want_bool(&p, key, val, &c->mesh);
    if (KEY("mesh-psk")) {
        if (val[0] != '/' || strlen(val) >= sizeof c->mesh_psk_file) {
            elpis_error("%s:%u: 'mesh-psk' takes an absolute path", src, lineno);
            return ELPIS_ERR;
        }
        elpis_strlcpy(c->mesh_psk_file, val, sizeof c->mesh_psk_file);
        return ELPIS_OK;
    }
    if (KEY("mesh-listen") || KEY("mesh-peer")) {
        int listen = KEY("mesh-listen");
        elpis_addr_t *arr = listen ? c->mesh_listen : c->mesh_peer;
        unsigned *n = listen ? &c->n_mesh_listen : &c->n_mesh_peer;
        unsigned max = listen ? ELPIS_MESH_MAX_LISTEN : ELPIS_MESH_MAX_BRIDGES;
        if (*n >= max) {
            elpis_warn("%s:%u: more than %u '%s' lines; the rest are ignored",
                       src, lineno, max, key);
            return ELPIS_OK;
        }
        if (elpis_addr_parse(&arr[*n], val, ELPIS_MESH_PORT) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        (*n)++;
        return ELPIS_OK;
    }
    if (KEY("mesh-share")) return want_bool(&p, key, val, &c->mesh_share);
    if (KEY("mesh-lsd"))   return want_bool(&p, key, val, &c->mesh_lsd);
    if (KEY("mesh-lookup")) return want_bool(&p, key, val, &c->mesh_lookup);
    if (KEY("mesh-lookup-rtt")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->mesh_lookup_rtt = ELPIS_CLAMP(v, 1u, 1000u);
        return ELPIS_OK;
    }
    if (KEY("mesh-share-min-hits")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->mesh_share_min_hits = ELPIS_CLAMP(v, 1u, 1000000u);
        return ELPIS_OK;
    }
    if (KEY("mesh-max-peers")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->mesh_max_peers = ELPIS_CLAMP(v, 1u, 64u);
        return ELPIS_OK;
    }

    /* ---- roots and TLDs ---- */
    if (KEY("root-hints")) {
        elpis_strlcpy(c->root_hints, val, sizeof c->root_hints);
        return ELPIS_OK;
    }
    if (KEY("prime-root"))      return want_bool(&p, key, val, &c->prime_root);
    if (KEY("probe-roots"))     return want_bool(&p, key, val, &c->probe_roots);
    if (KEY("probe-rounds"))    return want_u32(&p, key, val, &c->probe_rounds);
    if (KEY("probe-interval"))  return want_dur(&p, key, val, &c->probe_interval);
    if (KEY("warm-tlds") || KEY("prefetch-tld"))
                                return want_bool(&p, key, val, &c->warm_tlds);
    if (KEY("root-zone-transfer")) return want_bool(&p, key, val, &c->root_zone_transfer);
    if (KEY("root-zone-server")) {
        if (c->n_root_xfr >= ELPIS_ARRAY_LEN(c->root_xfr_addr))
            return ELPIS_OK;
        if (elpis_addr_parse(&c->root_xfr_addr[c->n_root_xfr], val, 53) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        c->n_root_xfr++;
        return ELPIS_OK;
    }
    if (KEY("tld-refresh"))  return want_dur(&p, key, val, &c->tld_refresh);
    if (KEY("root-refresh")) return want_dur(&p, key, val, &c->root_refresh);

    /* ---- DNSSEC ---- */
    if (KEY("dnssec") || KEY("dnssec-validation"))
        return want_bool(&p, key, val, &c->dnssec);
    if (KEY("dnssec-permissive"))      return want_bool(&p, key, val, &c->dnssec_permissive);
    if (KEY("harden-dnssec-stripped")) return want_bool(&p, key, val, &c->harden_dnssec_stripped);
    if (KEY("harden-below-nxdomain"))  return want_bool(&p, key, val, &c->harden_below_nxdomain);
    if (KEY("harden-referral-path"))   return want_bool(&p, key, val, &c->harden_referral_path);
    if (KEY("trust-anchor-file")) {
        elpis_strlcpy(c->trust_anchor_file, val, sizeof c->trust_anchor_file);
        return ELPIS_OK;
    }
    if (KEY("signature-clock-skew")) return want_dur(&p, key, val, &c->sig_skew);
    if (KEY("mldsa44-algorithm") || KEY("mldsa65-algorithm") ||
        KEY("mldsa87-algorithm")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0 || v == 0 || v > 255) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        if (KEY("mldsa44-algorithm")) c->alg_mldsa44 = (uint8_t)v;
        else if (KEY("mldsa65-algorithm")) c->alg_mldsa65 = (uint8_t)v;
        else c->alg_mldsa87 = (uint8_t)v;
        return ELPIS_OK;
    }

    /* ---- DNS64 ---- */
    if (KEY("dns64")) return want_bool(&p, key, val, &c->dns64);
    if (KEY("dns64-prefix")) {
        if (elpis_prefix_parse(&c->dns64_prefix, val) != 0 ||
            c->dns64_prefix.family != AF_INET6) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        /* RFC 6052 allows only these prefix lengths. */
        switch (c->dns64_prefix.bits) {
        case 32: case 40: case 48: case 56: case 64: case 96:
            break;
        default:
            elpis_error("%s:%u: dns64-prefix length must be 32, 40, 48, 56, "
                        "64 or 96 (RFC 6052)", src, lineno);
            return ELPIS_ERR;
        }
        return ELPIS_OK;
    }
    if (KEY("dns64-synthesize-all")) return want_bool(&p, key, val, &c->dns64_synth_all);
    if (KEY("dns64-strip-a")) return want_bool(&p, key, val, &c->dns64_strip_a);
    if (KEY("dns64-ignore-aaaa")) {
        if (c->n_dns64_ignore >= ELPIS_ARRAY_LEN(c->dns64_ignore_aaaa))
            return ELPIS_OK;
        if (elpis_prefix_parse(&c->dns64_ignore_aaaa[c->n_dns64_ignore], val) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        c->n_dns64_ignore++;
        return ELPIS_OK;
    }

    /* ---- resolution ---- */
    if (KEY("edns-buffer-size")) {
        uint32_t v;
        if (!elpis_strcasecmp_ascii(val, "auto")) {
            c->edns_auto = 1;        /* sized per family at startup */
            return ELPIS_OK;
        }
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->edns_auto    = 0;
        c->edns_buffer  = (uint16_t)ELPIS_CLAMP(v, 512u, 4096u);
        c->edns_buffer4 = c->edns_buffer;
        c->edns_buffer6 = c->edns_buffer;
        return ELPIS_OK;
    }
    if (KEY("outgoing-port-range")) {
        char *dash = strchr(val, '-');
        uint32_t lo, hi;
        if (dash == NULL) { perr(&p, key, val); return ELPIS_ERR; }
        *dash = '\0';
        if (elpis_parse_u32(elpis_strtrim(val), &lo) != 0 ||
            elpis_parse_u32(elpis_strtrim(dash + 1), &hi) != 0 ||
            lo < 1024 || hi > 65535 || lo >= hi) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        c->port_lo = (uint16_t)lo;
        c->port_hi = (uint16_t)hi;
        return ELPIS_OK;
    }
    if (KEY("outgoing-sockets"))   return want_u32(&p, key, val, &c->out_sockets);
    if (KEY("query-timeout"))      return want_u32(&p, key, val, &c->query_timeout_ms);
    if (KEY("query-total-timeout")) return want_u32(&p, key, val, &c->query_total_ms);
    if (KEY("max-retries"))        return want_u32(&p, key, val, &c->max_retries);
    if (KEY("max-pending")) {
        uint32_t v;
        if (!elpis_strcasecmp_ascii(val, "auto")) {
            c->max_pending_auto = 1;
            return ELPIS_OK;
        }
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->max_pending_auto = 0;
        c->max_pending      = ELPIS_CLAMP(v, 64u, 1000000u);
        return ELPIS_OK;
    }
    if (KEY("max-referrals"))      return want_u32(&p, key, val, &c->max_referrals);
    if (KEY("qname-minimisation") || KEY("qname-minimization"))
        return want_bool(&p, key, val, &c->qname_minimisation);
    if (KEY("qname-minimisation-strict") || KEY("qname-minimization-strict"))
        return want_bool(&p, key, val, &c->qname_min_strict);
    if (KEY("use-cookies"))   return want_bool(&p, key, val, &c->use_cookies);
    if (KEY("require-cookie")) return want_bool(&p, key, val, &c->require_cookie);
    if (KEY("use-0x20") || KEY("use-caps-for-id"))
        return want_bool(&p, key, val, &c->use_0x20);
    if (KEY("do-ipv4"))       return want_bool(&p, key, val, &c->do_ipv4);
    if (KEY("do-ipv6"))       return want_bool(&p, key, val, &c->do_ipv6);
    if (KEY("prefer-ipv6"))   return want_bool(&p, key, val, &c->prefer_ipv6);
    if (KEY("tcp-upstream"))  return want_bool(&p, key, val, &c->tcp_upstream);
    if (KEY("outgoing-interface")) {
        elpis_addr_t a;
        if (elpis_addr_parse(&a, val, 0) != 0) { perr(&p, key, val); return ELPIS_ERR; }
        if (elpis_addr_family(&a) == AF_INET) {
            if (c->have_src4 >= ELPIS_MAX_OUT_SRC) { perr(&p, key, val); return ELPIS_ERR; }
            c->out_src4[c->have_src4++] = a;
        } else {
            if (c->have_src6 >= ELPIS_MAX_OUT_SRC) { perr(&p, key, val); return ELPIS_ERR; }
            c->out_src6[c->have_src6++] = a;
        }
        return ELPIS_OK;
    }

    /* ---- forwarders and stubs ---- */
    if (KEY("forward-zone") || KEY("stub-zone")) {
        /* "zone addr[ addr...]" */
        char *sp = strpbrk(val, " \t");
        elpis_zoneroute_t *r;
        if (sp == NULL) { perr(&p, key, val); return ELPIS_ERR; }
        *sp++ = '\0';
        if (c->nroute >= ELPIS_ARRAY_LEN(c->route)) {
            elpis_warn("%s:%u: too many zone routes", src, lineno);
            return ELPIS_OK;
        }
        r = &c->route[c->nroute];
        memset(r, 0, sizeof *r);
        elpis_strlcpy(r->name, elpis_strtrim(val), sizeof r->name);
        r->is_stub = KEY("stub-zone") ? 1u : 0u;
        while (r->naddr < ELPIS_ARRAY_LEN(r->addr)) {
            char *tok = elpis_strtrim(sp);
            char *nx = strpbrk(tok, " \t");
            if (*tok == '\0')
                break;
            if (nx != NULL)
                *nx++ = '\0';
            if (elpis_addr_parse(&r->addr[r->naddr], tok, 53) != 0) {
                perr(&p, key, tok);
                return ELPIS_ERR;
            }
            r->naddr++;
            if (nx == NULL)
                break;
            sp = nx;
        }
        if (r->naddr == 0) { perr(&p, key, val); return ELPIS_ERR; }
        c->nroute++;
        return ELPIS_OK;
    }

    /* ---- rate limiting ---- */
    if (KEY("client-qps"))   return want_u32(&p, key, val, &c->client_qps);
    if (KEY("nxdomain-qps")) return want_u32(&p, key, val, &c->nxdomain_qps);
    if (KEY("max-udp-reply-size")) {
        uint32_t v;
        if (want_u32(&p, key, val, &v) != 0) return ELPIS_ERR;
        c->max_udp_size_reply = (uint16_t)ELPIS_CLAMP(v, 512u, 4096u);
        return ELPIS_OK;
    }

    /* ---- local behaviour ---- */
    if (KEY("block-private-reverse")) return want_bool(&p, key, val, &c->block_private_reverse);
    if (KEY("refuse-any"))            return want_bool(&p, key, val, &c->refuse_any);
    if (KEY("answer-version-bind"))   return want_bool(&p, key, val, &c->answer_version_bind);
    if (KEY("identity"))             return want_bool(&p, key, val, &c->identity);
    if (KEY("identity-system"))      return want_bool(&p, key, val, &c->identity_system);

    /* ---- process ---- */
    if (KEY("user"))     { elpis_strlcpy(c->user, val, sizeof c->user); return ELPIS_OK; }
    if (KEY("group"))    { elpis_strlcpy(c->group, val, sizeof c->group); return ELPIS_OK; }
    if (KEY("chroot"))   { elpis_strlcpy(c->chroot_dir, val, sizeof c->chroot_dir); return ELPIS_OK; }
    if (KEY("pidfile"))  { elpis_strlcpy(c->pidfile, val, sizeof c->pidfile); return ELPIS_OK; }
    if (KEY("daemonize")) return want_bool(&p, key, val, &c->daemonize);
    if (KEY("stop-systemd-resolved"))
        return want_bool(&p, key, val, &c->stop_systemd_resolved);

    /* ---- logging ---- */
    if (KEY("log-level")) {
        if (elpis_log_level_parse(val, &c->log_level) != 0) {
            perr(&p, key, val);
            return ELPIS_ERR;
        }
        return ELPIS_OK;
    }
    if (KEY("log-destination")) {
        if (!elpis_strcasecmp_ascii(val, "stderr")) c->log_dst = ELPIS_LOG_DST_STDERR;
        else if (!elpis_strcasecmp_ascii(val, "file")) c->log_dst = ELPIS_LOG_DST_FILE;
        else if (!elpis_strcasecmp_ascii(val, "syslog")) c->log_dst = ELPIS_LOG_DST_SYSLOG;
        else if (!elpis_strcasecmp_ascii(val, "none")) c->log_dst = ELPIS_LOG_DST_NONE;
        else { perr(&p, key, val); return ELPIS_ERR; }
        return ELPIS_OK;
    }
    if (KEY("log-file")) {
        elpis_strlcpy(c->log_file, val, sizeof c->log_file);
        c->log_dst = ELPIS_LOG_DST_FILE;
        return ELPIS_OK;
    }
    if (KEY("log-queries")) return want_bool(&p, key, val, &c->log_queries);
    if (KEY("log-replies")) return want_bool(&p, key, val, &c->log_replies);
    if (KEY("log-drops"))   return want_bool(&p, key, val, &c->log_drops);
    if (KEY("nsid"))        { elpis_strlcpy(c->nsid, val, sizeof c->nsid); return ELPIS_OK; }
    if (KEY("identity-name")) { elpis_strlcpy(c->identity_name, val,
                                              sizeof c->identity_name); return ELPIS_OK; }
    if (KEY("edition"))     { elpis_strlcpy(c->edition, val, sizeof c->edition); return ELPIS_OK; }
    if (KEY("licence") || KEY("license"))
                            { elpis_strlcpy(c->licence, val, sizeof c->licence); return ELPIS_OK; }
    if (KEY("operator"))    { elpis_strlcpy(c->operator_name, val,
                                            sizeof c->operator_name); return ELPIS_OK; }
    if (KEY("statistics-interval")) return want_dur(&p, key, val, &c->stats_interval);

    elpis_warn("%s:%u: unknown setting '%s' (ignored)", src, lineno, key);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* File loading                                                        */
/* ------------------------------------------------------------------ */

static int file_exists(const char *p)
{
    struct stat st;
    return p != NULL && *p != '\0' && stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int load_file(elpis_conf_t *c, const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[2048];
    unsigned lineno = 0;
    int errors = 0;
    int listen_seen = 0;

    if (fp == NULL)
        return ELPIS_ERR;

    /*
     * A "listen" line in the file replaces the built-in loopback defaults
     * rather than adding to them, which is what people expect.
     */
    while (fgets(line, sizeof line, fp) != NULL) {
        char probe[2048];
        char *k;
        elpis_strlcpy(probe, line, sizeof probe);
        k = strchr(probe, '#');
        if (k) *k = '\0';
        k = elpis_strtrim(probe);
        if (!elpis_strcasecmp_ascii(k, "") )
            continue;
        if ((strncmp(k, "listen", 6) == 0 || strncmp(k, "interface", 9) == 0) &&
            (k[6] == ':' || k[6] == ' ' || k[6] == '\t' ||
             k[9] == ':' || k[9] == ' ' || k[9] == '\t')) {
            listen_seen = 1;
            break;
        }
    }
    if (listen_seen)
        c->nlisten = 0;
    rewind(fp);

    while (fgets(line, sizeof line, fp) != NULL) {
        lineno++;
        if (elpis_conf_parse_line(c, line, path, lineno) != ELPIS_OK)
            errors++;
    }
    fclose(fp);

    elpis_strlcpy(c->path, path, sizeof c->path);
    if (errors)
        elpis_warn("%s: %d configuration error(s); defaults kept for those "
                   "settings", path, errors);
    return ELPIS_OK;
}

int elpis_conf_load(elpis_conf_t *c, const char *explicit_path)
{
    char cand[1024];
    const char *dir;

    elpis_conf_defaults(c);

    if (explicit_path != NULL && *explicit_path != '\0') {
        if (!file_exists(explicit_path)) {
            elpis_error("config file '%s' not found", explicit_path);
            return ELPIS_ERR;
        }
        return load_file(c, explicit_path);
    }

    /* 1. next to the executable */
    dir = elpis_exe_dir();
    if (dir != NULL && *dir != '\0') {
        size_t n;

        snprintf(cand, sizeof cand, "%s/elpis.conf", dir);
        if (file_exists(cand))
            return load_file(c, cand);

        /*
         * 1b. one level up, when the executable lives in a bin/ directory.
         * The build puts the binary in bin/, and an installed tree has the
         * same shape, so "beside the binary" would otherwise mean beside
         * nothing -- and the config sitting one level up where anyone would
         * put it would be passed over in silence for the built-in defaults.
         */
        n = strlen(dir);
        if (n >= 4 && strcmp(dir + n - 4, "/bin") == 0) {
            snprintf(cand, sizeof cand, "%.*s/elpis.conf", (int)(n - 4), dir);
            if (file_exists(cand))
                return load_file(c, cand);
        }
    }
    /* 2. /etc/elpis/elpis.conf */
    snprintf(cand, sizeof cand, "%s/elpis/elpis.conf", ELPIS_SYSCONFDIR);
    if (file_exists(cand))
        return load_file(c, cand);
    /* 3. /etc/elpis.conf */
    snprintf(cand, sizeof cand, "%s/elpis.conf", ELPIS_SYSCONFDIR);
    if (file_exists(cand))
        return load_file(c, cand);

    elpis_info("no elpis.conf found (looked next to the binary, above a bin/ "
               "directory, in %s/elpis/ and in %s/); using built-in defaults",
               ELPIS_SYSCONFDIR, ELPIS_SYSCONFDIR);
    return ELPIS_OK;
}

int elpis_conf_acl_check(const elpis_conf_t *c, const elpis_addr_t *a, int *snoop)
{
    unsigned i;
    int best = -1;
    unsigned best_bits = 0;

    if (snoop)
        *snoop = 0;

    /* Longest matching prefix wins, so a specific deny beats a broad allow. */
    for (i = 0; i < c->nacl; i++) {
        if (!elpis_prefix_match(&c->acl[i].prefix, a))
            continue;
        if (best < 0 || c->acl[i].prefix.bits >= best_bits) {
            best = (int)i;
            best_bits = c->acl[i].prefix.bits;
        }
    }
    if (best < 0)
        return c->acl_default_allow ? 1 : 0;
    if (snoop)
        *snoop = (int)c->acl[best].allow_snoop;
    return (int)c->acl[best].allow;
}

void elpis_conf_dump(const elpis_conf_t *c)
{
    char buf[80];
    unsigned i;

    elpis_info("config: %s", c->path[0] ? c->path : "(built-in defaults)");
    for (i = 0; i < c->nlisten; i++)
        elpis_info("  listen %s", elpis_addr_str(&c->listen[i], buf, sizeof buf));
    elpis_info("  threads=%s udp=%d tcp=%d",
               c->threads ? "fixed" : "auto", (int)c->listen_udp, (int)c->listen_tcp);
    elpis_info("  dnssec=%d qname-min=%d cookies=%d 0x20=%d dns64=%d%s",
               (int)c->dnssec, (int)c->qname_minimisation, (int)c->use_cookies,
               (int)c->use_0x20, (int)c->dns64,
               (c->dns64 && c->dns64_strip_a) ? " (A stripped)" : "");
    elpis_info("  max-pending=%u per worker%s", c->max_pending,
               c->max_pending_auto ? " (auto)" : "");
    if (c->checkpoint[0] != '\0')
        elpis_info("  checkpoint=%s every %us, up to %u names, warm-rate=%u/s",
                   c->checkpoint, (unsigned)c->checkpoint_interval,
                   (unsigned)c->checkpoint_names, (unsigned)c->warm_rate);
    if (c->mesh) {
        for (i = 0; i < c->n_mesh_listen; i++)
            elpis_info("  mesh-listen %s",
                       elpis_addr_str(&c->mesh_listen[i], buf, sizeof buf));
        for (i = 0; i < c->n_mesh_peer; i++)
            elpis_info("  mesh-peer %s",
                       elpis_addr_str(&c->mesh_peer[i], buf, sizeof buf));
        elpis_info("  mesh-share=%d (min hits %u), mesh-lsd=%d, mesh-max-peers=%u",
                   (int)c->mesh_share, (unsigned)c->mesh_share_min_hits,
                   (int)c->mesh_lsd, (unsigned)c->mesh_max_peers);
        if (c->mesh_lookup)
            elpis_info("  mesh-lookup: peers within %u ms",
                       (unsigned)c->mesh_lookup_rtt);
    }
    if (c->edns_auto)
        elpis_info("  edns-buffer-size=auto (IPv4 %u, IPv6 %u) "
                   "max-udp-reply-size=%u", (unsigned)c->edns_buffer4,
                   (unsigned)c->edns_buffer6, (unsigned)c->max_udp_size_reply);
    else
        elpis_info("  edns-buffer-size=%u max-udp-reply-size=%u",
                   (unsigned)c->edns_buffer, (unsigned)c->max_udp_size_reply);
    for (i = 0; i < c->nroute; i++) {
        char list[256];
        unsigned j;
        list[0] = '\0';
        for (j = 0; j < c->route[i].naddr; j++) {
            if (j) elpis_strlcat(list, " ", sizeof list);
            elpis_strlcat(list, elpis_addr_str(&c->route[i].addr[j], buf,
                                               sizeof buf), sizeof list);
        }
        elpis_info("  %s %s -> %s",
                   c->route[i].is_stub ? "stub-zone   " : "forward-zone",
                   c->route[i].name, list);
    }
}
