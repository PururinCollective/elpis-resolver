/*
 * elpis/conf.h -- configuration.
 *
 * Search order for the config file when none is given on the command line:
 *   1. <directory of the executable>/elpis.conf
 *   2. /etc/elpis/elpis.conf
 *   3. /etc/elpis.conf
 * The first that exists wins.  A missing file is not an error: the built-in
 * defaults are a working recursive resolver on 127.0.0.1 port 5335.
 */
#ifndef ELPIS_CONF_H
#define ELPIS_CONF_H

#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/dns.h"

#define ELPIS_MAX_LISTEN 16
#define ELPIS_MAX_ACL    64
#define ELPIS_MAX_FORWARD 8
#define ELPIS_MAX_STUB   16

typedef struct {
    elpis_prefix_t prefix;
    uint8_t      allow;
    uint8_t      allow_snoop;   /* may ask with RD clear */
} elpis_acl_t;

typedef struct {
    char         name[ELPIS_MAX_NAME * 4];
    elpis_addr_t addr[8];
    unsigned     naddr;
    uint8_t      is_stub;         /* stub (iterate) vs forward (recurse) */
} elpis_zoneroute_t;

typedef struct {
    /* --- listening ------------------------------------------------ */
    elpis_addr_t listen[ELPIS_MAX_LISTEN];
    unsigned     nlisten;
    uint8_t      listen_udp;
    uint8_t      listen_tcp;
    unsigned     threads;                  /* 0 = one per CPU            */
    unsigned     tcp_max_conn;
    uint32_t     tcp_idle_ms;

    /* --- access control ------------------------------------------- */
    elpis_acl_t  acl[ELPIS_MAX_ACL];
    unsigned     nacl;
    uint8_t      acl_default_allow;

    /* --- cache ---------------------------------------------------- */
    uint64_t     cache_size;               /* 0 = derive from host RAM   */
    uint32_t     cache_min_ttl;
    uint32_t     cache_max_ttl;
    uint32_t     cache_max_neg_ttl;
    uint32_t     cache_min_neg_ttl;
    uint32_t     serve_stale;              /* seconds past expiry        */
    uint32_t     serve_stale_reply_ttl;
    uint8_t      prefetch;
    unsigned     prefetch_pct;             /* refresh under this % of TTL */

    /* --- roots and TLDs ------------------------------------------- */
    char         root_hints[512];
    uint8_t      prime_root;
    uint8_t      probe_roots;       /* latency-rank the roots at startup */
    unsigned     probe_rounds;
    uint32_t     probe_interval;    /* seconds; 0 = once at startup only */
    uint8_t      warm_tlds;
    uint8_t      root_zone_transfer;
    elpis_addr_t root_xfr_addr[4];
    unsigned     n_root_xfr;
    uint32_t     tld_refresh;              /* seconds                    */
    uint32_t     root_refresh;

    /* --- DNSSEC --------------------------------------------------- */
    uint8_t      dnssec;
    uint8_t      dnssec_permissive;    /* log bogus, do not SERVFAIL */
    uint8_t      harden_dnssec_stripped;
    uint8_t      harden_below_nxdomain;
    uint8_t      harden_referral_path;
    char         trust_anchor_file[512];
    uint8_t      alg_mldsa44, alg_mldsa65, alg_mldsa87;
    uint32_t     sig_skew;                 /* tolerated clock skew, secs */

    /* --- DNS64 ---------------------------------------------------- */
    uint8_t      dns64;
    uint8_t      dns64_synth_all;
    elpis_prefix_t dns64_prefix;
    elpis_prefix_t dns64_ignore_aaaa[8];
    unsigned     n_dns64_ignore;

    /* --- resolution ----------------------------------------------- */
    uint16_t     edns_buffer;
    uint16_t     port_lo, port_hi;
    unsigned     out_sockets;
    uint32_t     query_timeout_ms;
    uint32_t     query_total_ms;
    unsigned     max_retries;
    unsigned     max_referrals;
    uint8_t      qname_minimisation;
    uint8_t      qname_min_strict;
    uint8_t      use_cookies;
    uint8_t      require_cookie;    /* answer BADCOOKIE to a bad cookie  */
    uint8_t      use_0x20;
    uint8_t      prefer_ipv6;
    uint8_t      do_ipv4;
    uint8_t      do_ipv6;
    uint8_t      tcp_upstream;
    elpis_addr_t out_src4, out_src6;
    uint8_t      have_src4;
    uint8_t      have_src6;

    /* --- forwarders / stubs --------------------------------------- */
    elpis_zoneroute_t route[ELPIS_MAX_FORWARD + ELPIS_MAX_STUB];
    unsigned     nroute;

    /* --- rate limiting -------------------------------------------- */
    uint32_t     client_qps;               /* 0 = off                    */
    uint32_t     nxdomain_qps;
    uint32_t     max_udp_size_reply;

    /* --- local data ----------------------------------------------- */
    uint8_t      block_private_reverse;   /* RFC 6761 / AS112        */
    uint8_t      refuse_any;              /* RFC 8482                */
    uint8_t      answer_version_bind;

    /* --- process -------------------------------------------------- */
    char         user[64];
    char         group[64];
    char         chroot_dir[512];
    char         pidfile[512];
    uint8_t      daemonize;
    /*
     * Stop systemd-resolved when it holds a port we were told to listen on.
     * Only ever acts on systemd-resolved, and only when running as root.
     */
    uint8_t      stop_systemd_resolved;

    /* --- logging -------------------------------------------------- */
    elpis_loglevel_t log_level;
    elpis_logdst_t   log_dst;
    char         log_file[512];
    uint8_t      log_queries;
    uint8_t      log_replies;
    uint8_t      log_drops;
    char         nsid[128];

    /* --- control -------------------------------------------------- */
    unsigned     stats_interval;           /* seconds, 0 = off           */

    char         path[512];                /* file actually loaded       */
} elpis_conf_t;

void elpis_conf_defaults(elpis_conf_t *c);
/* Returns ELPIS_OK even when no file was found; check c->path[0]. */
int  elpis_conf_load(elpis_conf_t *c, const char *explicit_path);
int  elpis_conf_parse_line(elpis_conf_t *c, char *line, const char *src,
                           unsigned lineno);
void elpis_conf_dump(const elpis_conf_t *c);
/* 1 when `a` may query us; sets *snoop when RD-clear queries are allowed. */
int  elpis_conf_acl_check(const elpis_conf_t *c, const elpis_addr_t *a,
                          int *snoop);

#endif /* ELPIS_CONF_H */
