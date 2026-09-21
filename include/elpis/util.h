/*
 * elpis/util.h -- time, memory, string, address helpers.
 */
#ifndef ELPIS_UTIL_H
#define ELPIS_UTIL_H

#include "elpis/common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ---------------- time -------------------------------------------- */
/* Monotonic clock in milliseconds; never goes backwards, unaffected by NTP. */
uint64_t elpis_now_ms(void);
/* Monotonic seconds -- the TTL time base used throughout the cache. */
uint32_t elpis_now_s(void);
/* Wall-clock seconds since the UNIX epoch (RRSIG inception/expiration). */
int64_t  elpis_wall_s(void);
/* Cheap cached clock, refreshed once per event-loop tick. */
void     elpis_clock_tick(void);
uint32_t elpis_cached_now_s(void);
uint64_t elpis_cached_now_ms(void);

/* ---------------- memory ------------------------------------------ */
void *elpis_malloc(size_t n);
void *elpis_calloc(size_t n, size_t sz);
void *elpis_realloc(void *p, size_t n);
void  elpis_free(void *p);

/* Total usable physical RAM in bytes, or 0 when undiscoverable. */
uint64_t elpis_physical_ram(void);
/* Number of usable CPUs (>= 1). */
unsigned elpis_cpu_count(void);

/* ---------------- strings ----------------------------------------- */
size_t elpis_strlcpy(char *dst, const char *src, size_t sz);
size_t elpis_strlcat(char *dst, const char *src, size_t sz);
/* Trim ASCII whitespace in place; returns pointer into s. */
char  *elpis_strtrim(char *s);
int    elpis_strcasecmp_ascii(const char *a, const char *b);
/* Parse a size with optional K/M/G suffix.  Returns -1 on error. */
int    elpis_parse_size(const char *s, uint64_t *out);
/* Parse a duration with optional s/m/h/d suffix (default seconds). */
int    elpis_parse_duration(const char *s, uint32_t *out);
int    elpis_parse_bool(const char *s, int *out);
int    elpis_parse_u32(const char *s, uint32_t *out);

/* ---------------- addresses --------------------------------------- */
/*
 * A single storage type used everywhere.  We deliberately avoid
 * getaddrinfo()/inet_pton from NSS-backed libc paths so that a static link
 * carries no dlopen() dependency.
 */
typedef struct {
    union {
        struct sockaddr         sa;
        struct sockaddr_in      v4;
        struct sockaddr_in6     v6;
        struct sockaddr_storage ss;
    } u;
    socklen_t len;
} elpis_addr_t;

int  elpis_pton4(const char *s, uint8_t out[4]);
int  elpis_pton6(const char *s, uint8_t out[16]);
int  elpis_ntop4(const uint8_t in[4], char *buf, size_t sz);
int  elpis_ntop6(const uint8_t in[16], char *buf, size_t sz);

/* "1.2.3.4", "[::1]:5353", "::1", "1.2.3.4@5353", "1.2.3.4:5353" */
int  elpis_addr_parse(elpis_addr_t *a, const char *s, uint16_t defport);
int  elpis_addr_from4(elpis_addr_t *a, const uint8_t ip[4], uint16_t port);
int  elpis_addr_from6(elpis_addr_t *a, const uint8_t ip[16], uint16_t port);
const char *elpis_addr_str(const elpis_addr_t *a, char *buf, size_t sz);
int  elpis_addr_eq(const elpis_addr_t *a, const elpis_addr_t *b);
int  elpis_addr_eq_ip(const elpis_addr_t *a, const elpis_addr_t *b);
uint16_t elpis_addr_port(const elpis_addr_t *a);
int  elpis_addr_family(const elpis_addr_t *a);
uint64_t elpis_addr_hash(const elpis_addr_t *a);

/* CIDR prefix container used by access-control and DNS64 config. */
typedef struct {
    uint8_t  ip[16];
    uint8_t  bits;      /* 0..128 (v4 stored as v4-mapped, bits +96)    */
    uint8_t  family;    /* AF_INET / AF_INET6                           */
} elpis_prefix_t;

int elpis_prefix_parse(elpis_prefix_t *p, const char *s);
int elpis_prefix_match(const elpis_prefix_t *p, const elpis_addr_t *a);

/* ---------------- misc -------------------------------------------- */
/* Directory holding the running executable; "" when undiscoverable. */
const char *elpis_exe_dir(void);
/* Full path to the running executable, or "elpis" when undiscoverable. */
const char *elpis_exe_path(void);
/* Highest-quality randomness the platform offers. */
void elpis_random_bytes(void *buf, size_t n);

/* Processor model name, e.g. "AMD Ryzen 9 3950X 16-Core Processor".
 * Empty when the platform will not say. */
void elpis_cpu_model(char *out, size_t outsz);

/* Seconds since the host booted, 0 when the platform will not say.  This is
 * the machine's uptime, not the resolver's: a resolver that restarted an hour
 * ago on a box that has been up for a month is a different story from one
 * where both numbers agree. */
uint64_t elpis_host_uptime(void);

/* Kernel and architecture, e.g. "Linux 7.0.0-31-generic x86_64", and the
 * host's own name.  Either may come back empty.  Both identify the machine
 * rather than the software, so callers must treat them as sensitive: a kernel
 * version is a CVE lookup key and a hostname often describes a network. */
void elpis_os_string(char *out, size_t outsz);

/* The commit this binary was built from, "" outside a git checkout.  Captured
 * by make into a generated header that only util.c includes. */
const char *elpis_build_rev(void);
void elpis_host_name(char *out, size_t outsz);
uint32_t elpis_random_u32(void);
/* Uniform in [0, n) without modulo bias. */
uint32_t elpis_random_below(uint32_t n);

#endif /* ELPIS_UTIL_H */
