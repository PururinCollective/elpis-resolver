/*
 * util.c -- time, memory, string and address helpers.
 *
 * Address parsing is hand-rolled on purpose: inet_pton()/getaddrinfo() drag
 * NSS into a static link on glibc, which defeats the "one portable binary"
 * goal.  The routines below only ever parse literals, never names.
 */
#include "elpis/util.h"
#include "elpis/log.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/sysinfo.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
#  include <sys/sysctl.h>
#endif
#if defined(__APPLE__)
#  include <mach-o/dyld.h>
#endif

/* ================================================================== */
/* Time                                                                */
/* ================================================================== */

#if defined(CLOCK_MONOTONIC)
#  define ELPIS_MONO_CLOCK CLOCK_MONOTONIC
#else
#  define ELPIS_MONO_CLOCK CLOCK_REALTIME
#endif

uint64_t elpis_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(ELPIS_MONO_CLOCK, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

uint32_t elpis_now_s(void)
{
    struct timespec ts;
    if (clock_gettime(ELPIS_MONO_CLOCK, &ts) != 0)
        return 0;
    return (uint32_t)ts.tv_sec;
}

int64_t elpis_wall_s(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (int64_t)time(NULL);
    return (int64_t)ts.tv_sec;
}

/*
 * The event loop calls elpis_clock_tick() once per wakeup.  Hot paths read the
 * cached values instead of issuing a syscall/vDSO call per packet.  The values
 * are written by whichever worker ticks last; a torn read is harmless because
 * both fields are monotonically increasing and only used for TTL arithmetic.
 */
static volatile uint32_t g_cached_s;
static volatile uint64_t g_cached_ms;

void elpis_clock_tick(void)
{
    struct timespec ts;
    if (clock_gettime(ELPIS_MONO_CLOCK, &ts) != 0)
        return;
    g_cached_s  = (uint32_t)ts.tv_sec;
    g_cached_ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

uint32_t elpis_cached_now_s(void)
{
    uint32_t v = g_cached_s;
    return v ? v : elpis_now_s();
}

uint64_t elpis_cached_now_ms(void)
{
    uint64_t v = g_cached_ms;
    return v ? v : elpis_now_ms();
}

/* ================================================================== */
/* Memory                                                              */
/* ================================================================== */

void *elpis_malloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (ELPIS_UNLIKELY(p == NULL))
        elpis_error("out of memory allocating %zu bytes", n);
    return p;
}

void *elpis_calloc(size_t n, size_t sz)
{
    void *p;
    if (n && sz && n > (size_t)-1 / sz) {
        elpis_error("allocation overflow (%zu x %zu)", n, sz);
        return NULL;
    }
    p = calloc(n ? n : 1, sz ? sz : 1);
    if (ELPIS_UNLIKELY(p == NULL))
        elpis_error("out of memory allocating %zu x %zu bytes", n, sz);
    return p;
}

void *elpis_realloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (ELPIS_UNLIKELY(q == NULL))
        elpis_error("out of memory reallocating to %zu bytes", n);
    return q;
}

void elpis_free(void *p)
{
    free(p);
}

/* ------------------------------------------------------------------ */
/* Physical RAM discovery (drives automatic cache sizing)              */
/* ------------------------------------------------------------------ */

#if defined(__linux__)
static uint64_t read_u64_file(const char *path)
{
    char buf[64];
    ssize_t n;
    int fd = open(path, O_RDONLY);
    uint64_t v = 0;
    size_t i;

    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    if (buf[0] < '0' || buf[0] > '9')  /* "max" on cgroup v2 */
        return 0;
    for (i = 0; i < (size_t)n && buf[i] >= '0' && buf[i] <= '9'; i++)
        v = v * 10u + (uint64_t)(buf[i] - '0');
    return v;
}

/*
 * Inside a container the host's RAM is the wrong number to scale by.  Honour
 * cgroup v2 memory.max and v1 memory.limit_in_bytes when they are smaller.
 */
/* MemTotal from /proc/meminfo, in bytes.  Inside an LXC container this is the
 * file lxcfs replaces with the container's own figure, while the sysinfo()
 * syscall behind sysconf(_SC_PHYS_PAGES) still reports the whole host. */
static uint64_t proc_meminfo_total(void)
{
    char buf[2048];
    ssize_t n;
    int fd = open("/proc/meminfo", O_RDONLY);
    const char *p;
    uint64_t kb = 0;

    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';

    p = strstr(buf, "MemTotal:");
    if (p == NULL)
        return 0;
    p += 9;
    while (*p == ' ' || *p == '\t')
        p++;
    for (; *p >= '0' && *p <= '9'; p++)
        kb = kb * 10u + (uint64_t)(*p - '0');
    return kb * 1024u;
}

/* One limit file, keeping the smaller of what we have and what it says. */
static void take_limit(uint64_t *best, const char *path)
{
    uint64_t v = read_u64_file(path);

    /* v1 reports a sentinel close to UINT64_MAX when unlimited. */
    if (v == 0 || v >= ((uint64_t)1 << 62))
        return;
    if (*best == 0 || v < *best)
        *best = v;
}

/*
 * The smallest memory limit that applies to this process.
 *
 * The limit is rarely on the cgroup we are in: a container's is usually set on
 * an ancestor, and reading only /sys/fs/cgroup/memory.max finds it solely when
 * the container also has a cgroup namespace putting it at the root.  Everywhere
 * else -- LXC, Docker under a slice, Kubernetes -- that file does not exist and
 * the whole host's memory is what gets reported.  So take the path from
 * /proc/self/cgroup and walk it upwards, since a limit on any ancestor binds us
 * just as much as one on ourselves.
 */
static uint64_t cgroup_memory_limit(void)
{
    static const char *const v2_root = "/sys/fs/cgroup";
    static const char *const v1_root = "/sys/fs/cgroup/memory";
    char line[4096], path[4096];
    uint64_t best = 0;
    FILE *f;

    /* The namespaced case, where our own cgroup is mounted as the root. */
    take_limit(&best, "/sys/fs/cgroup/memory.max");
    take_limit(&best, "/sys/fs/cgroup/memory/memory.limit_in_bytes");

    f = fopen("/proc/self/cgroup", "r");
    if (f == NULL)
        return best;

    while (fgets(line, (int)sizeof line, f) != NULL) {
        const char *root, *leaf;
        char *rel, *cut;
        size_t len;

        /* "0::<path>" is cgroup v2; "<n>:memory:<path>" is v1. */
        if (strncmp(line, "0::", 3) == 0) {
            rel  = line + 3;
            root = v2_root;
            leaf = "memory.max";
        } else if ((rel = strstr(line, ":memory:")) != NULL) {
            rel += 8;
            root = v1_root;
            leaf = "memory.limit_in_bytes";
        } else {
            continue;
        }

        len = strlen(rel);
        while (len > 0 && (rel[len - 1] == '\n' || rel[len - 1] == '\r'))
            rel[--len] = '\0';
        if (len >= sizeof path / 2u)
            continue;

        for (;;) {
            if (snprintf(path, sizeof path, "%s%s/%s", root, rel, leaf) > 0)
                take_limit(&best, path);
            cut = strrchr(rel, '/');
            if (cut == NULL || cut == rel)
                break;
            *cut = '\0';
        }
    }
    fclose(f);
    return best;
}
#endif

uint64_t elpis_physical_ram(void)
{
    uint64_t bytes = 0;

#if defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
    {
        long pages = sysconf(_SC_PHYS_PAGES);
        long psz   = sysconf(_SC_PAGESIZE);
        if (pages > 0 && psz > 0)
            bytes = (uint64_t)pages * (uint64_t)psz;
    }
#endif

#if defined(__linux__)
    if (bytes == 0) {
        struct sysinfo si;
        if (sysinfo(&si) == 0)
            bytes = (uint64_t)si.totalram * (uint64_t)si.mem_unit;
    }
    {
        /*
         * Every signal is an upper bound, so the smallest one wins.  Trusting
         * sysconf() alone hands a container the whole host's memory, and the
         * cache would then be sized for RAM that is not there to be used.
         */
        uint64_t mi = proc_meminfo_total();
        uint64_t lim = cgroup_memory_limit();
        if (mi != 0 && (bytes == 0 || mi < bytes))
            bytes = mi;
        if (lim != 0 && (bytes == 0 || lim < bytes))
            bytes = lim;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
    if (bytes == 0) {
        int mib[2];
        uint64_t v = 0;
        size_t len = sizeof v;
        mib[0] = CTL_HW;
#  if defined(HW_MEMSIZE)
        mib[1] = HW_MEMSIZE;
#  elif defined(HW_PHYSMEM64)
        mib[1] = HW_PHYSMEM64;
#  else
        mib[1] = HW_PHYSMEM;
#  endif
        if (sysctl(mib, 2, &v, &len, NULL, 0) == 0)
            bytes = v;
    }
#endif
    return bytes;
}

unsigned elpis_cpu_count(void)
{
    long n = -1;
#if defined(_SC_NPROCESSORS_ONLN)
    n = sysconf(_SC_NPROCESSORS_ONLN);
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
    if (n <= 0) {
        int mib[2] = { CTL_HW, HW_NCPU };
        int v = 0;
        size_t len = sizeof v;
        if (sysctl(mib, 2, &v, &len, NULL, 0) == 0)
            n = v;
    }
#endif
    if (n <= 0)
        n = 1;
    if (n > 1024)
        n = 1024;
    return (unsigned)n;
}

/* ================================================================== */
/* Strings                                                             */
/* ================================================================== */

size_t elpis_strlcpy(char *dst, const char *src, size_t sz)
{
    size_t len = strlen(src);
    if (sz != 0) {
        size_t n = (len >= sz) ? sz - 1 : len;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
}

size_t elpis_strlcat(char *dst, const char *src, size_t sz)
{
    size_t dl = 0;
    while (dl < sz && dst[dl] != '\0')
        dl++;
    if (dl == sz)
        return sz + strlen(src);
    return dl + elpis_strlcpy(dst + dl, src, sz - dl);
}

char *elpis_strtrim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        e--;
    *e = '\0';
    return s;
}

/* Locale-independent: the C library's tolower() honours LC_CTYPE. */
int elpis_strcasecmp_ascii(const char *a, const char *b)
{
    for (;;) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == 0)
            return 0;
    }
}

int elpis_parse_u32(const char *s, uint32_t *out)
{
    uint64_t v = 0;
    int digits = 0;
    if (s == NULL)
        return -1;
    while (*s == ' ' || *s == '\t')
        s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (uint64_t)(*s - '0');
        if (v > 0xFFFFFFFFull)
            return -1;
        s++;
        digits++;
    }
    while (*s == ' ' || *s == '\t')
        s++;
    if (!digits || *s != '\0')
        return -1;
    *out = (uint32_t)v;
    return 0;
}

int elpis_parse_size(const char *s, uint64_t *out)
{
    uint64_t v = 0, mul = 1;
    int digits = 0;
    if (s == NULL)
        return -1;
    while (*s == ' ' || *s == '\t')
        s++;
    while (*s >= '0' && *s <= '9') {
        uint64_t nv = v * 10u + (uint64_t)(*s - '0');
        if (nv < v)
            return -1;
        v = nv;
        s++;
        digits++;
    }
    if (!digits)
        return -1;
    switch (*s) {
    case 'k': case 'K': mul = 1024ull; s++; break;
    case 'm': case 'M': mul = 1024ull * 1024; s++; break;
    case 'g': case 'G': mul = 1024ull * 1024 * 1024; s++; break;
    case 't': case 'T': mul = 1024ull * 1024 * 1024 * 1024; s++; break;
    default: break;
    }
    if (*s == 'b' || *s == 'B')
        s++;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s != '\0')
        return -1;
    if (v > (uint64_t)-1 / mul)
        return -1;
    *out = v * mul;
    return 0;
}

int elpis_parse_duration(const char *s, uint32_t *out)
{
    uint64_t v = 0, mul = 1;
    int digits = 0;
    if (s == NULL)
        return -1;
    while (*s == ' ' || *s == '\t')
        s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (uint64_t)(*s - '0');
        if (v > 0xFFFFFFFFull)
            return -1;
        s++;
        digits++;
    }
    if (!digits)
        return -1;
    switch (*s) {
    case 's': case 'S': mul = 1; s++; break;
    case 'm': case 'M': mul = 60; s++; break;
    case 'h': case 'H': mul = 3600; s++; break;
    case 'd': case 'D': mul = 86400; s++; break;
    case 'w': case 'W': mul = 604800; s++; break;
    default: break;
    }
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s != '\0')
        return -1;
    v *= mul;
    if (v > 0xFFFFFFFFull)
        v = 0xFFFFFFFFull;
    *out = (uint32_t)v;
    return 0;
}

int elpis_parse_bool(const char *s, int *out)
{
    if (s == NULL)
        return -1;
    if (!elpis_strcasecmp_ascii(s, "yes")  || !elpis_strcasecmp_ascii(s, "true") ||
        !elpis_strcasecmp_ascii(s, "on")   || !strcmp(s, "1")) {
        *out = 1;
        return 0;
    }
    if (!elpis_strcasecmp_ascii(s, "no")   || !elpis_strcasecmp_ascii(s, "false") ||
        !elpis_strcasecmp_ascii(s, "off")  || !strcmp(s, "0")) {
        *out = 0;
        return 0;
    }
    return -1;
}

int elpis_ct_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    unsigned char d = 0;
    size_t i;
    for (i = 0; i < n; i++)
        d = (unsigned char)(d | (x[i] ^ y[i]));
    return d != 0;
}

/* ================================================================== */
/* Address literals                                                    */
/* ================================================================== */

int elpis_pton4(const char *s, uint8_t out[4])
{
    int octet = 0, val = 0, digits = 0;
    uint8_t tmp[4];

    for (;;) {
        char c = *s++;
        if (c >= '0' && c <= '9') {
            if (digits == 3)
                return -1;
            /* Reject leading zeros: "010" is octal-looking and ambiguous. */
            if (digits == 1 && val == 0)
                return -1;
            val = val * 10 + (c - '0');
            if (val > 255)
                return -1;
            digits++;
        } else if (c == '.' || c == '\0') {
            if (digits == 0 || octet > 3)
                return -1;
            tmp[octet++] = (uint8_t)val;
            val = 0;
            digits = 0;
            if (c == '\0')
                break;
            if (octet == 4)
                return -1;   /* trailing dot */
        } else {
            return -1;
        }
    }
    if (octet != 4)
        return -1;
    memcpy(out, tmp, 4);
    return 0;
}

int elpis_pton6(const char *s, uint8_t out[16])
{
    uint8_t tmp[16];
    int have = 0;          /* bytes written before "::"              */
    int gap  = -1;         /* index where "::" appeared              */
    int tail = 0;          /* bytes written after "::"               */
    uint8_t after[16];
    uint8_t *dst = tmp;
    int *cnt = &have;

    memset(tmp, 0, sizeof tmp);
    memset(after, 0, sizeof after);

    if (s[0] == ':') {
        if (s[1] != ':')
            return -1;
        s += 2;
        gap = 0;
        dst = after;
        cnt = &tail;
        if (*s == '\0')
            goto done;
    }

    for (;;) {
        uint32_t group = 0;
        int digits = 0;
        const char *start = s;

        while (isxdigit((unsigned char)*s)) {
            char c = *s++;
            int d;
            if (c >= '0' && c <= '9')      d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else                           d = c - 'A' + 10;
            group = (group << 4) | (uint32_t)d;
            if (++digits > 4)
                return -1;
        }

        if (*s == '.' && digits > 0) {
            /* Embedded IPv4 tail, e.g. ::ffff:192.0.2.1 */
            uint8_t v4[4];
            if (*cnt + 4 > 16)
                return -1;
            if (elpis_pton4(start, v4) != 0)
                return -1;
            memcpy(dst + *cnt, v4, 4);
            *cnt += 4;
            s = start + strlen(start);
            break;
        }

        if (digits == 0)
            return -1;
        if (*cnt + 2 > 16)
            return -1;
        dst[*cnt]     = (uint8_t)(group >> 8);
        dst[*cnt + 1] = (uint8_t)group;
        *cnt += 2;

        if (*s == '\0')
            break;
        if (*s != ':')
            return -1;
        s++;
        if (*s == ':') {
            if (gap >= 0)
                return -1;        /* only one "::" allowed */
            s++;
            gap = have;
            dst = after;
            cnt = &tail;
            if (*s == '\0')
                break;
        }
    }

done:
    if (gap < 0) {
        if (have != 16)
            return -1;
        memcpy(out, tmp, 16);
        return 0;
    }
    if (have + tail > 14)         /* "::" must stand for >= 1 zero group */
        return -1;
    memset(out, 0, 16);
    memcpy(out, tmp, (size_t)have);
    memcpy(out + 16 - tail, after, (size_t)tail);
    return 0;
}

int elpis_ntop4(const uint8_t in[4], char *buf, size_t sz)
{
    int n = snprintf(buf, sz, "%u.%u.%u.%u", in[0], in[1], in[2], in[3]);
    return (n > 0 && (size_t)n < sz) ? 0 : -1;
}

int elpis_ntop6(const uint8_t in[16], char *buf, size_t sz)
{
    uint16_t g[8];
    int best = -1, bestlen = 0, cur = -1, curlen = 0;
    int i;
    size_t off = 0;

    for (i = 0; i < 8; i++)
        g[i] = (uint16_t)((in[i * 2] << 8) | in[i * 2 + 1]);

    /* Longest run of >= 2 zero groups gets replaced by "::" (RFC 5952). */
    for (i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur < 0) { cur = i; curlen = 1; }
            else           curlen++;
            if (curlen > bestlen) { best = cur; bestlen = curlen; }
        } else {
            cur = -1;
            curlen = 0;
        }
    }
    if (bestlen < 2)
        best = -1;

    for (i = 0; i < 8; i++) {
        int n;
        if (best >= 0 && i == best) {
            n = snprintf(buf + off, sz - off, "::");
            if (n < 0 || (size_t)n >= sz - off) return -1;
            off += (size_t)n;
            i += bestlen - 1;
            continue;
        }
        n = snprintf(buf + off, sz - off, "%s%x",
                     (i > 0 && !(best >= 0 && i == best + bestlen)) ? ":" : "",
                     g[i]);
        if (n < 0 || (size_t)n >= sz - off) return -1;
        off += (size_t)n;
    }
    if (off == 0 && sz > 1) {
        buf[0] = ':'; buf[1] = ':'; buf[2] = '\0';
    }
    return 0;
}

int elpis_addr_from4(elpis_addr_t *a, const uint8_t ip[4], uint16_t port)
{
    memset(a, 0, sizeof *a);
    a->u.v4.sin_family = AF_INET;
    a->u.v4.sin_port   = htons(port);
    memcpy(&a->u.v4.sin_addr, ip, 4);
    a->len = (socklen_t)sizeof(struct sockaddr_in);
    return 0;
}

int elpis_addr_from6(elpis_addr_t *a, const uint8_t ip[16], uint16_t port)
{
    memset(a, 0, sizeof *a);
    a->u.v6.sin6_family = AF_INET6;
    a->u.v6.sin6_port   = htons(port);
    memcpy(&a->u.v6.sin6_addr, ip, 16);
    a->len = (socklen_t)sizeof(struct sockaddr_in6);
    return 0;
}

/*
 * Accepts:  1.2.3.4  1.2.3.4:53  1.2.3.4@53
 *           ::1      [::1]:53    ::1@53      2001:db8::1
 * A bare colon after an IPv6 literal is ambiguous, so v6 needs brackets or '@'.
 */
int elpis_addr_parse(elpis_addr_t *a, const char *s, uint16_t defport)
{
    char host[128];
    const char *pstr = NULL;
    uint16_t port = defport;
    uint8_t ip4[4], ip6[16];
    size_t hl;

    if (s == NULL || *s == '\0')
        return -1;

    if (*s == '[') {
        const char *end = strchr(s, ']');
        if (end == NULL)
            return -1;
        hl = (size_t)(end - s - 1);
        if (hl >= sizeof host)
            return -1;
        memcpy(host, s + 1, hl);
        host[hl] = '\0';
        if (end[1] == ':' || end[1] == '@')
            pstr = end + 2;
        else if (end[1] != '\0')
            return -1;
    } else {
        const char *at = strchr(s, '@');
        const char *colon = strrchr(s, ':');
        const char *sep = NULL;

        if (at != NULL)
            sep = at;
        else if (colon != NULL && strchr(s, ':') == colon)
            sep = colon;      /* single colon => IPv4:port */

        if (sep != NULL) {
            hl = (size_t)(sep - s);
            pstr = sep + 1;
        } else {
            hl = strlen(s);
        }
        if (hl >= sizeof host)
            return -1;
        memcpy(host, s, hl);
        host[hl] = '\0';
    }

    if (pstr != NULL) {
        uint32_t v;
        if (elpis_parse_u32(pstr, &v) != 0 || v == 0 || v > 65535)
            return -1;
        port = (uint16_t)v;
    }

    if (elpis_pton4(host, ip4) == 0)
        return elpis_addr_from4(a, ip4, port);
    if (elpis_pton6(host, ip6) == 0)
        return elpis_addr_from6(a, ip6, port);
    return -1;
}

const char *elpis_addr_str(const elpis_addr_t *a, char *buf, size_t sz)
{
    char ip[64];
    if (a == NULL) {
        elpis_strlcpy(buf, "(null)", sz);
        return buf;
    }
    if (a->u.sa.sa_family == AF_INET) {
        uint8_t raw[4];
        memcpy(raw, &a->u.v4.sin_addr, 4);
        if (elpis_ntop4(raw, ip, sizeof ip) != 0)
            elpis_strlcpy(ip, "?", sizeof ip);
        snprintf(buf, sz, "%s:%u", ip, (unsigned)ntohs(a->u.v4.sin_port));
    } else if (a->u.sa.sa_family == AF_INET6) {
        uint8_t raw[16];
        memcpy(raw, &a->u.v6.sin6_addr, 16);
        if (elpis_ntop6(raw, ip, sizeof ip) != 0)
            elpis_strlcpy(ip, "?", sizeof ip);
        snprintf(buf, sz, "[%s]:%u", ip, (unsigned)ntohs(a->u.v6.sin6_port));
    } else {
        elpis_strlcpy(buf, "(unspec)", sz);
    }
    return buf;
}

int elpis_addr_family(const elpis_addr_t *a)
{
    return a->u.sa.sa_family;
}

uint16_t elpis_addr_port(const elpis_addr_t *a)
{
    if (a->u.sa.sa_family == AF_INET)
        return ntohs(a->u.v4.sin_port);
    if (a->u.sa.sa_family == AF_INET6)
        return ntohs(a->u.v6.sin6_port);
    return 0;
}

int elpis_addr_eq_ip(const elpis_addr_t *a, const elpis_addr_t *b)
{
    if (a->u.sa.sa_family != b->u.sa.sa_family)
        return 0;
    if (a->u.sa.sa_family == AF_INET)
        return memcmp(&a->u.v4.sin_addr, &b->u.v4.sin_addr, 4) == 0;
    if (a->u.sa.sa_family == AF_INET6)
        return memcmp(&a->u.v6.sin6_addr, &b->u.v6.sin6_addr, 16) == 0;
    return 0;
}

int elpis_addr_eq(const elpis_addr_t *a, const elpis_addr_t *b)
{
    return elpis_addr_eq_ip(a, b) && elpis_addr_port(a) == elpis_addr_port(b);
}

uint64_t elpis_addr_hash(const elpis_addr_t *a)
{
    uint64_t h = 0xcbf29ce484222325ull;
    const uint8_t *p;
    size_t n, i;

    if (a->u.sa.sa_family == AF_INET) {
        p = (const uint8_t *)&a->u.v4.sin_addr;
        n = 4;
    } else if (a->u.sa.sa_family == AF_INET6) {
        p = (const uint8_t *)&a->u.v6.sin6_addr;
        n = 16;
    } else {
        return h;
    }
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    h ^= (uint64_t)elpis_addr_port(a);
    h *= 0x100000001b3ull;
    return h;
}

/* ------------------------------------------------------------------ */
/* CIDR prefixes                                                       */
/* ------------------------------------------------------------------ */

int elpis_prefix_parse(elpis_prefix_t *p, const char *s)
{
    char host[128];
    const char *slash = strchr(s, '/');
    size_t hl = slash ? (size_t)(slash - s) : strlen(s);
    uint8_t ip4[4], ip6[16];
    uint32_t bits;

    if (hl >= sizeof host)
        return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';

    memset(p, 0, sizeof *p);

    if (elpis_pton4(host, ip4) == 0) {
        p->family = AF_INET;
        memcpy(p->ip, ip4, 4);
        bits = 32;
        if (slash && (elpis_parse_u32(slash + 1, &bits) != 0 || bits > 32))
            return -1;
        p->bits = (uint8_t)bits;
        return 0;
    }
    if (elpis_pton6(host, ip6) == 0) {
        p->family = AF_INET6;
        memcpy(p->ip, ip6, 16);
        bits = 128;
        if (slash && (elpis_parse_u32(slash + 1, &bits) != 0 || bits > 128))
            return -1;
        p->bits = (uint8_t)bits;
        return 0;
    }
    return -1;
}

int elpis_prefix_match(const elpis_prefix_t *p, const elpis_addr_t *a)
{
    const uint8_t *addr;
    unsigned bytes, rem;

    if (a->u.sa.sa_family != p->family)
        return 0;
    if (p->family == AF_INET)
        addr = (const uint8_t *)&a->u.v4.sin_addr;
    else if (p->family == AF_INET6)
        addr = (const uint8_t *)&a->u.v6.sin6_addr;
    else
        return 0;

    bytes = p->bits / 8u;
    rem   = p->bits % 8u;
    if (bytes && memcmp(addr, p->ip, bytes) != 0)
        return 0;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFFu << (8u - rem));
        if (((addr[bytes] ^ p->ip[bytes]) & mask) != 0)
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Executable location                                                 */
/* ------------------------------------------------------------------ */

static char g_exe_dir[1024];
static char g_exe_path[1024];
static int  g_exe_dir_done;

const char *elpis_exe_path(void)
{
    (void)elpis_exe_dir();            /* fills both */
    return g_exe_path[0] ? g_exe_path : "elpis";
}

const char *elpis_exe_dir(void)
{
    char path[1024];
    ssize_t n = -1;
    char *slash;

    if (g_exe_dir_done)
        return g_exe_dir;
    g_exe_dir_done = 1;
    g_exe_dir[0] = '\0';
    g_exe_path[0] = '\0';

#if defined(__linux__)
    n = readlink("/proc/self/exe", path, sizeof path - 1);
#elif defined(__NetBSD__)
    n = readlink("/proc/curproc/exe", path, sizeof path - 1);
#elif defined(__DragonFly__)
    n = readlink("/proc/curproc/file", path, sizeof path - 1);
#elif defined(__FreeBSD__)
    {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
        size_t len = sizeof path;
        if (sysctl(mib, 4, path, &len, NULL, 0) == 0 && len > 0)
            n = (ssize_t)(len - 1);
    }
#elif defined(__APPLE__)
    {
        uint32_t len = (uint32_t)sizeof path;
        if (_NSGetExecutablePath(path, &len) == 0)
            n = (ssize_t)strlen(path);
    }
#endif

    if (n <= 0)
        return g_exe_dir;
    path[n] = '\0';
    elpis_strlcpy(g_exe_path, path, sizeof g_exe_path);
    slash = strrchr(path, '/');
    if (slash == NULL)
        return g_exe_dir;
    *slash = '\0';
    elpis_strlcpy(g_exe_dir, path, sizeof g_exe_dir);
    return g_exe_dir;
}
