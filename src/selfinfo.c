/*
 * selfinfo.c -- what the internet sees this resolver as.
 *
 * The status page shows the public addresses queries leave from and the
 * network they belong to.  Both are found through this resolver's own
 * recursion rather than an HTTP API: the address comes from whoami.akamai.net,
 * which answers with the address of whoever asked, and the network from Team
 * Cymru's IP-to-ASN zone, which is ordinary DNS.  Nothing here reaches outside
 * the resolver's normal path, so it works behind the same firewall rules
 * everything else does, and it is cached like any other answer.
 *
 * Entirely optional.  Every step fails quietly and leaves the fields empty.
 */
#define _POSIX_C_SOURCE 200809L

#include "elpis/resolver.h"
#include "elpis/log.h"
#include "elpis/util.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define REFRESH_MS   3600000u        /* an hour; none of this moves often */
#define FIRST_MS     8000u           /* after priming has settled         */

typedef enum {
    SI_V4 = 0,          /* ask what our public IPv4 is        */
    SI_ORIGIN,          /* which network announces it         */
    SI_ASNAME,          /* and what that network is called    */
    SI_DONE
} si_stage_t;

typedef struct {
    elpis_worker_t *w;
    elpis_timer_t   timer;
    si_stage_t      stage;
    char            asn[20];
} si_state_t;

static ELPIS_TLS si_state_t g_si;

static void si_step(si_state_t *s);
static void si_tick(elpis_loop_t *lp, elpis_timer_t *tm);

/* ------------------------------------------------------------------ */
/* Local outbound addresses                                            */
/* ------------------------------------------------------------------ */

/*
 * Which address would the kernel send from?  A UDP connect() does no I/O, it
 * just runs the route lookup, so this costs nothing.  For IPv6 the answer is
 * normally the public address already; for IPv4 behind NAT it is not, which is
 * why the address is also asked for over DNS.
 */
static int outbound_addr(int family, char *out, size_t outsz)
{
    elpis_addr_t to, me;
    int fd;

    out[0] = '\0';
    if (family == AF_INET) {
        if (elpis_addr_parse(&to, "198.41.0.4@53", 53) != 0)
            return 0;
    } else {
        if (elpis_addr_parse(&to, "[2001:503:ba3e::2:30]@53", 53) != 0)
            return 0;
    }

    fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    if (connect(fd, &to.u.sa, to.len) != 0) {
        close(fd);
        return 0;
    }
    me.len = sizeof me.u.ss;
    if (getsockname(fd, &me.u.sa, &me.len) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    elpis_addr_str(&me, out, outsz);
    {   /* strip the port: "1.2.3.4:53" and "[2001:db8::1]:53" */
        char *p = strrchr(out, ':');
        if (out[0] == '[') {
            char *end = strchr(out, ']');
            if (end != NULL) {
                size_t n = (size_t)(end - out) - 1u;
                memmove(out, out + 1, n);
                out[n] = '\0';
            }
        } else if (p != NULL) {
            *p = '\0';
        }
    }
    return out[0] != '\0';
}

/* Is this an address the rest of the world could route to? */
static int has_prefix(const char *s, const char *p)
{
    size_t i;
    for (i = 0; p[i] != '\0'; i++) {
        int a = (unsigned char)s[i], b = (unsigned char)p[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (a != b)
            return 0;
    }
    return 1;
}

static int is_public_v6(const char *s)
{
    if (s[0] == '\0' || strcmp(s, "::1") == 0)
        return 0;
    if (has_prefix(s, "fe8") || has_prefix(s, "fe9") ||
        has_prefix(s, "fea") || has_prefix(s, "feb"))
        return 0;                       /* link-local   */
    if (has_prefix(s, "fc") || has_prefix(s, "fd"))
        return 0;                       /* unique-local */
    return 1;
}

/* ------------------------------------------------------------------ */
/* Cymru query names                                                   */
/* ------------------------------------------------------------------ */

/* "1.2.3.4" -> "4.3.2.1.origin.asn.cymru.com" */
static int origin4_name(const char *ip, char *out, size_t outsz)
{
    unsigned a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255u || b > 255u || c > 255u || d > 255u)
        return 0;
    return snprintf(out, outsz, "%u.%u.%u.%u.origin.asn.cymru.com",
                    d, c, b, a) < (int)outsz;
}

/* An IPv6 address to its nibble-reversed origin6 name. */
static int origin6_name(const elpis_addr_t *a, char *out, size_t outsz)
{
    static const char hex[] = "0123456789abcdef";
    const uint8_t *b = (const uint8_t *)&a->u.v6.sin6_addr;
    size_t i, n = 0;

    if (outsz < 64u + 24u)
        return 0;
    for (i = 16; i-- > 0; ) {
        out[n++] = hex[b[i] & 0x0Fu];
        out[n++] = '.';
        out[n++] = hex[b[i] >> 4];
        out[n++] = '.';
    }
    out[n] = '\0';
    return (size_t)snprintf(out + n, outsz - n, "origin6.asn.cymru.com") <
           outsz - n;
}

/* ------------------------------------------------------------------ */
/* Reading the answers                                                 */
/* ------------------------------------------------------------------ */

/* First TXT string in the answer, concatenated character-strings. */
static int first_txt(const elpis_task_t *t, char *out, size_t outsz)
{
    unsigned i;

    out[0] = '\0';
    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        const uint8_t *rd;
        size_t pos = 0, n = 0;

        if (rr->type != ELPIS_T_TXT || rr->section != (uint8_t)ELPIS_SEC_ANSWER)
            continue;
        rd = elpis_trr_rd(&t->ans, i);
        while (pos < rr->rdlen) {
            uint8_t l = rd[pos++];
            if (pos + l > rr->rdlen)
                break;
            while (l-- > 0 && n + 1u < outsz)
                out[n++] = (char)rd[pos++];
        }
        out[n] = '\0';
        return n > 0;
    }
    return 0;
}

/* First A record in the answer, as text. */
static int first_a(const elpis_task_t *t, char *out, size_t outsz)
{
    unsigned i;

    out[0] = '\0';
    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        const uint8_t *rd;

        if (rr->type != ELPIS_T_A || rr->rdlen != 4 ||
            rr->section != (uint8_t)ELPIS_SEC_ANSWER)
            continue;
        rd = elpis_trr_rd(&t->ans, i);
        return (size_t)snprintf(out, outsz, "%u.%u.%u.%u",
                                rd[0], rd[1], rd[2], rd[3]) < outsz;
    }
    return 0;
}

/* Cymru answers are " field | field | field "; take one, trimmed. */
static void txt_field(const char *txt, unsigned want, char *out, size_t outsz)
{
    const char *p = txt, *start;
    unsigned f = 0;
    size_t n = 0;

    out[0] = '\0';
    for (;;) {
        while (*p == ' ' || *p == '\t')
            p++;
        start = p;
        while (*p != '\0' && *p != '|')
            p++;
        if (f == want) {
            const char *e = p;
            while (e > start && (e[-1] == ' ' || e[-1] == '\t'))
                e--;
            while (start < e && n + 1u < outsz)
                out[n++] = *start++;
            out[n] = '\0';
            return;
        }
        if (*p == '\0')
            return;
        p++;
        f++;
    }
}

/* ------------------------------------------------------------------ */
/* The walk                                                            */
/* ------------------------------------------------------------------ */

static void si_done(elpis_task_t *child, void *ctx)
{
    si_state_t *s = (si_state_t *)ctx;
    elpis_selfinfo_t *si;
    char txt[512];

    if (s == NULL || s->w == NULL)
        return;
    si = &s->w->ctx->self;

    switch (s->stage) {
    case SI_V4:
        if (child->rcode == ELPIS_RC_NOERROR)
            (void)first_a(child, si->v4, sizeof si->v4);
        s->stage = SI_ORIGIN;
        break;

    case SI_ORIGIN:
        if (child->rcode == ELPIS_RC_NOERROR && first_txt(child, txt, sizeof txt)) {
            txt_field(txt, 0, s->asn, sizeof s->asn);
            snprintf(si->asn, sizeof si->asn, "AS%s", s->asn);
        }
        s->stage = (s->asn[0] != '\0') ? SI_ASNAME : SI_DONE;
        break;

    case SI_ASNAME:
        if (child->rcode == ELPIS_RC_NOERROR && first_txt(child, txt, sizeof txt))
            txt_field(txt, 4, si->asname, sizeof si->asname);
        s->stage = SI_DONE;
        break;

    default:
        s->stage = SI_DONE;
        break;
    }

    si->at_ms = elpis_now_ms();
    si_step(s);
}

static int si_ask(si_state_t *s, const char *name, uint16_t type)
{
    elpis_task_t *t = elpis_task_new(s->w);
    elpis_name_t n;

    if (t == NULL)
        return 0;
    if (elpis_name_from_text(&n, name) != ELPIS_OK) {
        elpis_task_free(t);
        return 0;
    }
    elpis_name_lower(&n);
    t->qname   = n;
    t->qtype   = type;
    t->qclass  = ELPIS_CLASS_IN;
    t->warming = 1;                 /* no client is waiting on this */
    t->done_cb = si_done;
    t->done_ctx = s;
    elpis_task_start(t);
    return 1;
}

static void si_step(si_state_t *s)
{
    elpis_selfinfo_t *si = &s->w->ctx->self;
    char name[160];

    switch (s->stage) {
    case SI_V4:
        if (si_ask(s, "whoami.akamai.net", ELPIS_T_A))
            return;
        s->stage = SI_ORIGIN;
        /* fall through */
    case SI_ORIGIN:
        if (si->v4[0] != '\0' && origin4_name(si->v4, name, sizeof name)) {
            if (si_ask(s, name, ELPIS_T_TXT))
                return;
        } else if (si->v6[0] != '\0') {
            elpis_addr_t a;
            char withport[96];
            snprintf(withport, sizeof withport, "[%s]@53", si->v6);
            if (elpis_addr_parse(&a, withport, 53) == 0 &&
                origin6_name(&a, name, sizeof name) &&
                si_ask(s, name, ELPIS_T_TXT))
                return;
        }
        s->stage = SI_DONE;
        break;

    case SI_ASNAME:
        snprintf(name, sizeof name, "AS%s.asn.cymru.com", s->asn);
        if (si_ask(s, name, ELPIS_T_TXT))
            return;
        s->stage = SI_DONE;
        break;

    default:
        break;
    }

    if (s->stage == SI_DONE) {
        elpis_info("this resolver appears as %s%s%s%s%s",
                   si->v4[0] ? si->v4 : "(no public IPv4)",
                   si->v6[0] ? " / " : "", si->v6,
                   si->asn[0] ? " on " : "",
                   si->asn[0] ? si->asn : "");
        elpis_timer_add(s->w->loop, &s->timer, REFRESH_MS, si_tick, s);
    }
}

static void si_tick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    si_state_t *s = (si_state_t *)tm->data;
    elpis_selfinfo_t *si;

    (void)lp;
    if (s->w->ctx->shutdown)
        return;
    si = &s->w->ctx->self;

    /* The outbound IPv6 source is normally the public one already. */
    {
        char a6[80];
        if (outbound_addr(AF_INET6, a6, sizeof a6) && is_public_v6(a6))
            elpis_strlcpy(si->v6, a6, sizeof si->v6);
    }

    s->stage  = SI_V4;
    s->asn[0] = '\0';
    si_step(s);
}

int elpis_selfinfo_start(elpis_worker_t *w)
{
    if (w->index != 0)
        return ELPIS_OK;            /* one worker is enough */
    memset(&g_si, 0, sizeof g_si);
    g_si.w = w;
    elpis_timer_add(w->loop, &g_si.timer, FIRST_MS, si_tick, &g_si);
    return ELPIS_OK;
}
