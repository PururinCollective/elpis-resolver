/*
 * name.c -- DNS owner name handling.
 *
 * Every parser here is total: it either produces a valid name or fails with a
 * drop reason.  No path can produce an over-long name, an over-long label, or
 * follow an unbounded compression chain.
 */
#include "elpis/name.h"
#include "elpis/simd.h"
#include "elpis/log.h"
#include "elpis/util.h"

const elpis_name_t elpis_name_root = { 1, 0, { 0 } };

void elpis_name_init_root(elpis_name_t *n)
{
    memset(n, 0, sizeof *n);
    n->len    = 1;
    n->labels = 0;
}

/* ------------------------------------------------------------------ */
/* Wire parsing                                                        */
/* ------------------------------------------------------------------ */

int elpis_name_parse(elpis_name_t *n, const uint8_t *msg, size_t msglen,
                     size_t off, size_t *end, int *drop)
{
    size_t out = 0;
    unsigned labels = 0;
    int jumps = 0;
    size_t first_end = 0;
    size_t limit = off;      /* pointers must strictly decrease */

    if (drop) *drop = ELPIS_DROP_NAME;

    for (;;) {
        uint8_t c;

        if (off >= msglen)
            return ELPIS_EFORMAT;
        c = msg[off];

        if ((c & 0xC0u) == 0xC0u) {
            size_t target;
            if (off + 1 >= msglen)
                return ELPIS_EFORMAT;
            target = (size_t)((c & 0x3Fu) << 8) | msg[off + 1];
            if (!first_end)
                first_end = off + 2;
            /*
             * A pointer must aim strictly backwards.  That single rule makes
             * every chain finite; the jump counter is belt-and-braces against
             * a pathological but legal ladder of 16k single-byte hops.
             */
            if (target >= limit) {
                if (drop) *drop = ELPIS_DROP_COMPRESS;
                return ELPIS_EFORMAT;
            }
            if (++jumps > ELPIS_MAX_LABELS) {
                if (drop) *drop = ELPIS_DROP_COMPRESS;
                return ELPIS_EFORMAT;
            }
            limit = target;
            off   = target;
            continue;
        }
        if ((c & 0xC0u) != 0) {
            /* 0x40 and 0x80 label types were never deployed (RFC 6891 §6.2). */
            if (drop) *drop = ELPIS_DROP_NAME;
            return ELPIS_EFORMAT;
        }

        if (c == 0) {
            if (out + 1 > ELPIS_MAX_NAME)
                return ELPIS_EFORMAT;
            n->d[out++] = 0;
            if (!first_end)
                first_end = off + 1;
            break;
        }

        if (c > ELPIS_MAX_LABEL)
            return ELPIS_EFORMAT;
        if (off + 1 + c > msglen)
            return ELPIS_EFORMAT;
        /* +1 for the root label that still has to fit. */
        if (out + 1 + c + 1 > ELPIS_MAX_NAME)
            return ELPIS_EFORMAT;
        if (++labels > ELPIS_MAX_LABELS)
            return ELPIS_EFORMAT;

        n->d[out++] = c;
        memcpy(n->d + out, msg + off + 1, c);
        out += c;
        off += 1 + (size_t)c;
    }

    memset(n->d + out, 0, ELPIS_NAME_PAD);
    n->len    = (uint8_t)out;
    n->labels = (uint8_t)labels;
    if (end)
        *end = first_end;
    if (drop) *drop = ELPIS_DROP_NONE;
    return ELPIS_OK;
}

int elpis_name_parse_nocomp(elpis_name_t *n, const uint8_t *p, size_t len,
                            size_t *used)
{
    size_t off = 0, out = 0;
    unsigned labels = 0;

    for (;;) {
        uint8_t c;
        if (off >= len)
            return ELPIS_EFORMAT;
        c = p[off];
        if ((c & 0xC0u) != 0)
            return ELPIS_EFORMAT;       /* compression is not allowed here */
        if (c == 0) {
            if (out + 1 > ELPIS_MAX_NAME)
                return ELPIS_EFORMAT;
            n->d[out++] = 0;
            off++;
            break;
        }
        if (c > ELPIS_MAX_LABEL || off + 1 + c > len)
            return ELPIS_EFORMAT;
        if (out + 1 + c + 1 > ELPIS_MAX_NAME)
            return ELPIS_EFORMAT;
        if (++labels > ELPIS_MAX_LABELS)
            return ELPIS_EFORMAT;
        n->d[out++] = c;
        memcpy(n->d + out, p + off + 1, c);
        out += c;
        off += 1 + (size_t)c;
    }
    memset(n->d + out, 0, ELPIS_NAME_PAD);
    n->len    = (uint8_t)out;
    n->labels = (uint8_t)labels;
    if (used)
        *used = off;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Presentation format                                                 */
/* ------------------------------------------------------------------ */

int elpis_name_from_text(elpis_name_t *n, const char *s)
{
    size_t out = 0;
    unsigned labels = 0;
    size_t lenpos;

    if (s == NULL)
        return ELPIS_EFORMAT;
    if (s[0] == '.' && s[1] == '\0') {
        elpis_name_init_root(n);
        return ELPIS_OK;
    }
    if (s[0] == '\0')
        return ELPIS_EFORMAT;

    lenpos = out++;
    n->d[lenpos] = 0;

    while (*s != '\0') {
        uint8_t ch = (uint8_t)*s++;

        if (ch == '.') {
            if (n->d[lenpos] == 0)
                return ELPIS_EFORMAT;      /* empty label */
            if (++labels > ELPIS_MAX_LABELS)
                return ELPIS_EFORMAT;
            if (*s == '\0')
                break;
            if (out + 1 >= ELPIS_MAX_NAME)
                return ELPIS_EFORMAT;
            lenpos = out++;
            n->d[lenpos] = 0;
            continue;
        }

        if (ch == '\\') {
            uint8_t c0 = (uint8_t)*s;
            if (c0 >= '0' && c0 <= '9') {
                unsigned v;
                if (!(s[1] >= '0' && s[1] <= '9') || !(s[2] >= '0' && s[2] <= '9'))
                    return ELPIS_EFORMAT;
                v = (unsigned)(s[0] - '0') * 100u +
                    (unsigned)(s[1] - '0') * 10u  +
                    (unsigned)(s[2] - '0');
                if (v > 255)
                    return ELPIS_EFORMAT;
                ch = (uint8_t)v;
                s += 3;
            } else if (c0 == '\0') {
                return ELPIS_EFORMAT;
            } else {
                ch = c0;
                s++;
            }
        }

        if (n->d[lenpos] >= ELPIS_MAX_LABEL)
            return ELPIS_EFORMAT;
        if (out + 2 > ELPIS_MAX_NAME)       /* byte + root label */
            return ELPIS_EFORMAT;
        n->d[out++] = ch;
        n->d[lenpos]++;
    }

    if (n->d[lenpos] == 0)
        return ELPIS_EFORMAT;
    /*
     * Count labels from the wire form rather than tracking separators: it is
     * the same answer whether or not the text had a trailing dot.
     */
    {
        size_t i = 0;
        labels = 0;
        while (i < out) {
            labels++;
            i += 1 + (size_t)n->d[i];
        }
        if (i != out)
            return ELPIS_EFORMAT;
    }
    if (out + 1 > ELPIS_MAX_NAME)
        return ELPIS_EFORMAT;
    n->d[out++] = 0;

    memset(n->d + out, 0, ELPIS_NAME_PAD);
    n->len    = (uint8_t)out;
    n->labels = (uint8_t)labels;
    return ELPIS_OK;
}

int elpis_name_to_text(const elpis_name_t *n, char *buf, size_t sz)
{
    size_t i = 0, o = 0;

    if (sz < 2)
        return ELPIS_ETRUNC;
    if (n->len <= 1) {
        buf[0] = '.';
        buf[1] = '\0';
        return ELPIS_OK;
    }
    while (i < (size_t)n->len && n->d[i] != 0) {
        unsigned l = n->d[i++];
        unsigned k;
        for (k = 0; k < l; k++) {
            uint8_t c = n->d[i + k];
            if (c == '.' || c == '\\' || c == ';' || c == '(' || c == ')' ||
                c == '"' || c == '@' || c == '$') {
                if (o + 2 >= sz) return ELPIS_ETRUNC;
                buf[o++] = '\\';
                buf[o++] = (char)c;
            } else if (c > 0x20 && c < 0x7F) {
                if (o + 1 >= sz) return ELPIS_ETRUNC;
                buf[o++] = (char)c;
            } else {
                if (o + 4 >= sz) return ELPIS_ETRUNC;
                buf[o++] = '\\';
                buf[o++] = (char)('0' + (c / 100));
                buf[o++] = (char)('0' + ((c / 10) % 10));
                buf[o++] = (char)('0' + (c % 10));
            }
        }
        i += l;
        if (o + 1 >= sz) return ELPIS_ETRUNC;
        buf[o++] = '.';
    }
    buf[o] = '\0';
    return ELPIS_OK;
}

const char *elpis_name_str(const elpis_name_t *n, char *buf, size_t sz)
{
    if (n == NULL || elpis_name_to_text(n, buf, sz) != ELPIS_OK)
        elpis_strlcpy(buf, "<bad-name>", sz);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Folding, hashing, comparison                                        */
/* ------------------------------------------------------------------ */

void elpis_name_lower(elpis_name_t *n)
{
    /*
     * Label length bytes are 1..63 and so are never in 'A'..'Z' (0x41..0x5A).
     * That means the whole buffer can be folded in one pass without walking
     * label boundaries -- the length octets are provably unaffected.
     */
    ELPIS_CTASSERT(ELPIS_MAX_LABEL < 0x41);
    elpis_lower_pad16(n->d, n->d, ((size_t)n->len + 15u) & ~(size_t)15u);
}

uint64_t elpis_name_hash(const elpis_name_t *n)
{
    return elpis_simd_hash_ci(n->d, n->len, 0x9E3779B97F4A7C15ull);
}

int elpis_name_eq(const elpis_name_t *a, const elpis_name_t *b)
{
    if (a->len != b->len)
        return 0;
    return elpis_eq_ci(a->d, b->d, a->len);
}

/*
 * These three are routinely called in place (name_parent(&x, &x) to walk up a
 * name), so the copies must be memmove: the ranges overlap by construction.
 */
int elpis_name_parent(const elpis_name_t *n, elpis_name_t *out)
{
    unsigned l;
    if (n->len <= 1)
        return -1;
    l = n->d[0];
    if ((size_t)1 + l >= (size_t)n->len + 1u)
        return -1;
    memmove(out->d, n->d + 1 + l, (size_t)n->len - 1 - l);
    out->len    = (uint8_t)(n->len - 1 - l);
    out->labels = (uint8_t)(n->labels - 1);
    memset(out->d + out->len, 0, ELPIS_NAME_PAD);
    return 0;
}

int elpis_name_suffix(const elpis_name_t *n, unsigned keep, elpis_name_t *out)
{
    size_t i = 0;
    unsigned drop_labels;

    if (keep >= n->labels) {
        *out = *n;
        return 0;
    }
    drop_labels = n->labels - keep;
    while (drop_labels-- > 0) {
        if (i >= n->len || n->d[i] == 0)
            return -1;
        i += 1 + (size_t)n->d[i];
    }
    if (i >= (size_t)n->len)
        return -1;
    memmove(out->d, n->d + i, (size_t)n->len - i);
    out->len    = (uint8_t)((size_t)n->len - i);
    out->labels = (uint8_t)keep;
    memset(out->d + out->len, 0, ELPIS_NAME_PAD);
    return 0;
}

int elpis_name_covers(const elpis_name_t *zone, const elpis_name_t *name)
{
    elpis_name_t tail;

    if (zone->labels > name->labels)
        return 0;
    if (elpis_name_suffix(name, zone->labels, &tail) != 0)
        return 0;
    return elpis_name_eq(&tail, zone);
}

int elpis_name_is_subdomain(const elpis_name_t *sub, const elpis_name_t *parent)
{
    size_t off;
    if (parent->len > sub->len)
        return 0;
    if (parent->len == 1)
        return 1;                       /* everything is under the root */
    if (sub->labels < parent->labels)
        return 0;
    off = (size_t)sub->len - parent->len;
    /*
     * The suffix must start on a label boundary, otherwise "notexample.com"
     * would test as a subdomain of "example.com".
     */
    {
        size_t i = 0;
        while (i < off) {
            if (sub->d[i] == 0)
                return 0;
            i += 1 + (size_t)sub->d[i];
        }
        if (i != off)
            return 0;
    }
    return elpis_eq_ci(sub->d + off, parent->d, parent->len);
}

unsigned elpis_name_common_labels(const elpis_name_t *a, const elpis_name_t *b)
{
    elpis_name_t x = *a, y = *b;

    /* Trim the deeper name until both have the same label count... */
    while (x.labels > y.labels && elpis_name_parent(&x, &x) == 0)
        ;
    while (y.labels > x.labels && elpis_name_parent(&y, &y) == 0)
        ;
    /* ...then climb together until they coincide. */
    while (x.len > 1 && y.len > 1) {
        if (elpis_name_eq(&x, &y))
            return x.labels;
        if (elpis_name_parent(&x, &x) != 0) break;
        if (elpis_name_parent(&y, &y) != 0) break;
    }
    return 0;   /* only the root in common */
}

int elpis_name_prepend(elpis_name_t *out, const uint8_t *label, size_t llen,
                       const elpis_name_t *parent)
{
    if (llen == 0 || llen > ELPIS_MAX_LABEL)
        return ELPIS_EFORMAT;
    if (1 + llen + (size_t)parent->len > ELPIS_MAX_NAME)
        return ELPIS_EFORMAT;
    if (parent->labels + 1u > ELPIS_MAX_LABELS)
        return ELPIS_EFORMAT;
    /* Shift the parent up first: out and parent may be the same object. */
    memmove(out->d + 1 + llen, parent->d, parent->len);
    memmove(out->d + 1, label, llen);
    out->d[0] = (uint8_t)llen;
    out->len    = (uint8_t)(1 + llen + parent->len);
    out->labels = (uint8_t)(parent->labels + 1);
    memset(out->d + out->len, 0, ELPIS_NAME_PAD);
    return ELPIS_OK;
}

int elpis_name_substitute(const elpis_name_t *n, const elpis_name_t *owner,
                          const elpis_name_t *target, elpis_name_t *out)
{
    size_t prefix;
    unsigned prefix_labels;

    if (!elpis_name_is_subdomain(n, owner))
        return ELPIS_EFORMAT;
    prefix = (size_t)n->len - owner->len;
    prefix_labels = (unsigned)(n->labels - owner->labels);
    if (prefix + target->len > ELPIS_MAX_NAME)
        return ELPIS_EFORMAT;            /* RFC 6672: answer YXDOMAIN */
    if (prefix_labels + target->labels > ELPIS_MAX_LABELS)
        return ELPIS_EFORMAT;
    memmove(out->d + prefix, target->d, target->len);
    memmove(out->d, n->d, prefix);
    out->len    = (uint8_t)(prefix + target->len);
    out->labels = (uint8_t)(prefix_labels + target->labels);
    memset(out->d + out->len, 0, ELPIS_NAME_PAD);
    return ELPIS_OK;
}

/*
 * RFC 4034 section 6.1: sort by label, right to left, each label compared as
 * unsigned octets after case folding, shorter label sorting first.
 */
int elpis_name_canon_cmp(const elpis_name_t *a, const elpis_name_t *b)
{
    size_t ao[ELPIS_MAX_LABELS], bo[ELPIS_MAX_LABELS];
    unsigned an = 0, bn = 0;
    size_t i;
    unsigned k;

    for (i = 0; i < (size_t)a->len && a->d[i] != 0 && an < ELPIS_MAX_LABELS; ) {
        ao[an++] = i;
        i += 1 + (size_t)a->d[i];
    }
    for (i = 0; i < (size_t)b->len && b->d[i] != 0 && bn < ELPIS_MAX_LABELS; ) {
        bo[bn++] = i;
        i += 1 + (size_t)b->d[i];
    }

    for (k = 0; k < an && k < bn; k++) {
        const uint8_t *pa = a->d + ao[an - 1 - k];
        const uint8_t *pb = b->d + bo[bn - 1 - k];
        unsigned la = pa[0], lb = pb[0];
        unsigned m = la < lb ? la : lb;
        unsigned j;
        for (j = 0; j < m; j++) {
            uint8_t ca = pa[1 + j], cb = pb[1 + j];
            if (ca >= 'A' && ca <= 'Z') ca = (uint8_t)(ca + 32);
            if (cb >= 'A' && cb <= 'Z') cb = (uint8_t)(cb + 32);
            if (ca != cb)
                return ca < cb ? -1 : 1;
        }
        if (la != lb)
            return la < lb ? -1 : 1;
    }
    if (an == bn)
        return 0;
    return an < bn ? -1 : 1;
}

int elpis_name_is_wildcard(const elpis_name_t *n)
{
    return n->len >= 3 && n->d[0] == 1 && n->d[1] == '*';
}
