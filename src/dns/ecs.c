/*
 * ecs.c -- EDNS Client Subnet (RFC 7871): the option and the subnets in it.
 *
 * What to send and when is the resolver's business (outbound.c, server.c);
 * this file only knows the option's shape and which addresses mean anything.
 */
#include "elpis/ecs.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

static unsigned family_bits(unsigned family)
{
    return family == ELPIS_ECS_IPV4 ? 32u : family == ELPIS_ECS_IPV6 ? 128u : 0u;
}

/* Zero every bit of `addr` past `bits`. */
static void mask_addr(uint8_t addr[16], unsigned bits)
{
    unsigned i;

    for (i = 0; i < 16u; i++) {
        if (bits >= 8u) {
            bits -= 8u;
            continue;
        }
        addr[i] &= (uint8_t)(0xFFu << (8u - bits));
        bits = 0;
    }
}

int elpis_ecs_parse(elpis_ecs_t *e, const uint8_t *p, size_t len)
{
    unsigned family, n, width;

    memset(e, 0, sizeof *e);
    if (len < 4)
        return ELPIS_EFORMAT;
    family    = elpis_get16(p);
    e->source = p[2];
    e->scope  = p[3];
    n         = (unsigned)(len - 4u);

    if (family == 0) {
        /* The "+subnet=0" shape: nothing to use, nothing to refuse. */
        if (e->source != 0 || e->scope != 0 || n != 0)
            return ELPIS_EFORMAT;
        return ELPIS_OK;
    }
    width = family_bits(family);
    if (width == 0 || e->source > width || e->scope > width)
        return ELPIS_EFORMAT;
    if (n != ELPIS_ECS_ADDRLEN(e->source))
        return ELPIS_EFORMAT;
    e->family = (uint8_t)family;
    memcpy(e->addr, p + 4, n);
    {
        uint8_t check[16];
        memcpy(check, e->addr, sizeof check);
        mask_addr(check, e->source);
        if (memcmp(check, e->addr, sizeof check) != 0)
            return ELPIS_EFORMAT;       /* bits set past SOURCE */
    }
    return ELPIS_OK;
}

size_t elpis_ecs_encode(const elpis_ecs_t *e, uint8_t *out, size_t cap)
{
    unsigned n = ELPIS_ECS_ADDRLEN(e->source);

    if (cap < 4u + n)
        return 0;
    /* A subnet of no family goes out as IPv4 /0: nothing to reveal, in the
     * shape every server reads. */
    elpis_put16(out, (uint16_t)(e->family ? e->family : ELPIS_ECS_IPV4));
    out[2] = e->source;
    out[3] = e->scope;
    memcpy(out + 4, e->addr, n);
    return 4u + n;
}

int elpis_ecs_from_addr(elpis_ecs_t *e, const elpis_addr_t *a,
                        unsigned v4bits, unsigned v6bits)
{
    memset(e, 0, sizeof *e);
    if (a->u.sa.sa_family == AF_INET) {
        memcpy(e->addr, &a->u.v4.sin_addr, 4);
        e->family = ELPIS_ECS_IPV4;
    } else if (a->u.sa.sa_family == AF_INET6) {
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0xFF, 0xFF };
        const uint8_t *b = (const uint8_t *)&a->u.v6.sin6_addr;
        if (memcmp(b, mapped, sizeof mapped) == 0) {
            memcpy(e->addr, b + 12, 4);
            e->family = ELPIS_ECS_IPV4;
        } else {
            memcpy(e->addr, b, 16);
            e->family = ELPIS_ECS_IPV6;
        }
    } else {
        return 0;
    }
    e->source = (uint8_t)(e->family == ELPIS_ECS_IPV4
                              ? (v4bits > 32u ? 32u : v4bits)
                              : (v6bits > 128u ? 128u : v6bits));
    mask_addr(e->addr, e->source);
    return 1;
}

void elpis_ecs_truncate(elpis_ecs_t *out, const elpis_ecs_t *in,
                        unsigned v4bits, unsigned v6bits)
{
    unsigned cap = in->family == ELPIS_ECS_IPV4 ? v4bits : v6bits;

    *out = *in;
    out->scope = 0;
    if (out->source > cap)
        out->source = (uint8_t)cap;
    mask_addr(out->addr, out->source);
}

/* Does `addr` fall inside prefix `p`/`bits`?  Only the first 16 octets. */
static int in_range(const uint8_t *addr, const uint8_t *p, unsigned bits)
{
    unsigned i;

    for (i = 0; bits > 0; i++) {
        uint8_t m = bits >= 8u ? 0xFFu : (uint8_t)(0xFFu << (8u - bits));
        if ((addr[i] & m) != (p[i] & m))
            return 0;
        bits = bits >= 8u ? bits - 8u : 0u;
    }
    return 1;
}

int elpis_ecs_is_public(const elpis_ecs_t *e)
{
    /* Ranges that do not place a client anywhere.  RFC 6890 and friends. */
    static const struct { uint8_t p[4]; uint8_t bits; } v4[] = {
        { { 0, 0, 0, 0 },       8 },    /* "this network"        */
        { { 10, 0, 0, 0 },      8 },    /* private               */
        { { 100, 64, 0, 0 },   10 },    /* shared / CGNAT        */
        { { 127, 0, 0, 0 },     8 },    /* loopback              */
        { { 169, 254, 0, 0 },  16 },    /* link-local            */
        { { 172, 16, 0, 0 },   12 },    /* private               */
        { { 192, 0, 0, 0 },    24 },    /* IETF protocol use     */
        { { 192, 0, 2, 0 },    24 },    /* documentation         */
        { { 192, 168, 0, 0 },  16 },    /* private               */
        { { 198, 18, 0, 0 },   15 },    /* benchmarking          */
        { { 198, 51, 100, 0 }, 24 },    /* documentation         */
        { { 203, 0, 113, 0 },  24 },    /* documentation         */
        { { 224, 0, 0, 0 },     3 },    /* multicast and class E */
    };
    static const uint8_t unicast6[1] = { 0x20 };                 /* 2000::/3     */
    static const uint8_t doc6[4]     = { 0x20, 0x01, 0x0D, 0xB8 }; /* 2001:db8::/32 */
    unsigned i;

    if (e->source == 0)
        return 0;
    if (e->family == ELPIS_ECS_IPV4) {
        for (i = 0; i < ELPIS_ARRAY_LEN(v4); i++)
            if (e->source >= v4[i].bits && in_range(e->addr, v4[i].p, v4[i].bits))
                return 0;
        return 1;
    }
    /*
     * IPv6 is simpler the other way round: everything routable is global
     * unicast, 2000::/3.  Loopback, unique-local, link-local, multicast and
     * the mapped and translated forms of IPv4 are all outside it.
     */
    if (e->family == ELPIS_ECS_IPV6)
        return e->source >= 3u && in_range(e->addr, unicast6, 3) &&
               !(e->source >= 32u && in_range(e->addr, doc6, 32));
    return 0;
}

int elpis_ecs_same_subnet(const elpis_ecs_t *a, const elpis_ecs_t *b)
{
    return a->family == b->family && a->source == b->source &&
           memcmp(a->addr, b->addr, ELPIS_ECS_ADDRLEN(a->source)) == 0;
}

const char *elpis_ecs_str(const elpis_ecs_t *e, char *buf, size_t sz)
{
    char ip[64];

    if (e->family == ELPIS_ECS_IPV4)
        elpis_ntop4(e->addr, ip, sizeof ip);
    else if (e->family == ELPIS_ECS_IPV6)
        elpis_ntop6(e->addr, ip, sizeof ip);
    else
        elpis_strlcpy(ip, "0.0.0.0", sizeof ip);
    snprintf(buf, sz, "%s/%u", ip, (unsigned)e->source);
    return buf;
}
