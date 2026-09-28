/*
 * elpis/ecs.h -- EDNS Client Subnet (RFC 7871).
 *
 * A content network that picks a server by who is asking only ever sees the
 * resolver's address.  That is the right answer when the resolver sits beside
 * its clients and the wrong one when it does not: a forwarder in Malaysia that
 * sends half its questions to a resolver in Singapore gets Singapore's edge
 * for them.  ECS carries part of the client's address -- a /24 or a /56, never
 * the whole of it -- so the authority can answer for where the client is.
 *
 * The option, on the wire:
 *
 *   FAMILY (2)  SOURCE PREFIX-LENGTH (1)  SCOPE PREFIX-LENGTH (1)  ADDRESS
 *
 * ADDRESS is the prefix only, in as few octets as SOURCE needs, with every bit
 * past SOURCE zero.  SCOPE is the authority's reply: how much of the address
 * its answer actually depended on.  0 means "the same for everyone", and only
 * an answer with a SCOPE above 0 is tailored and has to be cached per subnet.
 */
#ifndef ELPIS_ECS_H
#define ELPIS_ECS_H

#include "elpis/common.h"
#include "elpis/util.h"

#define ELPIS_ECS_IPV4  1u      /* IANA address family numbers */
#define ELPIS_ECS_IPV6  2u

/* Octets of ADDRESS that a prefix of `bits` takes on the wire. */
#define ELPIS_ECS_ADDRLEN(bits) (((unsigned)(bits) + 7u) / 8u)
/* The whole option, header included, for a prefix of `bits`. */
#define ELPIS_ECS_OPTLEN(bits)  (4u + 4u + ELPIS_ECS_ADDRLEN(bits))

typedef struct {
    uint8_t family;         /* ELPIS_ECS_IPV4, ELPIS_ECS_IPV6, or 0 for none */
    uint8_t source;         /* SOURCE PREFIX-LENGTH                        */
    uint8_t scope;          /* SCOPE PREFIX-LENGTH                         */
    uint8_t addr[16];       /* the prefix; every bit past `source` is zero */
} elpis_ecs_t;

/*
 * Read the option data (without its code and length).  Returns ELPIS_OK, or
 * ELPIS_EFORMAT for anything RFC 7871 says to refuse: an unknown
 * family, a prefix longer than the family, more address octets than the
 * prefix needs, or bits set past it.  FAMILY 0 with both prefixes 0 and no
 * address is accepted as "no subnet", which older dig sends for +subnet=0.
 */
int  elpis_ecs_parse(elpis_ecs_t *e, const uint8_t *p, size_t len);

/* Append the option data -- FAMILY through ADDRESS -- to `out`.  Returns the
 * octets written, or 0 when `cap` is too small. */
size_t elpis_ecs_encode(const elpis_ecs_t *e, uint8_t *out, size_t cap);

/*
 * The subnet of `a` cut to `v4bits` or `v6bits`.  An IPv4-mapped IPv6 address
 * counts as the IPv4 address it carries.  Returns 0, leaving e->family 0, for
 * an address of any other family.
 */
int  elpis_ecs_from_addr(elpis_ecs_t *e, const elpis_addr_t *a,
                         unsigned v4bits, unsigned v6bits);

/* `in` cut down to at most `v4bits` or `v6bits` of prefix; SCOPE is cleared. */
void elpis_ecs_truncate(elpis_ecs_t *out, const elpis_ecs_t *in,
                        unsigned v4bits, unsigned v6bits);

/*
 * Is the subnet worth sending to an authority?  Not when it is empty, or
 * inside any range that does not say where on the internet a client is:
 * private, shared (CGNAT), loopback, link-local, unique-local, documentation,
 * multicast and the like.  An authority can place none of those, and the
 * resolver's own address says more.  Test a client's whole address, before
 * elpis_ecs_truncate(): cut short, a private address can land in a prefix
 * that also holds public ones.
 */
int  elpis_ecs_is_public(const elpis_ecs_t *e);

/* Same FAMILY, SOURCE and ADDRESS; SCOPE is not compared. */
int  elpis_ecs_same_subnet(const elpis_ecs_t *a, const elpis_ecs_t *b);

/* "203.0.113.0/24" or "2001:db8::/56", for logs. */
const char *elpis_ecs_str(const elpis_ecs_t *e, char *buf, size_t sz);

#endif /* ELPIS_ECS_H */
