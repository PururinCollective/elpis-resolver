/*
 * edns.c -- OPT record assembly.
 */
#include "elpis/edns.h"
#include "elpis/log.h"

void elpis_edns_init(elpis_edns_t *e, uint16_t bufsize, int do_bit)
{
    memset(e, 0, sizeof *e);
    e->bufsize  = bufsize;
    e->do_bit   = do_bit ? 1u : 0u;
    e->ede_code = -1;
}

uint16_t elpis_edns_for_mtu(unsigned mtu, int family)
{
    unsigned hdr = (family == AF_INET6) ? 48u : 28u;   /* IP + UDP */
    unsigned v;

    if (mtu <= hdr + ELPIS_MAX_UDP_LEGACY)
        return ELPIS_MAX_UDP_LEGACY;
    v = mtu - hdr;
    if (v > ELPIS_EDNS_DEFAULT)
        v = ELPIS_EDNS_DEFAULT;
    return (uint16_t)v;
}

int elpis_edns_write(elpis_bld_t *b, const elpis_edns_t *e, unsigned rcode)
{
    size_t rdlen_pos;
    uint32_t ttl;
    elpis_name_t root;
    size_t start = b->len;

    elpis_name_init_root(&root);

    /* TTL field of OPT: extended-rcode | version | flags */
    ttl = ((uint32_t)(rcode >> 4) << 24) |
          ((uint32_t)ELPIS_EDNS_VERSION << 16) |
          (uint32_t)(e->do_bit ? ELPIS_EDNS_DO : 0);

    if (elpis_bld_name_raw(b, &root) != ELPIS_OK) goto trunc;
    if (elpis_bld_u16(b, ELPIS_T_OPT) != ELPIS_OK) goto trunc;
    if (elpis_bld_u16(b, e->bufsize) != ELPIS_OK)  goto trunc;
    if (elpis_bld_u32(b, ttl) != ELPIS_OK)         goto trunc;
    rdlen_pos = b->len;
    if (elpis_bld_u16(b, 0) != ELPIS_OK)           goto trunc;

    if (e->have_cookie && e->cookie_len) {
        if (elpis_bld_u16(b, ELPIS_OPT_COOKIE) != ELPIS_OK) goto trunc;
        if (elpis_bld_u16(b, e->cookie_len) != ELPIS_OK)    goto trunc;
        if (elpis_bld_bytes(b, e->cookie, e->cookie_len) != ELPIS_OK) goto trunc;
    }

    if (e->nsid != NULL && e->want_nsid) {
        size_t n = strlen(e->nsid);
        if (n > 255) n = 255;
        if (elpis_bld_u16(b, ELPIS_OPT_NSID) != ELPIS_OK) goto trunc;
        if (elpis_bld_u16(b, (uint16_t)n) != ELPIS_OK)    goto trunc;
        if (elpis_bld_bytes(b, e->nsid, n) != ELPIS_OK)   goto trunc;
    }

    if (e->have_keepalive) {
        if (elpis_bld_u16(b, ELPIS_OPT_TCP_KEEPALIVE) != ELPIS_OK) goto trunc;
        if (elpis_bld_u16(b, 2) != ELPIS_OK)                       goto trunc;
        if (elpis_bld_u16(b, e->keepalive) != ELPIS_OK)            goto trunc;
    }

    if (e->ede_code >= 0) {
        size_t tlen = e->ede_text ? strlen(e->ede_text) : 0;
        if (tlen > 200) tlen = 200;
        if (elpis_bld_u16(b, ELPIS_OPT_EDE) != ELPIS_OK)            goto trunc;
        if (elpis_bld_u16(b, (uint16_t)(2 + tlen)) != ELPIS_OK)     goto trunc;
        if (elpis_bld_u16(b, (uint16_t)e->ede_code) != ELPIS_OK)    goto trunc;
        if (tlen && elpis_bld_bytes(b, e->ede_text, tlen) != ELPIS_OK) goto trunc;
    }

    /*
     * Padding is emitted last so it can absorb everything before it
     * (RFC 7830).  Four extra octets are needed for the option header itself.
     */
    if (e->pad_to > 1) {
        size_t cur = b->len + 4;
        size_t pad = (e->pad_to - (cur % e->pad_to)) % e->pad_to;
        if (pad > 0 || cur % e->pad_to == 0) {
            static const uint8_t zeros[512] = { 0 };
            while (pad > sizeof zeros)
                pad = sizeof zeros;       /* never pad beyond one block */
            if (elpis_bld_u16(b, ELPIS_OPT_PADDING) != ELPIS_OK) goto trunc;
            if (elpis_bld_u16(b, (uint16_t)pad) != ELPIS_OK)     goto trunc;
            if (pad && elpis_bld_bytes(b, zeros, pad) != ELPIS_OK) goto trunc;
        }
    }

    if (elpis_bld_rr_end(b, rdlen_pos) != ELPIS_OK) goto trunc;
    if (elpis_bld_count(b, ELPIS_SEC_ADDITIONAL, 1) != ELPIS_OK) goto trunc;
    return ELPIS_OK;

trunc:
    /* An OPT that does not fit is dropped whole rather than left half-written. */
    b->len = start;
    b->overflow = 0;
    return ELPIS_ETRUNC;
}
