/*
 * dns64.c -- DNS64 synthesis (RFC 6147).
 *
 * When an IPv6-only client asks for AAAA and the name has none, an A lookup
 * is made and each address is embedded in the configured prefix per RFC 6052.
 * Synthesis is deliberately conservative: it never happens when real AAAA
 * records exist, and never for a name that is already inside the prefix.
 */
#include "elpis/resolver.h"
#include "elpis/rdata.h"
#include "elpis/log.h"

/*
 * RFC 6052 section 2.2.  The prefix lengths are fixed, and bits 64..71 are
 * always zero (the "u" octet), which is why the layout is not a simple copy.
 */
void elpis_dns64_embed(const elpis_prefix_t *p, const uint8_t v4[4],
                       uint8_t out[16])
{
    memset(out, 0, 16);
    memcpy(out, p->ip, 16);

    switch (p->bits) {
    case 32:
        memcpy(out + 4, v4, 4);
        break;
    case 40:
        memcpy(out + 5, v4, 3);
        out[8] = 0;
        out[9] = v4[3];
        break;
    case 48:
        memcpy(out + 6, v4, 2);
        out[8] = 0;
        memcpy(out + 9, v4 + 2, 2);
        break;
    case 56:
        out[7] = v4[0];
        out[8] = 0;
        memcpy(out + 9, v4 + 1, 3);
        break;
    case 64:
        out[8] = 0;
        memcpy(out + 9, v4, 4);
        break;
    case 96:
    default:
        memcpy(out + 12, v4, 4);
        break;
    }
}

static int has_type(const elpis_rrlist_t *l, uint16_t type)
{
    unsigned i;
    for (i = 0; i < l->n; i++)
        if (l->rr[i].section == (uint8_t)ELPIS_SEC_ANSWER &&
            l->rr[i].type == type)
            return 1;
    return 0;
}

int elpis_dns64_needed(elpis_task_t *t)
{
    const elpis_conf_t *c = &t->w->ctx->conf;

    if (!c->dns64 || t->dns64_tried)
        return 0;
    if (t->orig_qtype != ELPIS_T_AAAA || t->qclass != ELPIS_CLASS_IN)
        return 0;
    /* NXDOMAIN means the name does not exist at all; do not invent one. */
    if (t->rcode != ELPIS_RC_NOERROR)
        return 0;
    if (!c->dns64_synth_all && has_type(&t->ans, ELPIS_T_AAAA))
        return 0;
    /*
     * RFC 6147 section 5.5.  DO and CD together are a client validating for
     * itself, which must get the data as it is and synthesise on its own: an
     * AAAA made here would fail its validation.  DO alone is not that -- it is
     * any DNSSEC-aware forwarder in front of us, AdGuard Home with DNSSEC on
     * among them -- and is synthesised for like anyone else, from answers the
     * validator has already passed.  This had the two the other way round:
     * behind such a forwarder an IPv6-only client got no address at all for
     * an IPv4-only name, and CLAT could not discover the prefix from
     * ipv4only.arpa, while the one client that must not be synthesised for
     * was.
     */
    if (t->client_do && t->client_cd)
        return 0;
    return 1;
}

static void dns64_child_done(elpis_task_t *child, void *ctxp)
{
    elpis_task_t *p = child->parent;
    const elpis_prefix_t *pfx;
    unsigned i;
    unsigned synth = 0;

    (void)ctxp;
    if (p == NULL)
        return;
    pfx = &p->w->ctx->conf.dns64_prefix;

    if (child->rcode == ELPIS_RC_NOERROR) {
        for (i = 0; i < child->ans.n; i++) {
            const elpis_trr_t *rr = &child->ans.rr[i];
            elpis_name_t on;
            uint8_t v6[16];

            if (rr->section != (uint8_t)ELPIS_SEC_ANSWER)
                continue;
            if (elpis_trr_get_name(&child->ans, i, &on) != ELPIS_OK)
                continue;

            if (rr->type == ELPIS_T_CNAME) {
                /* Keep the chain so the client sees the same shape. */
                elpis_rrlist_add(&p->ans, ELPIS_SEC_ANSWER, &on, rr->type,
                                 rr->klass, rr->ttl,
                                 elpis_trr_rd(&child->ans, i), rr->rdlen);
                continue;
            }
            if (rr->type != ELPIS_T_A || rr->rdlen != 4)
                continue;

            elpis_dns64_embed(pfx, elpis_trr_rd(&child->ans, i), v6);
            elpis_rrlist_add(&p->ans, ELPIS_SEC_ANSWER, &on, ELPIS_T_AAAA,
                             rr->klass, rr->ttl, v6, 16);
            synth++;
        }
    }

    if (synth) {
        p->dns64_synth = 1;
        /* Synthesised data cannot be validated; say so rather than claim AD. */
        p->sec = ELPIS_SEC_INSECURE;
        elpis_stat_inc(&p->w->stats.dns64_synth, synth);
    }

    if (p->nchild)
        p->nchild--;

    if (p->state == ELPIS_TS_WAIT) {
        p->state = ELPIS_TS_FINISH;
        elpis_task_step(p);
    }
}

int elpis_dns64_start(elpis_task_t *t)
{
    elpis_name_t n = t->orig_qname;

    t->dns64_tried = 1;
    if (elpis_task_child(t, &n, ELPIS_T_A, dns64_child_done, NULL) == NULL)
        return ELPIS_ERR;
    return ELPIS_OK;
}

/*
 * Called on the way out for every answer.  Synthesis itself happens in the
 * child callback; this only strips AAAA records that fall inside an address
 * range the operator has told us to ignore (RFC 6147 section 5.1.4).
 */
void elpis_dns64_apply(elpis_task_t *t)
{
    const elpis_conf_t *c = &t->w->ctx->conf;
    unsigned i, out = 0;

    if (c->n_dns64_ignore == 0)
        return;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        int drop = 0;

        if (rr->section == (uint8_t)ELPIS_SEC_ANSWER &&
            rr->type == ELPIS_T_AAAA && rr->rdlen == 16) {
            unsigned k;
            elpis_addr_t a;
            elpis_addr_from6(&a, t->ans.pool + rr->rdoff, 0);
            for (k = 0; k < c->n_dns64_ignore; k++) {
                if (elpis_prefix_match(&c->dns64_ignore_aaaa[k], &a)) {
                    drop = 1;
                    break;
                }
            }
        }
        if (!drop)
            t->ans.rr[out++] = t->ans.rr[i];
    }
    t->ans.n = out;
}
