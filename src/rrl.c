/*
 * rrl.c -- response-rate-limiting helpers shared with the server path.
 *
 * The bucket machinery lives in ratelimit.c; this file holds the policy
 * decisions that depend on what the answer turned out to be.
 */
#include "elpis/resolver.h"

/*
 * Whether a response may be sent at full size, sent truncated, or dropped.
 * Truncating rather than dropping keeps legitimate clients working: they
 * simply retry over TCP, which an amplification attacker cannot do because
 * the spoofed source never completes a handshake.
 */
int elpis_rrl_decide(elpis_worker_t *w, const elpis_addr_t *client,
                     unsigned rcode, int over_tcp)
{
    if (over_tcp)
        return 0;                     /* 0 = send normally */
    if (elpis_rrl_allow(w, client, rcode))
        return 0;
    return 1;                         /* 1 = answer with TC set */
}
