/*
 * tests/fuzz_msg.c -- libFuzzer harness for everything a DNS message passes
 * through before the resolver trusts it.
 *
 * Every upstream reply and every client query arrives here as bytes from
 * someone else.  Each input is parsed as both, every record in every section
 * is validated, decompressed, folded, named and printed, and any NSEC or NSEC3
 * records are handed to the denial proofs -- the same path a referral or a
 * negative answer takes.
 *
 *   make fuzz                     # builds bin/fuzz-msg with clang
 *   mkdir -p bin/corpus && cd bin && ./fuzz-msg -max_total_time=300 corpus/
 */
#include "elpis/common.h"
#include "elpis/log.h"
#include "elpis/simd.h"
#include "elpis/name.h"
#include "elpis/msg.h"
#include "elpis/rdata.h"
#include "elpis/dnssec.h"

#include <string.h>

#define MAX_PROOF 32

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void walk(const uint8_t *data, size_t size, unsigned flags)
{
    static uint8_t rd[70000];
    static uint8_t pool[MAX_PROOF][1024];
    static char text[8192];
    elpis_denial_rr_t proof[MAX_PROOF];
    unsigned nproof = 0;
    elpis_msg_t m;
    int drop = 0;
    unsigned s;

    if (elpis_msg_parse(&m, data, size, flags, &drop) != ELPIS_OK)
        return;
    (void)elpis_name_to_text(&m.qname, text, sizeof text);

    for (s = 0; s < ELPIS_SEC__COUNT; s++) {
        elpis_rr_iter_t it;
        elpis_rr_t rr;

        elpis_rr_iter(&it, &m, (elpis_section_t)s);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            elpis_name_t target;
            size_t rdlen;

            (void)elpis_name_to_text(&rr.name, text, sizeof text);
            if (elpis_rdata_validate(rr.type, data, size, rr.rdoff, rr.rdlen,
                                     &drop) != ELPIS_OK)
                continue;
            if (elpis_rdata_canonical(rr.type, data, size, rr.rdoff, rr.rdlen,
                                      rd, sizeof rd, &rdlen, 1) != ELPIS_OK)
                continue;
            (void)elpis_rdata_target(rr.type, rd, rdlen, &target);
            (void)elpis_rdata_to_text(rr.type, rd, rdlen, text, sizeof text);

            if ((rr.type == ELPIS_T_NSEC || rr.type == ELPIS_T_NSEC3) &&
                nproof < MAX_PROOF && rdlen <= sizeof pool[0]) {
                memcpy(pool[nproof], rd, rdlen);
                proof[nproof].owner = rr.name;
                elpis_name_lower(&proof[nproof].owner);
                proof[nproof].rd    = pool[nproof];
                proof[nproof].rdlen = (uint16_t)rdlen;
                nproof++;
            }
        }
    }

    if (nproof > 0) {
        elpis_name_t q = m.qname, zone;
        elpis_name_lower(&q);
        if (elpis_name_parent(&q, &zone) != 0)
            zone = q;
        (void)elpis_nsec_proves_nxdomain(proof, nproof, &q);
        (void)elpis_nsec_proves_nodata(proof, nproof, &q, m.qtype);
        (void)elpis_nsec_proves_no_ds(proof, nproof, &q);
        (void)elpis_nsec_proves_insecure_deleg(proof, nproof, &q);
        (void)elpis_nsec3_proves_nxdomain(proof, nproof, &q, &zone);
        (void)elpis_nsec3_proves_nodata(proof, nproof, &q, m.qtype, &zone);
        (void)elpis_nsec3_proves_no_ds(proof, nproof, &q, &zone);
        (void)elpis_nsec3_proves_insecure_deleg(proof, nproof, &q, &zone);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int ready;
    static char text[512];

    if (!ready) {
        elpis_log_init(ELPIS_LOG_DST_NONE, NULL, ELPIS_LOG_FATAL);
        elpis_simd_init();
        ready = 1;
    }
    walk(data, size, ELPIS_PARSE_RESPONSE);
    walk(data, size, ELPIS_PARSE_QUERY);

    /* The same bytes as presentation text: names typed into the config. */
    if (size < sizeof text) {
        elpis_name_t n;
        memcpy(text, data, size);
        text[size] = '\0';
        if (elpis_name_from_text(&n, text) == ELPIS_OK)
            (void)elpis_name_to_text(&n, text, sizeof text);
    }
    return 0;
}
