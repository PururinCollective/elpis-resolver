/*
 * elpis-licence -- issue and inspect deployment licences.
 *
 * Built by `make licence-tool`, never by `make`, and never installed.  This is
 * the only thing in the tree that signs, and the only thing that touches a
 * private key: the resolver verifies and nothing more.
 *
 *   elpis-licence keygen issuer.key
 *   elpis-licence issue --key issuer.key --org "Example ISP" \
 *                       --edition commercial --days 365 --serial 1001
 *   elpis-licence verify --pub <hex> elpis1.....
 *
 * Keep issuer.key off the build machine and out of the repository.  Anyone
 * holding it can mint licences your binaries will believe.
 */
#include "elpis/licence.h"
#include "elpis/crypto.h"
#include "elpis/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* log.c hands warnings to the status page's log ring.  A command line tool
 * has no status page, so this is where they stop. */
void elpis_tm_log_add(const char *level, const char *msg);
void elpis_tm_log_add(const char *level, const char *msg)
{
    (void)level; (void)msg;
}

static int die(const char *msg)
{
    fprintf(stderr, "elpis-licence: %s\n", msg);
    return 2;
}

static void hex_print(const uint8_t *p, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = h[p[i] >> 4];
        out[i * 2 + 1] = h[p[i] & 15];
    }
    out[n * 2] = '\0';
}

static int read_key(const char *path, uint8_t sk[32])
{
    char buf[128];
    size_t n = 0;
    ssize_t got;
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return die("cannot open the key file");
    got = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (got <= 0)
        return die("the key file is empty");
    buf[got] = '\0';
    while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r' ||
                       buf[got - 1] == ' '))
        buf[--got] = '\0';
    if (elpis_hex_decode(buf, sk, 32, &n) != ELPIS_OK || n != 32)
        return die("the key file does not hold 64 hex characters");
    return 0;
}

static int cmd_keygen(const char *path)
{
    uint8_t sk[32], pk[32];
    char hex[130];
    int fd;

    elpis_random_init();
    elpis_random_bytes(sk, sizeof sk);
    if (elpis_ed25519_pubkey(sk, pk) != ELPIS_OK)
        return die("could not derive the public key");

    /* 0600 from the moment it exists -- never world-readable, not even
     * briefly between creat() and chmod(). */
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return die("refusing to overwrite an existing key file");
    hex_print(sk, 32, hex);
    if (write(fd, hex, strlen(hex)) < 0 || write(fd, "\n", 1) < 0) {
        close(fd);
        return die("could not write the key file");
    }
    close(fd);

    hex_print(pk, 32, hex);
    printf("private key written to %s (keep it off the build machine)\n", path);
    printf("\npaste the public half into include/elpis/licence.h and rebuild:\n\n");
    printf("  #define ELPIS_LICENCE_ISSUER \"%s\"\n\n", hex);
    printf("or pass it to a single build:\n\n");
    printf("  make LICENCE_ISSUER=%s\n", hex);
    return 0;
}

static int cmd_issue(int argc, char **argv)
{
    elpis_licence_t l;
    uint8_t sk[32], payload[ELPIS_LICENCE_MAX_TOKEN];
    uint8_t sig[64], signed_buf[ELPIS_LICENCE_MAX_TOKEN + 32];
    char token[sizeof(char[7]) + 256 + 1 + 128 + 8], b1[256], b2[128], when[32];
    const char *keyfile = NULL;
    size_t plen, ctxlen = strlen(ELPIS_LICENCE_CONTEXT);
    long days = 365;
    int perpetual = 0;
    int i, rc;

    memset(&l, 0, sizeof l);
    l.edition = ELPIS_ED_COMMERCIAL;
    l.issued  = (uint32_t)time(NULL);

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if      (!strcmp(a, "--key")     && v) { keyfile = v; i++; }
        else if (!strcmp(a, "--org")     && v) { elpis_strlcpy(l.org, v, sizeof l.org); i++; }
        else if (!strcmp(a, "--serial")  && v) { l.serial = (uint32_t)strtoul(v, NULL, 10); i++; }
        else if (!strcmp(a, "--days")    && v) { days = strtol(v, NULL, 10); i++; }
        else if (!strcmp(a, "--perpetual"))    { perpetual = 1; }
        else if (!strcmp(a, "--edition") && v) {
            if (elpis_edition_from_name(v, &l.edition) != ELPIS_OK)
                return die("edition must be commercial, community, homelab or evaluation");
            i++;
        } else {
            return die("unknown option to issue");
        }
    }
    if (keyfile == NULL)  return die("issue needs --key");
    if (l.org[0] == '\0') return die("issue needs --org");
    if (strlen(l.org) > ELPIS_LICENCE_MAX_ORG)
        return die("org is too long");

    /* --days is a plain offset, so a negative one back-dates the expiry and
     * mints something already lapsed -- useful for testing what a customer
     * will see.  Perpetual is its own flag rather than a magic zero. */
    l.expires = perpetual ? 0u : (uint32_t)((int64_t)l.issued + (int64_t)days * 86400);

    if ((rc = read_key(keyfile, sk)) != 0)
        return rc;

    plen = elpis_licence_payload(&l, payload, sizeof payload);
    if (plen == 0)
        return die("could not build the payload");

    memcpy(signed_buf, ELPIS_LICENCE_CONTEXT, ctxlen);
    memcpy(signed_buf + ctxlen, payload, plen);
    if (elpis_ed25519_sign(sk, signed_buf, ctxlen + plen, sig) != ELPIS_OK)
        return die("signing failed");

    if (elpis_b64url_encode(payload, plen, b1, sizeof b1) == 0 ||
        elpis_b64url_encode(sig, sizeof sig, b2, sizeof b2) == 0)
        return die("could not encode the token");

    snprintf(token, sizeof token, "%s.%s.%s", ELPIS_LICENCE_MAGIC, b1, b2);
    if (strlen(token) >= ELPIS_LICENCE_MAX_TOKEN)
        return die("the token came out too long; shorten --org");

    elpis_licence_date(l.expires, when, sizeof when);
    fprintf(stderr, "%s licence for \"%s\", serial %lu, expires %s\n",
            elpis_edition_name(l.edition), l.org,
            (unsigned long)l.serial, when);
    fprintf(stderr, "add this line to elpis.conf:\n\n");
    printf("licence: %s\n", token);
    return 0;
}

static int cmd_verify(int argc, char **argv)
{
    elpis_licence_t l;
    const char *token = NULL;
    char when[32], issued[32];
    int i;

    for (i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "--", 2))
            return die("verify checks against the issuer key built into this "
                       "tool; rebuild it with LICENCE_ISSUER to check another");
        token = argv[i];
    }
    if (token == NULL)
        return die("verify needs a token");

    if (!elpis_licence_enabled())
        return die("this build has no issuer key, so it cannot check anything");

    elpis_licence_parse(token, (uint32_t)time(NULL), &l);
    elpis_licence_date(l.expires, when, sizeof when);
    elpis_licence_date(l.issued, issued, sizeof issued);

    printf("  edition   %s\n", elpis_edition_name(l.edition));
    printf("  org       %s\n", l.org);
    printf("  serial    %lu\n", (unsigned long)l.serial);
    printf("  issued    %s\n", issued);
    printf("  expires   %s%s\n", when, l.expired ? "  (EXPIRED)" : "");
    printf("  signature %s\n", l.valid ? "valid" : "INVALID");
    if (!l.valid)
        printf("            %s\n", l.why);
    return l.valid ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  elpis-licence keygen <file>\n"
            "  elpis-licence issue --key <file> --org <name> "
            "[--edition commercial] [--days 365 | --perpetual] [--serial N]\n"
            "  elpis-licence verify <token>\n");
        return 2;
    }
    if (!strcmp(argv[1], "keygen")) {
        if (argc != 3) return die("keygen takes one file name");
        return cmd_keygen(argv[2]);
    }
    if (!strcmp(argv[1], "issue"))  return cmd_issue(argc - 2, argv + 2);
    if (!strcmp(argv[1], "verify")) return cmd_verify(argc - 2, argv + 2);
    return die("unknown command");
}
