/*
 * elpis/webui.h -- the read-only status page.
 *
 * A small HTTP server on its own thread.  It exposes exactly two things: the
 * page itself, and one JSON snapshot of what the resolver is doing.  Nothing
 * it serves can change the resolver's behaviour -- there is no endpoint that
 * writes anything, which is the whole reason it is safe to have at all.
 *
 * It speaks plain HTTP and binds loopback unless told otherwise.  Put it
 * behind an SSH tunnel, a VPN, or a reverse proxy that terminates TLS.
 */
#ifndef ELPIS_WEBUI_H
#define ELPIS_WEBUI_H

#include "elpis/ctx.h"

/*
 * Settle the password before anything is served.
 *
 * With no password configured, one is generated and printed to stderr -- once,
 * at startup, where an operator will see it.  With a plaintext one, it is
 * replaced by a PBKDF2 hash, in memory and in the config file if that file can
 * be written, so the plaintext does not outlive the first start.
 */
int  elpis_webui_prepare(elpis_ctx_t *ctx);

/* Runs until ctx->shutdown.  Intended as a pthread entry point. */
void *elpis_webui_main(void *ctx);

#endif /* ELPIS_WEBUI_H */
