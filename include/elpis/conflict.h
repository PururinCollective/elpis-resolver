/*
 * elpis/conflict.h -- find out what already owns a listening port.
 *
 * This exists because the obvious failure mode is not a failure.  Elpis sets
 * SO_REUSEADDR on its listeners, and on Linux that lets a second UDP socket
 * bind a port another process already holds -- even the same address.  Run as
 * root on a systemd-resolved host, a bind to :53 succeeds silently and the
 * kernel then splits incoming queries between the two resolvers at random.
 * Half your lookups go somewhere else and nothing logs an error.
 *
 * So the conflict has to be found before the socket is opened, by asking the
 * kernel who is listening rather than by trying and seeing what happens.
 */
#ifndef ELPIS_CONFLICT_H
#define ELPIS_CONFLICT_H

#include "elpis/util.h"

typedef struct {
    unsigned found : 1;
    unsigned identified : 1;    /* we managed to name the process           */
    unsigned is_resolved : 1;   /* it is systemd-resolved                   */
    long     pid;
    char     name[64];          /* /proc/<pid>/comm, truncated as the kernel does */
    char     cmdline[256];
    elpis_addr_t addr;          /* the conflicting local address            */
    char     proto[4];          /* "udp" or "tcp"                           */
} elpis_conflict_t;

/*
 * Who, if anyone, is listening on something that conflicts with `a`?
 * A wildcard on either side counts as a conflict.  Returns 1 when found.
 * Linux only; elsewhere it always reports nothing and the bind speaks for
 * itself.
 */
int elpis_conflict_find(const elpis_addr_t *a, elpis_conflict_t *out);

/* Is systemd the init system on this host? */
int elpis_systemd_present(void);

/* Ask systemd to stop systemd-resolved and wait for the port to clear. */
int elpis_stop_systemd_resolved(const elpis_addr_t *a);

/* 1 when /etc/resolv.conf points at the systemd-resolved stub. */
int elpis_resolvconf_uses_stub(void);

/*
 * Exposed for testing.  Both of these got the fiddly detail wrong the first
 * time -- the inode column index and the endianness of the printed address --
 * and neither is exercised by anything but a Linux host at startup, so they
 * are pinned by the self test instead.
 */
/* Parse one /proc/net/{udp,tcp}[6] row.  Returns 1 on success. */
int elpis_conflict_parse_row(const char *line, int family,
                             elpis_addr_t *addr, unsigned long *inode);
/* Would a socket bound to `bound` collide with a bind to `want`? */
int elpis_conflict_collides(const elpis_addr_t *bound, const elpis_addr_t *want);

#endif /* ELPIS_CONFLICT_H */
