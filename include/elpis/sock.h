/*
 * elpis/sock.h -- socket setup and datagram I/O.
 *
 * Replies are sent from the address the query arrived on, recovered via
 * IP_PKTINFO / IPV6_PKTINFO.  On a multi-homed host bound to the wildcard
 * address that is not optional: without it the kernel picks a source address
 * by route, the reply appears to come from somewhere else, and clients
 * discard it.
 */
#ifndef ELPIS_SOCK_H
#define ELPIS_SOCK_H

#include "elpis/util.h"

int elpis_sock_nonblock(int fd);
int elpis_sock_cloexec(int fd);

/* Server sockets. */
int elpis_sock_udp_listen(const elpis_addr_t *a, int reuseport, int *fd_out);
int elpis_sock_tcp_listen(const elpis_addr_t *a, int reuseport, int backlog,
                          int *fd_out);

/* Outbound UDP socket bound to a random high port on `family`. */
int elpis_sock_udp_client(int family, const elpis_addr_t *src_hint,
                          uint16_t lo, uint16_t hi, int *fd_out);
/* Outbound TCP, non-blocking connect. */
int elpis_sock_tcp_connect(const elpis_addr_t *dst, const elpis_addr_t *src_hint,
                           int *fd_out);

/* Datagram I/O that carries the local address when the kernel supports it. */
ssize_t elpis_sock_recv(int fd, void *buf, size_t n,
                        elpis_addr_t *from, elpis_addr_t *to);
ssize_t elpis_sock_send(int fd, const void *buf, size_t n,
                        const elpis_addr_t *to, const elpis_addr_t *from);

/* Best-effort tuning; failures are logged at debug level and ignored. */
void elpis_sock_tune_udp(int fd, int rcvbuf, int sndbuf);
void elpis_sock_tune_tcp(int fd);

#endif /* ELPIS_SOCK_H */
