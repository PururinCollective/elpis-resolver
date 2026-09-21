/*
 * Linux hides struct in6_pktinfo behind __USE_GNU even though RFC 3542
 * specifies it; ask for it explicitly before any header is pulled in.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif

/*
 * sock.c -- socket helpers.
 */
#include "elpis/sock.h"
#include "elpis/log.h"
#include "elpis/crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/uio.h>

int elpis_sock_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return ELPIS_ERR;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
        return ELPIS_ERR;
    return ELPIS_OK;
}

int elpis_sock_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl < 0)
        return ELPIS_ERR;
    if (fcntl(fd, F_SETFD, fl | FD_CLOEXEC) < 0)
        return ELPIS_ERR;
    return ELPIS_OK;
}

static void set_pktinfo(int fd, int family)
{
    int on = 1;
    if (family == AF_INET) {
#if defined(IP_PKTINFO)
        (void)setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof on);
#elif defined(IP_RECVDSTADDR)
        (void)setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof on);
#endif
    } else {
#if defined(IPV6_RECVPKTINFO)
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on);
#elif defined(IPV6_PKTINFO)
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof on);
#endif
    }
}

void elpis_sock_tune_udp(int fd, int rcvbuf, int sndbuf)
{
    if (rcvbuf > 0)
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    if (sndbuf > 0)
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    /*
     * Never fragment outbound DNS: a fragmented response is both a
     * reassembly-poisoning target and a common cause of black holes.  We keep
     * payloads at or below the EDNS buffer size and let the peer's TC bit
     * drive a TCP retry instead.
     */
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_OMIT)
    {
        int v = IP_PMTUDISC_OMIT;
        (void)setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v);
    }
#elif defined(IP_DONTFRAG)
    {
        int v = 1;
        (void)setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &v, sizeof v);
    }
#endif
}

void elpis_sock_tune_tcp(int fd)
{
    int on = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
#if defined(TCP_KEEPIDLE)
    {
        int idle = 30;
        (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
        (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    }
#endif
}

static int bind_common(int fd, const elpis_addr_t *a, int reuseport, int isudp)
{
    int on = 1;

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#if defined(SO_REUSEPORT)
    if (reuseport &&
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) != 0) {
        elpis_debug("SO_REUSEPORT unavailable: %s", strerror(errno));
    }
#else
    (void)reuseport;
#endif
    if (elpis_addr_family(a) == AF_INET6) {
        int v6only = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
    }
    if (isudp)
        set_pktinfo(fd, elpis_addr_family(a));

    if (bind(fd, &a->u.sa, a->len) != 0) {
        char buf[80];
        elpis_error("bind %s: %s", elpis_addr_str(a, buf, sizeof buf),
                    strerror(errno));
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

int elpis_sock_udp_listen(const elpis_addr_t *a, int reuseport, int *fd_out)
{
    int fd = socket(elpis_addr_family(a), SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        elpis_error("socket(udp): %s", strerror(errno));
        return ELPIS_ERR;
    }
    elpis_sock_cloexec(fd);
    if (bind_common(fd, a, reuseport, 1) != ELPIS_OK) {
        close(fd);
        return ELPIS_ERR;
    }
    if (elpis_sock_nonblock(fd) != ELPIS_OK) {
        close(fd);
        return ELPIS_ERR;
    }
    elpis_sock_tune_udp(fd, 4 * 1024 * 1024, 1024 * 1024);
    *fd_out = fd;
    return ELPIS_OK;
}

int elpis_sock_tcp_listen(const elpis_addr_t *a, int reuseport, int backlog,
                          int *fd_out)
{
    int fd = socket(elpis_addr_family(a), SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        elpis_error("socket(tcp): %s", strerror(errno));
        return ELPIS_ERR;
    }
    elpis_sock_cloexec(fd);
    if (bind_common(fd, a, reuseport, 0) != ELPIS_OK) {
        close(fd);
        return ELPIS_ERR;
    }
    if (listen(fd, backlog > 0 ? backlog : 256) != 0) {
        elpis_error("listen: %s", strerror(errno));
        close(fd);
        return ELPIS_ERR;
    }
    if (elpis_sock_nonblock(fd) != ELPIS_OK) {
        close(fd);
        return ELPIS_ERR;
    }
    *fd_out = fd;
    return ELPIS_OK;
}

/*
 * Outbound socket on an unpredictable source port (RFC 5452).  We ask the
 * kernel for a specific random port rather than letting it choose, because
 * the ephemeral range is often both narrow and sequential.
 */
int elpis_sock_udp_client(int family, const elpis_addr_t *src_hint,
                          uint16_t lo, uint16_t hi, int *fd_out)
{
    int fd, tries;

    if (lo < 1024) lo = 1024;
    if (hi <= lo)  hi = 65535;

    fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return ELPIS_ERR;
    elpis_sock_cloexec(fd);
    if (family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }

    for (tries = 0; tries < 64; tries++) {
        elpis_addr_t b;
        uint16_t port = (uint16_t)(lo + elpis_random_below((uint32_t)(hi - lo + 1u)));

        if (src_hint != NULL && elpis_addr_family(src_hint) == family) {
            b = *src_hint;
        } else {
            memset(&b, 0, sizeof b);
            if (family == AF_INET) {
                b.u.v4.sin_family = AF_INET;
                b.len = (socklen_t)sizeof(struct sockaddr_in);
            } else {
                b.u.v6.sin6_family = AF_INET6;
                b.len = (socklen_t)sizeof(struct sockaddr_in6);
            }
        }
        if (family == AF_INET)
            b.u.v4.sin_port = htons(port);
        else
            b.u.v6.sin6_port = htons(port);

        if (bind(fd, &b.u.sa, b.len) == 0) {
            if (elpis_sock_nonblock(fd) != ELPIS_OK)
                break;
            elpis_sock_tune_udp(fd, 1024 * 1024, 256 * 1024);
            *fd_out = fd;
            return ELPIS_OK;
        }
        if (errno != EADDRINUSE && errno != EACCES)
            break;
    }
    close(fd);
    return ELPIS_ERR;
}

int elpis_sock_tcp_connect(const elpis_addr_t *dst, const elpis_addr_t *src_hint,
                           int *fd_out)
{
    int fd = socket(elpis_addr_family(dst), SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return ELPIS_ERR;
    elpis_sock_cloexec(fd);
    if (elpis_sock_nonblock(fd) != ELPIS_OK) {
        close(fd);
        return ELPIS_ERR;
    }
    if (src_hint != NULL && elpis_addr_family(src_hint) == elpis_addr_family(dst)) {
        elpis_addr_t b = *src_hint;
        if (elpis_addr_family(&b) == AF_INET)
            b.u.v4.sin_port = 0;
        else
            b.u.v6.sin6_port = 0;
        (void)bind(fd, &b.u.sa, b.len);
    }
    elpis_sock_tune_tcp(fd);

    if (connect(fd, &dst->u.sa, dst->len) != 0 &&
        errno != EINPROGRESS && errno != EINTR) {
        close(fd);
        return ELPIS_ERR;
    }
    *fd_out = fd;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Datagram I/O with local-address tracking                            */
/* ------------------------------------------------------------------ */

ssize_t elpis_sock_recv(int fd, void *buf, size_t n,
                        elpis_addr_t *from, elpis_addr_t *to)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align;
        char           space[256];
    } cbuf;
    struct cmsghdr *cm;
    ssize_t r;

    memset(&msg, 0, sizeof msg);
    memset(&cbuf, 0, sizeof cbuf);
    if (to != NULL)
        memset(to, 0, sizeof *to);

    iov.iov_base = buf;
    iov.iov_len  = n;
    msg.msg_name    = &from->u.ss;
    msg.msg_namelen = (socklen_t)sizeof from->u.ss;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_control    = cbuf.space;
    msg.msg_controllen = (socklen_t)sizeof cbuf.space;

    r = recvmsg(fd, &msg, 0);
    if (r < 0)
        return r;
    from->len = msg.msg_namelen;

    if (to == NULL)
        return r;

    for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
#if defined(IP_PKTINFO)
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(cm), sizeof pi);
            to->u.v4.sin_family = AF_INET;
            to->u.v4.sin_addr   = pi.ipi_addr;
            to->len = (socklen_t)sizeof(struct sockaddr_in);
        }
#elif defined(IP_RECVDSTADDR)
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_RECVDSTADDR) {
            struct in_addr ia;
            memcpy(&ia, CMSG_DATA(cm), sizeof ia);
            to->u.v4.sin_family = AF_INET;
            to->u.v4.sin_addr   = ia;
            to->len = (socklen_t)sizeof(struct sockaddr_in);
        }
#endif
#if defined(IPV6_PKTINFO)
        if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pi6;
            memcpy(&pi6, CMSG_DATA(cm), sizeof pi6);
            to->u.v6.sin6_family = AF_INET6;
            to->u.v6.sin6_addr   = pi6.ipi6_addr;
            to->u.v6.sin6_scope_id = pi6.ipi6_ifindex;
            to->len = (socklen_t)sizeof(struct sockaddr_in6);
        }
#endif
    }
    return r;
}

ssize_t elpis_sock_send(int fd, const void *buf, size_t n,
                        const elpis_addr_t *to, const elpis_addr_t *from)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr align;
        char           space[256];
    } cbuf;

    memset(&msg, 0, sizeof msg);
    memset(&cbuf, 0, sizeof cbuf);

    iov.iov_base = (void *)(uintptr_t)buf;
    iov.iov_len  = n;
    msg.msg_name    = (void *)(uintptr_t)&to->u.sa;
    msg.msg_namelen = to->len;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (from != NULL && from->len != 0) {
        struct cmsghdr *cm;
        msg.msg_control    = cbuf.space;
        msg.msg_controllen = (socklen_t)sizeof cbuf.space;
        cm = CMSG_FIRSTHDR(&msg);
#if defined(IP_PKTINFO)
        if (elpis_addr_family(from) == AF_INET) {
            struct in_pktinfo pi;
            memset(&pi, 0, sizeof pi);
            pi.ipi_spec_dst = from->u.v4.sin_addr;
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type  = IP_PKTINFO;
            cm->cmsg_len   = CMSG_LEN(sizeof pi);
            memcpy(CMSG_DATA(cm), &pi, sizeof pi);
            msg.msg_controllen = CMSG_SPACE(sizeof pi);
        } else
#endif
#if defined(IPV6_PKTINFO)
        if (elpis_addr_family(from) == AF_INET6) {
            struct in6_pktinfo pi6;
            memset(&pi6, 0, sizeof pi6);
            pi6.ipi6_addr = from->u.v6.sin6_addr;
            cm->cmsg_level = IPPROTO_IPV6;
            cm->cmsg_type  = IPV6_PKTINFO;
            cm->cmsg_len   = CMSG_LEN(sizeof pi6);
            memcpy(CMSG_DATA(cm), &pi6, sizeof pi6);
            msg.msg_controllen = CMSG_SPACE(sizeof pi6);
        } else
#endif
        {
            msg.msg_control    = NULL;
            msg.msg_controllen = 0;
        }
    }

    return sendmsg(fd, &msg, 0);
}
