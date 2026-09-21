/*
 * conflict.c -- identify (and, for systemd-resolved, clear) a port conflict.
 */
#include "elpis/conflict.h"
#include "elpis/log.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int elpis_systemd_present(void)
{
#if defined(__linux__)
    struct stat st;
    return stat("/run/systemd/system", &st) == 0 && S_ISDIR(st.st_mode);
#else
    return 0;
#endif
}

int elpis_resolvconf_uses_stub(void)
{
#if defined(__linux__)
    char link[512];
    ssize_t n;
    FILE *fp;
    char line[256];

    n = readlink("/etc/resolv.conf", link, sizeof link - 1);
    if (n > 0) {
        link[n] = '\0';
        if (strstr(link, "systemd/resolve") != NULL)
            return 1;
    }
    /* Not a symlink, or pointing elsewhere: look for the stub address. */
    fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL)
        return 0;
    while (fgets(line, sizeof line, fp) != NULL) {
        if (strstr(line, "127.0.0.53") != NULL) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
#endif
    return 0;
}

/*
 * /proc/net/{udp,tcp}[6] print the socket's local address as the raw __be32
 * words formatted with %08X.  Writing that value back out in native order
 * reproduces the original network-order bytes, so this works the same on
 * little- and big-endian hosts.
 */
static int parse_hex_addr(const char *hex, size_t hexlen, uint8_t *ip,
                          size_t iplen)
{
    size_t words = hexlen / 8;
    size_t w;

    if (hexlen != iplen * 2 || (hexlen % 8) != 0)
        return 0;
    for (w = 0; w < words; w++) {
        char buf[9];
        unsigned long v;
        char *end;

        memcpy(buf, hex + w * 8, 8);
        buf[8] = '\0';
        v = strtoul(buf, &end, 16);
        if (*end != '\0')
            return 0;
        {
            uint32_t n = (uint32_t)v;
            memcpy(ip + w * 4, &n, 4);
        }
    }
    return 1;
}

int elpis_conflict_parse_row(const char *line, int family,
                             elpis_addr_t *addr, unsigned long *inode)
{
    char laddr[40];
    unsigned lport = 0;
    const char *p, *colon;
    uint8_t ip[16];

    p = line;
    while (*p == ' ') p++;
    p = strchr(p, ':');                /* end of the "sl" column */
    if (p == NULL) return 0;
    p++;
    while (*p == ' ') p++;

    colon = strchr(p, ':');
    if (colon == NULL) return 0;
    if ((size_t)(colon - p) >= sizeof laddr) return 0;
    memcpy(laddr, p, (size_t)(colon - p));
    laddr[colon - p] = '\0';
    if (sscanf(colon + 1, "%4X", &lport) != 1) return 0;

    /*
     * Counting from the local port, the columns are:
     *   rem_address st tx:rx tr:when retrnsmt uid timeout inode
     * so the inode is eight tokens along.  Getting this off by one silently
     * yields the "ref" count instead, which never matches any socket.
     */
    {
        const char *q = colon + 1;
        int field = 0;
        while (*q && field < 8) {
            while (*q && *q != ' ') q++;
            while (*q == ' ') q++;
            field++;
        }
        if (sscanf(q, "%lu", inode) != 1)
            return 0;
    }

    memset(ip, 0, sizeof ip);
    if (family == AF_INET) {
        if (!parse_hex_addr(laddr, strlen(laddr), ip, 4)) return 0;
        elpis_addr_from4(addr, ip, (uint16_t)lport);
    } else {
        if (!parse_hex_addr(laddr, strlen(laddr), ip, 16)) return 0;
        elpis_addr_from6(addr, ip, (uint16_t)lport);
    }
    return 1;
}

typedef struct {
    unsigned long inode;
    elpis_addr_t  addr;
} listener_t;

int elpis_conflict_collides(const elpis_addr_t *bound, const elpis_addr_t *want)
{
    static const uint8_t zero16[16] = { 0 };

    if (elpis_addr_port(bound) != elpis_addr_port(want))
        return 0;
    if (elpis_addr_family(bound) != elpis_addr_family(want))
        return 0;

    /* A wildcard on either side covers the other. */
    if (elpis_addr_family(bound) == AF_INET) {
        const uint8_t *b = (const uint8_t *)&bound->u.v4.sin_addr;
        const uint8_t *w = (const uint8_t *)&want->u.v4.sin_addr;
        if (memcmp(b, zero16, 4) == 0 || memcmp(w, zero16, 4) == 0)
            return 1;
        return memcmp(b, w, 4) == 0;
    }
    {
        const uint8_t *b = (const uint8_t *)&bound->u.v6.sin6_addr;
        const uint8_t *w = (const uint8_t *)&want->u.v6.sin6_addr;
        if (memcmp(b, zero16, 16) == 0 || memcmp(w, zero16, 16) == 0)
            return 1;
        return memcmp(b, w, 16) == 0;
    }
}

/* Collect sockets from one /proc/net table that collide with `want`. */
#if defined(__linux__)

static unsigned scan_table(const char *path, int family, const elpis_addr_t *want,
                           listener_t *out, unsigned max, unsigned n)
{
    FILE *fp = fopen(path, "r");
    char line[512];

    if (fp == NULL)
        return n;
    if (fgets(line, sizeof line, fp) == NULL) {  /* header */
        fclose(fp);
        return n;
    }
    while (n < max && fgets(line, sizeof line, fp) != NULL) {
        unsigned long inode = 0;
        elpis_addr_t bound;

        if (!elpis_conflict_parse_row(line, family, &bound, &inode))
            continue;
        if (inode == 0)
            continue;
        if (!elpis_conflict_collides(&bound, want))
            continue;

        out[n].inode = inode;
        out[n].addr  = bound;
        n++;
    }
    fclose(fp);
    return n;
}

/* Map a socket inode back to the process holding it. */
static int find_owner(const listener_t *l, unsigned nl, elpis_conflict_t *out)
{
    DIR *proc = opendir("/proc");
    struct dirent *de;
    int found = 0;

    if (proc == NULL)
        return 0;
    while (!found && (de = readdir(proc)) != NULL) {
        char fdpath[64];
        DIR *fds;
        struct dirent *fe;
        long pid;
        char *end;

        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        pid = strtol(de->d_name, &end, 10);
        if (*end != '\0')
            continue;

        snprintf(fdpath, sizeof fdpath, "/proc/%ld/fd", pid);
        fds = opendir(fdpath);
        if (fds == NULL)
            continue;                  /* not ours and we are not root */

        while ((fe = readdir(fds)) != NULL) {
            char link[sizeof fdpath + 260], target[128];
            ssize_t n;
            unsigned long ino;
            unsigned k;

            if (!isdigit((unsigned char)fe->d_name[0]))
                continue;
            snprintf(link, sizeof link, "%s/%s", fdpath, fe->d_name);
            n = readlink(link, target, sizeof target - 1);
            if (n <= 0)
                continue;
            target[n] = '\0';
            if (sscanf(target, "socket:[%lu]", &ino) != 1)
                continue;
            for (k = 0; k < nl; k++) {
                if (l[k].inode != ino)
                    continue;
                out->pid  = pid;
                out->addr = l[k].addr;
                found = 1;
                break;
            }
            if (found)
                break;
        }
        closedir(fds);
    }
    closedir(proc);

    if (!found)
        return 0;

    /* comm is what the kernel shows, truncated to 15 characters. */
    {
        char path[64];
        FILE *fp;
        snprintf(path, sizeof path, "/proc/%ld/comm", out->pid);
        fp = fopen(path, "r");
        if (fp != NULL) {
            if (fgets(out->name, (int)sizeof out->name, fp) != NULL) {
                size_t l2 = strlen(out->name);
                while (l2 > 0 && (out->name[l2 - 1] == '\n' || out->name[l2 - 1] == '\r'))
                    out->name[--l2] = '\0';
            }
            fclose(fp);
        }
    }
    {
        char path[64];
        int fd;
        snprintf(path, sizeof path, "/proc/%ld/cmdline", out->pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, out->cmdline, sizeof out->cmdline - 1);
            close(fd);
            if (n > 0) {
                ssize_t i;
                out->cmdline[n] = '\0';
                for (i = 0; i < n - 1; i++)
                    if (out->cmdline[i] == '\0')
                        out->cmdline[i] = ' ';
            }
        }
    }
    out->identified = 1;
    /*
     * "systemd-resolved" is sixteen characters and comm holds fifteen, so the
     * kernel reports "systemd-resolve".  Matching the full name would never
     * fire.
     */
    if (!strcmp(out->name, "systemd-resolve") ||
        !strcmp(out->name, "systemd-resolved"))
        out->is_resolved = 1;
    return 1;
}

#endif /* __linux__ */

int elpis_conflict_find(const elpis_addr_t *a, elpis_conflict_t *out)
{
    memset(out, 0, sizeof *out);
#if defined(__linux__)
    {
        listener_t l[64];
        unsigned n = 0;
        int is4 = (elpis_addr_family(a) == AF_INET);

        n = scan_table(is4 ? "/proc/net/udp" : "/proc/net/udp6",
                       elpis_addr_family(a), a, l, 64, n);
        if (n > 0)
            elpis_strlcpy(out->proto, "udp", sizeof out->proto);
        else {
            n = scan_table(is4 ? "/proc/net/tcp" : "/proc/net/tcp6",
                           elpis_addr_family(a), a, l, 64, n);
            if (n > 0)
                elpis_strlcpy(out->proto, "tcp", sizeof out->proto);
        }
        if (n == 0)
            return 0;

        out->found = 1;
        out->addr  = l[0].addr;
        (void)find_owner(l, n, out);
        return 1;
    }
#else
    (void)a;
    return 0;
#endif
}

/* ------------------------------------------------------------------ */

int elpis_stop_systemd_resolved(const elpis_addr_t *a)
{
#if defined(__linux__)
    pid_t pid;
    int status = -1;
    unsigned waited;

    elpis_info("stopping systemd-resolved so the port can be bound cleanly");

    pid = fork();
    if (pid < 0) {
        elpis_error("fork: %s", strerror(errno));
        return ELPIS_ERR;
    }
    if (pid == 0) {
        /* No shell: nothing here is built from untrusted input, and exec'ing
         * one would be a needless way to get that wrong. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }
        execlp("systemctl", "systemctl", "stop", "systemd-resolved.service",
               (char *)NULL);
        _exit(127);
    }

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            break;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        elpis_error("'systemctl stop systemd-resolved' failed (status %d)",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return ELPIS_ERR;
    }

    /* systemctl returns once the job is queued; wait for the port to clear. */
    for (waited = 0; waited < 50; waited++) {
        elpis_conflict_t c;
        struct timespec ts;

        if (!elpis_conflict_find(a, &c) || (c.identified && !c.is_resolved))
            break;
        ts.tv_sec = 0;
        ts.tv_nsec = 100 * 1000000L;
        nanosleep(&ts, NULL);
    }

    {
        elpis_conflict_t c;
        if (elpis_conflict_find(a, &c) && c.is_resolved) {
            elpis_error("systemd-resolved still holds the port after stopping");
            return ELPIS_ERR;
        }
    }

    elpis_info("systemd-resolved stopped");
    if (elpis_resolvconf_uses_stub()) {
        elpis_warn("/etc/resolv.conf still points at the systemd-resolved "
                   "stub (127.0.0.53), which is no longer listening -- this "
                   "host cannot resolve names until you repoint it");
        elpis_warn("  e.g. 'nameserver 127.0.0.1' once elpis is listening, or "
                   "keep resolved's stub and run elpis on another port");
    }
    elpis_warn("systemd-resolved will come back on reboot; make it permanent "
               "with 'systemctl disable --now systemd-resolved'");
    return ELPIS_OK;
#else
    (void)a;
    return ELPIS_ERR;
#endif
}
