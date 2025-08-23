#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int (*real_socket)(int domain, int type, int protocol) = NULL;
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen) = NULL;

static int netlink_fake_fd = -1;

static void init_real_functions(void)
{
    if (!real_socket)
    {
        real_socket = dlsym(RTLD_NEXT, "socket");
    }
    if (!real_sendto)
    {
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    }
    if (!real_recvfrom)
    {
        real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    }
}

// Intercept socket creation
int socket(int domain, int type, int protocol)
{
    init_real_functions();

    // Check if this is a netlink netfilter socket
    if (domain == AF_NETLINK && protocol == NETLINK_NETFILTER)
    {
        fprintf(stderr, "[netlink shim] Intercepted NETLINK_NETFILTER socket request\n");

        // Create a pipe instead to simulate the socket
        int pipefd[2];
        if (pipe(pipefd) == -1)
        {
            errno = EPROTONOSUPPORT;
            return -1;
        }

        // Store the read end as our fake socket
        netlink_fake_fd = pipefd[0];
        close(pipefd[1]); // Close write end immediately

        return netlink_fake_fd;
    }

    return real_socket(domain, type, protocol);
}

// Intercept sendto for netlink messages
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    init_real_functions();

    if (sockfd == netlink_fake_fd)
    {
        fprintf(stderr, "[netlink shim] Intercepted netfilter sendto, len=%zu\n", len);
        // Pretend we sent the message successfully
        return len;
    }

    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

// Intercept recvfrom for netlink responses
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    init_real_functions();

    if (sockfd == netlink_fake_fd)
    {
        fprintf(stderr, "[netlink shim] Intercepted netfilter recvfrom\n");

        // Create a minimal netlink response indicating no connections
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        if (len < sizeof(struct nlmsghdr))
        {
            errno = ENOBUFS;
            return -1;
        }

        // Create NLMSG_DONE response (no connections to report)
        nlh->nlmsg_len = sizeof(struct nlmsghdr);
        nlh->nlmsg_type = NLMSG_DONE;
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_seq = 0;
        nlh->nlmsg_pid = getpid();

        if (src_addr && addrlen)
        {
            struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)src_addr;
            nl_addr->nl_family = AF_NETLINK;
            nl_addr->nl_pid = 0; // Kernel
            nl_addr->nl_groups = 0;
            *addrlen = sizeof(struct sockaddr_nl);
        }

        return sizeof(struct nlmsghdr);
    }

    return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

// Intercept bind for netlink sockets
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;

    if (!real_bind)
    {
        real_bind = dlsym(RTLD_NEXT, "bind");
    }

    if (sockfd == netlink_fake_fd)
    {
        fprintf(stderr, "[netlink shim] Intercepted netfilter bind\n");
        // Pretend bind succeeded
        return 0;
    }

    return real_bind(sockfd, addr, addrlen);
}
