#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

// Function pointers to real functions
static int (*real_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = NULL;
static int (*real_accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) = NULL;
static int (*real_getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = NULL;
static int (*real_getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = NULL;
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_listen)(int sockfd, int backlog) = NULL;
static struct hostent *(*real_gethostbyname)(const char *name) = NULL;
static int (*real_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;

// Initialize function pointers
static void init_real_functions()
{
    if (!real_accept)
    {
        real_accept = dlsym(RTLD_NEXT, "accept");
    }
    if (!real_accept4)
    {
        real_accept4 = dlsym(RTLD_NEXT, "accept4");
    }
    if (!real_getpeername)
    {
        real_getpeername = dlsym(RTLD_NEXT, "getpeername");
    }
    if (!real_getsockname)
    {
        real_getsockname = dlsym(RTLD_NEXT, "getsockname");
    }
    if (!real_connect)
    {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }
    if (!real_listen)
    {
        real_listen = dlsym(RTLD_NEXT, "listen");
    }
    if (!real_gethostbyname)
    {
        real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
    }
    if (!real_getaddrinfo)
    {
        real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    }
}

// Spoof the source address to look like localhost
static void spoof_address(struct sockaddr *addr)
{
    if (!addr)
        return;

    if (addr->sa_family == AF_INET)
    {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        // Log original address before spoofing
        fprintf(stderr, "[SPOOF] Original IPv4: %s:%d -> spoofing to 127.0.0.1\n",
                inet_ntoa(in_addr->sin_addr), ntohs(in_addr->sin_port));
        // Force all connections to appear as 127.0.0.1
        in_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    else if (addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr;
        // Force all connections to appear as ::1
        in6_addr->sin6_addr = in6addr_loopback;
        fprintf(stderr, "[SPOOF] Spoofed IPv6 connection to appear as ::1\n");
    }
}

// Override accept() system call
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_real_functions();

    int result = real_accept(sockfd, addr, addrlen);

    if (result >= 0)
    {
        fprintf(stderr, "[SPOOF] accept() - INBOUND connection\n");
        spoof_address(addr);
    }

    return result;
}

// Override accept4() system call
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    init_real_functions();

    int result = real_accept4(sockfd, addr, addrlen, flags);

    if (result >= 0)
    {
        fprintf(stderr, "[SPOOF] accept4() - INBOUND connection\n");
        spoof_address(addr);
    }

    return result;
}

// Override getpeername() to log peer address lookups (no spoofing for SSL validation)
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_real_functions();

    int result = real_getpeername(sockfd, addr, addrlen);

    if (result >= 0 && addr && addr->sa_family == AF_INET)
    {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        fprintf(stderr, "[SPOOF] getpeername() - connected to %s:%d\n",
                inet_ntoa(in_addr->sin_addr), ntohs(in_addr->sin_port));
    }

    return result; // Return real address for SSL validation
}

// Override getsockname() to log local address lookups (no spoofing for SSL validation)
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_real_functions();

    int result = real_getsockname(sockfd, addr, addrlen);

    if (result >= 0 && addr && addr->sa_family == AF_INET)
    {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        fprintf(stderr, "[SPOOF] getsockname() - local socket %s:%d\n",
                inet_ntoa(in_addr->sin_addr), ntohs(in_addr->sin_port));
    }

    return result; // Return real address for SSL validation
}

// Override connect() to log outbound connections
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    init_real_functions();

    if (addr && addr->sa_family == AF_INET)
    {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        fprintf(stderr, "[SPOOF] OUTBOUND connect() to %s:%d\n",
                inet_ntoa(in_addr->sin_addr), ntohs(in_addr->sin_port));
    }

    int result = real_connect(sockfd, addr, addrlen);

    if (result < 0)
    {
        fprintf(stderr, "[SPOOF] connect() failed: %s (errno=%d)\n",
                strerror(errno), errno);
    }

    return result;
}

// Override listen() to log when daemon starts listening
int listen(int sockfd, int backlog)
{
    init_real_functions();

    fprintf(stderr, "[SPOOF] listen() - daemon starting to accept connections (backlog=%d)\n", backlog);

    return real_listen(sockfd, backlog);
}

// Override gethostbyname() to log DNS lookups
struct hostent *gethostbyname(const char *name)
{
    init_real_functions();

    if (name)
    {
        fprintf(stderr, "[SPOOF] DNS lookup: gethostbyname(\"%s\")\n", name);
    }

    struct hostent *result = real_gethostbyname(name);

    if (result && result->h_addr_list && result->h_addr_list[0])
    {
        struct in_addr addr;
        memcpy(&addr, result->h_addr_list[0], sizeof(addr));
        fprintf(stderr, "[SPOOF] DNS resolved \"%s\" -> %s\n", name, inet_ntoa(addr));
    }
    else
    {
        fprintf(stderr, "[SPOOF] DNS lookup failed for \"%s\"\n", name ? name : "(null)");
    }

    return result;
}

// Override getaddrinfo() to log modern DNS lookups
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    init_real_functions();

    fprintf(stderr, "[SPOOF] DNS lookup: getaddrinfo(\"%s\", \"%s\")\n",
            node ? node : "(null)", service ? service : "(null)");

    int result = real_getaddrinfo(node, service, hints, res);

    if (result == 0 && res && *res)
    {
        struct addrinfo *current = *res;
        while (current)
        {
            if (current->ai_family == AF_INET)
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)current->ai_addr;
                fprintf(stderr, "[SPOOF] DNS resolved \"%s\" -> %s:%d\n",
                        node ? node : "(null)", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
            }
            current = current->ai_next;
        }
    }
    else
    {
        fprintf(stderr, "[SPOOF] getaddrinfo() failed for \"%s\"\n", node ? node : "(null)");
    }

    return result;
}
