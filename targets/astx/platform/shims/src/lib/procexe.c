// gcc -m32 -shared -fPIC -O2 -ldl -o libprocexe.so procexe.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;

__attribute__((constructor)) static void init_hooks(void)
{
    real_readlink = dlsym(RTLD_NEXT, "readlink");
    real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
}

// Return a fake path when someone asks for /proc/<pid>/exe
static ssize_t spoof(const char *fake, char *buf, size_t bufsz)
{
    size_t n = strlen(fake);
    if (buf && bufsz)
    {
        if (n > bufsz)
            n = bufsz;
        memcpy(buf, fake, n);
    }
    return (ssize_t)n;
}

static int is_proc_exe(const char *path)
{
    return path && strstr(path, "/proc/") && strstr(path, "/exe");
}

ssize_t readlink(const char *path, char *buf, size_t bufsz)
{
    if (is_proc_exe(path))
    {
        // Pretend the executable is /usr/bin/chrome
        return spoof("/usr/bin/chrome", buf, bufsz);
    }
    return real_readlink(path, buf, bufsz);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsz)
{
    if (is_proc_exe(path))
    {
        return spoof("/usr/bin/chrome", buf, bufsz);
    }
    return real_readlinkat(dirfd, path, buf, bufsz);
}
