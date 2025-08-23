#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

int execve(const char *pathname, char *const argv[], char *const envp[])
{
  fprintf(stderr, "[EXEC-TRACE] PID=%d executing: %s", getpid(), pathname);

  // Log ALL arguments - no truncation!
  for (int i = 0; argv && argv[i] != NULL; i++)
  {
    fprintf(stderr, " '%s'", argv[i]);
  }
  fprintf(stderr, "\n");

  // Call real execve
  int (*real_execve)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
  return real_execve(pathname, argv, envp);
}
