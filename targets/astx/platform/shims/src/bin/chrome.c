// fake "chrome" that just sits idle and responds to signals.
// Build:  gcc -O2 -Wall -o chrome chrome.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
  running = 0;
}

static void set_comm_name(const char *name)
{
#ifdef __linux__
  // Set the kernel thread name (/proc/<pid>/comm), max 16 bytes including null
  prctl(PR_SET_NAME, name, 0, 0, 0);
  // Also try writing comm explicitly (optional)
  FILE *f = fopen("/proc/self/comm", "w");
  if (f)
  {
    fprintf(f, "%.15s\n", name);
    fclose(f);
  }
#endif
}

int main(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  set_comm_name("chrome");

  struct sigaction sa = {0};
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);

  printf("[chrome] started, pid=%d. Press Ctrl-C to exit.\n", getpid());
  fflush(stdout);

  // Idle forever until a signal arrives
  while (running)
  {
    pause(); // sleeps until a signal; EINTR wakes us
  }

  puts("[chrome] exiting.");
  return 0;
}
