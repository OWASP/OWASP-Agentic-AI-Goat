#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int signal_number) { (void)signal_number; stopping = 1; }

int main(int argc, char **argv) {
  if (argc != 2 || strncmp(argv[1], "/owned-restart/targets/", 23) != 0
      || strstr(argv[1], "/runtime/instance") == NULL || strlen(argv[1]) > 160) return 64;
  umask(077);
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return 65;
  char value[32]; int length = snprintf(value, sizeof(value), "%ld\n", (long)getpid());
  if (length < 1 || write(fd, value, (size_t)length) != length || fsync(fd) != 0 || close(fd) != 0) return 66;
  struct sigaction action = {0}; action.sa_handler = stop; sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0) return 67;
  while (!stopping) pause();
  if (unlink(argv[1]) != 0 && errno != ENOENT) return 68;
  return 0;
}
