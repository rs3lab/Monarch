#include <sys/time.h>

#define MDEBUG 1

extern uint64 executor_index;

void debug_cmd(const char *cmdbuf) {

  FILE *cmd = popen(cmdbuf, "r");
  char result[1000] = {0x0};
  while (fgets(result, sizeof(result), cmd) != NULL)
    fprintf(stderr, "----------executor %lld debug cmd (%s): %s\n",
            executor_index, cmdbuf, result);
  pclose(cmd);
}

int time_now() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000000 + tv.tv_usec) / 1000;
}
