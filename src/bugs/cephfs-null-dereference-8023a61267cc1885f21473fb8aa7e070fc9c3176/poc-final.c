#define _GNU_SOURCE

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

uint64_t r[2] = {0xffffffffffffffff, 0xffffffffffffffff};

int w1, w2 = 0;

static long long unsigned int current_time_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    printf("clock_gettime failed");
  return (long long unsigned int)ts.tv_sec * 1000 + (long long unsigned int)ts.tv_nsec / 1000000;
}

void *unlink_thread(void *arg) {
  while (w1 == 0) {}
  printf("unlink starts at %llu\n", current_time_ms());
  memcpy((void*)0x20000000, "./file0\000", 8);
  syscall(__NR_unlink, 0x20000000ul);
  printf("unlink ends at %llu\n", current_time_ms());
  return 0;
}

void fsync_thread(void *arg) {
  while (w2 == 0) {}
  printf("fsync starts at %llu\n", current_time_ms());
  syscall(__NR_fsync, r[1]);
  printf("fysnc ends at %llu\n", current_time_ms());
  return 0;
}

int main(void)
{

  pthread_t p1, p2;
  pthread_create(&p1, NULL, unlink_thread, NULL);
  pthread_create(&p2, NULL, fsync_thread, NULL);


  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);

  memcpy((void*)0x200001c0, ".\000", 2);
  memcpy((void*)0x20000080, "./file0\000", 8);
  syscall(__NR_symlink, 0x200001c0ul, 0x20000080ul);
  
  memcpy((void*)0x200000c0, "./file0\000", 8);
  syscall(__NR_lchown, 0x200000c0ul, -1, 0xee00);
  printf("lchown ends at %llu\n", current_time_ms());

  printf("open starts at %llu\n", current_time_ms());
  memcpy((void*)0x20000040, "./file0\000", 8);
  int res = syscall(__NR_open, 0x20000040ul, 0ul, 0ul);
  if (res != -1)
    r[1] = res;
  printf("open ends at %llu\n", current_time_ms());

  w1 = 1;
  //wait around 3 seconds after seeing "unlink starts at" from the terminal.
  int wait;
  scanf("%d", &wait);
  w2 = 1;
  
  pthread_join(p1, NULL);
  pthread_join(p2, NULL);
  return 0;
}
