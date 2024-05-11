// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in
// the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <vector>
#define KCOVREMOTECNT 100

const unsigned long KCOV_TRACE_PC = 0;
const unsigned long KCOV_TRACE_CMP = 1;

template <int N> struct kcov_remote_arg {
  uint32 trace_mode;
  uint32 area_size;
  uint32 num_handles;
  uint32 pad;
  uint64 common_handle;
  uint64 handles[N];
};

#define SERVER 1
#define CLIENT 0

#define KCOV_INIT_TRACE32 _IOR('c', 1, uint32)
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, kcov_remote_arg<0>)

#define KCOV_SUBSYSTEM_COMMON (0x00ull << 56)
#define KCOV_SUBSYSTEM_USB (0x01ull << 56)

#define KCOV_SUBSYSTEM_MASK (0xffull << 56)
#define KCOV_INSTANCE_MASK (0xffffffffull)

static bool is_gvisor;

static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst) {
  if (subsys & ~KCOV_SUBSYSTEM_MASK || inst & ~KCOV_INSTANCE_MASK)
    return 0;
  return subsys | inst;
}

static bool detect_kernel_bitness();
static bool detect_gvisor();

static void os_init(int argc, char **argv, char *data, size_t data_size) {
  prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
  is_kernel_64_bit = detect_kernel_bitness();
  is_gvisor = detect_gvisor();
  // Surround the main data mapping with PROT_NONE pages to make virtual address
  // layout more consistent across different configurations (static/non-static
  // build) and C repros. One observed case before: executor had a mapping above
  // the data mapping (output region), while C repros did not have that mapping
  // above, as the result in one case VMA had next link, while in the other it
  // didn't and it caused a bug to not reproduce with the C repro.
  if (mmap(data - SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE,
           MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data - SYZ_PAGE_SIZE)
    fail("mmap of left data PROT_NONE page failed");
  if (mmap(data, data_size, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
    fail("mmap of data segment failed");
  if (mmap(data + data_size, SYZ_PAGE_SIZE, PROT_NONE,
           MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data + data_size)
    fail("mmap of right data PROT_NONE page failed");
}

void sync_lock() {
  uint8 expected = 0;
  uint8 new_value = 1;
  while (!execCtl->lockByte3.compare_exchange_strong(
      expected, new_value, std::memory_order_acquire)) {
    expected = 0;
  }
  __sync_synchronize();
}
void sync_unlock() { execCtl->lockByte3.store(0, std::memory_order_release); }

struct callOrderControl {
  // std::atomic<uint8> lockByte;
  uint8 cnt;
};
extern struct callOrderControl *callOrderCtl;
extern uint32 enable_c2san;
extern uint8 *callOrders;

void exec_lock() {
  if (!enable_c2san) {
    return;
  }
  uint8 expected = 0;
  uint8 new_value = 1;
  while (!execCtl->lockByte2.compare_exchange_strong(
      expected, new_value, std::memory_order_acquire)) {
    expected = 0;
  }
}

void exec_unlock(int call_index) {
  if (!enable_c2san) {
    return;
  }
  // when executing failure calls, call_index == -1
  if (call_index != -1) {
    callOrders[2 * callOrderCtl->cnt] = executor_index;
    callOrders[2 * callOrderCtl->cnt + 1] = call_index;
    callOrderCtl->cnt++;
  }
  execCtl->lockByte2.store(0, std::memory_order_release);
}

/*
void exec_lock1() {
  if (!enable_c2san) {
      return;
  }
  fprintf(stderr, "exec_lock spin\n");
  uint8 expected = 0;
  uint8 new_value = 1;
  int i = 0;
  while (!lockCtlPtr->lockByte.compare_exchange_strong(expected, new_value,
std::memory_order_acquire)) {
  //while (!lockCtlPtr->lockByte.compare_exchange_weak(expected, new_value,
std::memory_order_acquire)) { usleep(100); if (i % 100000 == 0) {
          fprintf(stderr, "expected value: %d\n", expected);
    }
    i ++;
    expected = 0;
  }
  fprintf(stderr, "exec_lock finished\n");
}

void exec_unlock1(int call_index) {
  if (!enable_c2san) {
    return;
  }
  fprintf(stderr, "callOrder idx: %d\n", lockCtlPtr->idx);
  callOrders[2 * lockCtlPtr->idx] = executor_index;
  callOrders[2 * lockCtlPtr->idx + 1] = call_index;
  lockCtlPtr->idx ++;
  lockCtlPtr->lockByte.store(0, std::memory_order_release);
  fprintf(stderr, "exec_unlock finished %d %d\n", lockCtlPtr->lockByte.load(),
lockCtlPtr->idx);
}
*/

static intptr_t execute_syscall(const call_t *c, intptr_t a[kMaxArgs],
                                int call_index) {
  intptr_t ret;
  exec_lock();
  if (c->call) {
    ret = c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
  } else {
    ret = syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5]);
  }
  exec_unlock(call_index);
  return ret;
}

static void cover_open(cover_t *cov, bool extra) {
  int fd = open("/sys/kernel/debug/kcov", O_RDWR);
  if (fd == -1)
    fail("open of /sys/kernel/debug/kcov failed");
  if (dup2(fd, cov->fd) < 0)
    failmsg("filed to dup cover fd", "from=%d, to=%d", fd, cov->fd);
  close(fd);
  const int kcov_init_trace =
      is_kernel_64_bit ? KCOV_INIT_TRACE64 : KCOV_INIT_TRACE32;
  const int cover_size = extra ? kExtraCoverSize : kCoverSize;
  if (ioctl(cov->fd, kcov_init_trace, cover_size) == -1)
    fail("cover init trace write failed");
  size_t mmap_alloc_size = cover_size * (is_kernel_64_bit ? 8 : 4);
  cov->data = (char *)mmap(NULL, mmap_alloc_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, cov->fd, 0);
  if (cov->data == MAP_FAILED)
    fail("cover mmap failed");
  cov->data_end = (char *)(cov->data + mmap_alloc_size);
  cov->data_offset = is_kernel_64_bit ? sizeof(uint64_t) : sizeof(uint32_t);
  cov->pc_offset = 0;
}

int shmids[SHMCNT];

void remove_shms() {
  for (int i = 0; i < SHMCNT; i++)
    shmctl(shmids[i], IPC_RMID, NULL);
  unlink(FIFONAME);
  unlink(FIFONAME2);
}

int shm_nattach(int shmid) {
  struct shmid_ds shminfo;
  extern int errno;
  errno = 0;
  if (shmctl(shmid, IPC_STAT, &shminfo) == -1) {
    fprintf(stderr, "shmctl failed: %s\n", strerror(errno));
    fail("shm_nattach shmctl failed\n");
  }
  return shminfo.shm_nattch;
}

using namespace std;

void reinit_cov_shms() {
  int clt_fd = open(FIFONAME2, O_RDWR | O_NONBLOCK);
  int send_fd = open(FIFONAME, O_RDWR | O_NONBLOCK);
  if (clt_fd == -1 || send_fd == -1) {
    fail("collect and resend open pipe errors\n");
  }

  int shmid;
  // clear two pipes
  while (read(clt_fd, &shmid, sizeof(shmid)) > 0) {
  }
  while (read(send_fd, &shmid, sizeof(shmid)) > 0) {
  }

  // write all shmids to the send pipe
  for (int i = 0; i < SHMCNT; i++) {
    write(send_fd, &(shmids[i]), sizeof(shmid));
  }
}

void *collect_and_resend_shms(void *argv) {

  int clt_fd = open(FIFONAME2, O_RDWR); // O_NONBLOCK
  int send_fd = open(FIFONAME, O_RDWR);
  if (clt_fd == -1 || send_fd == -1) {
    fail("collect and resend open pipe errors\n");
  }

  int shmid;
  std::vector<int> using_shms;
  while (1) {
    if (read(clt_fd, &shmid, sizeof(shmid)) == sizeof(shmid)) {
#if MDEBUG
      // fprintf(stderr, "-----executor %lld collect shmids %d\n",
      // executor_index,
      //         shmid);
#endif
      write(send_fd, &shmid, sizeof(shmid));
#if MDEBUG
      // fprintf(stderr, "----- directly resend shmid %d\n", shmid);
#endif
    }
    usleep(1000);
  }
  /*
int nattach = shm_nattach(shmid);
if (nattach == 2) {
  write(send_fd, &shmid, sizeof(shmid));
#if MDEBUG
  fprintf(stderr, "----- directly resend shmid %d\n", shmid);
#endif
} else {
  using_shms.push_back(shmid);
}
}

for (vector<int>::iterator it = using_shms.begin();
   it != using_shms.end();) {
if (shm_nattach(*it) == 2) {
  write(send_fd, &(*it), sizeof(*it));
#if MDEBUG
  fprintf(stderr, "----- queue resend shmid %d\n", shmid);
#endif
  it = using_shms.erase(it);
} else
  ++it;
}
}
*/
}

void uclient_cover_pipe_create() {
  unlink(FIFONAME3);
  if ((mkfifo(FIFONAME3, S_IRWXU)) != 0) {
    fail("mkfifo FIFONAME3 error\n");
  }
}

void uclient_cover_open(cover_t *cov) {
  int fd = open(FIFONAME3, O_RDWR | O_APPEND);
  if (fd == -1)
    fail("uclient_cover_open open FIFONAME3 failed\n");
  int shmid = shmget(IPC_PRIVATE, AREA_BYTESIZE, IPC_CREAT | IPC_EXCL | 0600);
  int ret = write(fd, &shmid, sizeof(shmid));
  fprintf(stderr, "----- uclient_cover_open write to pipe %d\n", ret);
  cov->data = (char *)shmat(shmid, NULL, 0);
  cov->data_end = (char *)(cov->data + AREA_BYTESIZE);
  cov->data_offset =
      is_kernel_64_bit ? sizeof(uint64_t) * 3 : sizeof(uint32_t) * 3;
  cov->pc_offset = 0;
  // close(fd);
}

void usrv_cover_open(cover_t *usp_covers) {

  extern int errno;
  errno = 0;
  int ret = unlink(FIFONAME);
  int ret2 = unlink(FIFONAME2);
  if (ret == -1 || ret2 == -1) {
    fprintf(stderr, "unlink FIFO failed: %s\n", strerror(errno));
  }

  if ((mkfifo(FIFONAME, S_IRWXU)) != 0 || (mkfifo(FIFONAME2, S_IRWXU) != 0)) {
    fail("mkfifo error\n");
  }

  int fd = open(FIFONAME, O_RDWR);
  for (int i = 0; i < SHMCNT; i++) {
    int shmid = shmget(IPC_PRIVATE, AREA_BYTESIZE, IPC_CREAT | IPC_EXCL | 0600);
    shmids[i] = shmid;
    write(fd, &shmid, sizeof(shmid));
    usp_covers[i].data = (char *)shmat(shmid, NULL, 0);
    if (usp_covers[i].data == (char *)-1) {
      fail("test2 shmat failed\n");
    }
    usp_covers[i].data_end = (char *)(usp_covers[i].data + AREA_BYTESIZE);
    usp_covers[i].data_offset =
        is_kernel_64_bit ? sizeof(uint64_t) * 3 : sizeof(uint32_t) * 3;
    usp_covers[i].pc_offset = 0;
  }
  // close(fd);

  pthread_t cltThrdId;
  pthread_create(&cltThrdId, NULL, &collect_and_resend_shms, NULL);
  fprintf(stderr, "executor %lld finishes userspace_cover_open\n",
          executor_index);
  atexit(remove_shms);
}

void usrv_cover_enable(cover_t *ups_kcovs, bool collect_comps) {
  unsigned int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
  for (int i = 0; i < SHMCNT; i++) {
    if (is_kernel_64_bit) {
      ((uint64 *)ups_kcovs[i].data)[0] = 0;
      ((uint64 *)ups_kcovs[i].data)[1] = kcov_mode;
    } else {
      ((uint32 *)ups_kcovs[i].data)[0] = 0;
      ((uint32 *)ups_kcovs[i].data)[1] = kcov_mode;
    }
  }
}

static void cover_protect(cover_t *cov) {}

static void cover_unprotect(cover_t *cov) {}

static void cover_enable(cover_t *cov, bool collect_comps, bool extra) {
  unsigned int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
  // kernel client
  if (in_kernel(CLIENT)) {
    // The KCOV_ENABLE call should be fatal,
    // but in practice ioctl fails with assorted errors (9, 14, 25),
    // so we use exitf.
    if (!extra) {
      if (ioctl(cov->fd, KCOV_ENABLE, kcov_mode) == -1)
        exitf("cover enable write trace failed, mode=%d", kcov_mode);
      return;
    }
    kcov_remote_arg<1> arg = {
        .trace_mode = kcov_mode,
        // Coverage buffer size of background threads.
        .area_size = kExtraCoverSize,
        .num_handles = 1,
    };
    arg.common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, procid + 1);
    arg.handles[0] = kcov_remote_handle(KCOV_SUBSYSTEM_USB, procid + 1);
    if (ioctl(cov->fd, KCOV_REMOTE_ENABLE, &arg) == -1)
      exitf("remote cover enable write trace failed");
  }
  // FUSE client
  else {
    if (is_kernel_64_bit) {
      ((uint64 *)cov->data)[1] = kcov_mode;
      ((uint64 *)cov->data)[2] = gettid();
    } else {
      ((uint32 *)cov->data)[1] = kcov_mode;
      ((uint32 *)cov->data)[2] = gettid();
    }
  }
}

pthread_t cov_thds[KCOVREMOTECNT];
int start_disable = 0;
void *run_one_remote_cover(void *argv) {

  cover_t *cov = (cover_t *)argv;

  kcov_remote_arg<0> arg = {
      .trace_mode = KCOV_TRACE_PC,
      .area_size = kExtraCoverSize,
      .num_handles = 0,
      .common_handle =
          kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, 0x30 + cov->idx),
  };

#if MDEBUG
  // fprintf(stderr, "----- remote_cover_enable %d\n", cov->fd);
#endif
  if (ioctl(cov->fd, KCOV_REMOTE_ENABLE, &arg) == -1)
    exitf("remote server cover enable write trace failed");

  if (is_kernel_64_bit)
    *(uint64 *)cov->data = 0;
  else
    *(uint32 *)cov->data = 0;

  // wait servers to disable and collect coverage
  while (!start_disable) {
    usleep(100);
  }

  if (ioctl(cov->fd, KCOV_DISABLE, 0) == -1)
    exitf("remote server cover disable failed\n");

  pthread_exit(0);
}

static void remote_cover_enable(cover_t *covs, bool collect_comps) {

  unsigned int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
#if MDEBUG
  fprintf(stderr, "----- executor %lld remote server cover enable\n",
          executor_index);
#endif
  start_disable = 0;
  for (int i = 0; i < KCOVREMOTECNT; i++) {
    covs[i].idx = i;
    covs[i].mode = kcov_mode;
    pthread_create(&(cov_thds[i]), NULL, &run_one_remote_cover, &(covs[i]));
  }
}

void remote_cover_disable() {
  start_disable = 1;
  for (int i = 0; i < KCOVREMOTECNT; i++) {
    pthread_join(cov_thds[i], NULL);
  }
}

static void cover_reset(cover_t *cov) {
  // Callers in common_linux.h don't check this flag.
  if (!flag_coverage)
    return;
  if (cov == 0) {
    if (current_thread == 0)
      fail("cover_reset: current_thread == 0");
    cov = &current_thread->cov;
  }

  if (is_kernel_64_bit)
    *(uint64 *)cov->data = 0;
  else
    *(uint32 *)cov->data = 0;
}

static void cover_collect(cover_t *cov) {
  if (is_kernel_64_bit)
    cov->size = *(uint64 *)cov->data;
  else
    cov->size = *(uint32 *)cov->data;
}

static bool use_cover_edges(uint32 pc) { return true; }

static bool use_cover_edges(uint64 pc) {
#if defined(__i386__) || defined(__x86_64__)
  if (is_gvisor)
    return false; // gvisor coverage is not a trace, so producing edges won't
                  // work
  // Text/modules range for x86_64.
  if (pc < 0xffffffff80000000ull || pc >= 0xffffffffff000000ull) {
    debug("executor %lld is_dfs_client %lld got bad pc: 0x%llx\n",
          executor_index, is_dfs_client, pc);
    doexit(0);
  }
#endif
  return true;
}

static bool detect_kernel_bitness() {
  if (sizeof(void *) == 8)
    return true;
  // It turns out to be surprisingly hard to understand if the kernel underneath
  // is 64-bits. A common method is to look at uname.machine. But it is produced
  // in some involved ways, and we will need to know about all strings it
  // returns and in the end it can be overriden during build and lie (and there
  // are known precedents of this). So instead we look at size of addresses in
  // /proc/kallsyms.
  bool wide = true;
  int fd = open("/proc/kallsyms", O_RDONLY);
  if (fd != -1) {
    char buf[16];
    if (read(fd, buf, sizeof(buf)) == sizeof(buf) &&
        (buf[8] == ' ' || buf[8] == '\t'))
      wide = false;
    close(fd);
  }
  debug("detected %d-bit kernel\n", wide ? 64 : 32);
  return wide;
}

static bool detect_gvisor() {
  char buf[64] = {};
  // 3 stands for undeclared SYSLOG_ACTION_READ_ALL.
  syscall(__NR_syslog, 3, buf, sizeof(buf) - 1);
  // This is a first line of gvisor dmesg.
  return strstr(buf, "Starting gVisor");
}

// One does not simply exit.
// _exit can in fact fail.
// syzkaller did manage to generate a seccomp filter that prohibits exit_group
// syscall. Previously, we get into infinite recursion via segv_handler in such
// case and corrupted output_data, which does matter in our case since it is
// shared with fuzzer process. Loop infinitely instead. Parent will kill us. But
// one does not simply loop either. Compilers are sure that _exit never returns,
// so they remove all code after _exit as dead. Call _exit via volatile
// indirection. And this does not work as well. _exit has own handling of
// failing exit_group in the form of HLT instruction, it will divert control
// flow from our loop. So call the syscall directly.
NORETURN void doexit(int status) {
  volatile unsigned i;
  syscall(__NR_exit_group, status);
  for (i = 0;; i++) {
  }
}

#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {"leak", setup_leak},
    {"fault", setup_fault},
    {"binfmt_misc", setup_binfmt_misc},
    {"kcsan", setup_kcsan},
    {"usb", setup_usb},
    {"802154", setup_802154},
};
