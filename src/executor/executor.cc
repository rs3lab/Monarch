// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in
// the LICENSE file.

// +build
#include <algorithm>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <map>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
// #include <stdatomic.h>
#include <atomic>
using namespace std;

#include "../instrument/ucov/userspace-kcov.h"
#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"

// tao added
#define SYZ_EXECUTOR_USES_SHMEM 1
// tao end

#if defined(__GNUC__)
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define ALIGNED(N) __attribute__((aligned(N)))
#define PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#define INPUT_DATA_ALIGNMENT 64 << 10
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define INPUT_DATA_ALIGNMENT 4 << 10
#define ALIGNED(N)                                                             \
  __declspec(align(N)) // here we are not aligning the value because of msvc
                       // reporting the value as an illegal value
#define PRINTF(fmt, args)
#define __thread __declspec(thread)
#endif

#ifndef GIT_REVISION
#define GIT_REVISION "unknown"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// uint64 is impossible to printf without using the clumsy and verbose "%"
// PRId64. So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

// exit/_exit do not necessary work (e.g. if fuzzer sets seccomp filter that
// prohibits exit_group). Use doexit instead.  We must redefine exit to
// something that exists in stdlib, because some standard libraries contain
// "using ::exit;", but has different signature.
#define exit vsnprintf

// Dynamic memory allocation reduces test reproducibility across different libc
// versions and kernels. malloc will cause unspecified number of additional
// mmap's at unspecified locations. For small objects prefer stack allocations,
// for larger -- either global objects (this may have issues with concurrency),
// or controlled mmaps, or make the fuzzer allocate memory.
#define malloc do_not_use_malloc
#define calloc do_not_use_calloc

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
// const int kMaxThreads = 16;
// const int kInPipeFd = kMaxFd - 1;  // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
const int kMaxArgs = 9;
const int kCoverSize = 256 << 10;
const int kFailStatus = 67;

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by
// syz-fuzzer. syz-fuzzer will fail and syz-manager will create a bug for this.
// Note: err is used for bug deduplication, thus distinction between err
// (constant message) and msg (varying part).
static NORETURN void fail(const char *err);
static NORETURN PRINTF(2, 3) void failmsg(const char *err, const char *msg,
                                          ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char *msg, ...);
static NORETURN void doexit(int status);

// Print debug output that is visible when running syz-manager/execprog with
// -debug flag. Debug output is supposed to be relatively high-level (syscalls
// executed, return values, timing, etc) and is intended mostly for end users.
// If you need to debug lower-level details, use debug_verbose function and
// temporary enable it in your build by changing #if 0 below. This function does
// not add \n at the end of msg as opposed to the previous functions.
static PRINTF(1, 2) void debug(const char *msg, ...);
void debug_dump_data(const char *data, int length);

#if 0
#define debug_verbose(...) debug(__VA_ARGS__)
#else
#define debug_verbose(...) (void)0
#endif

static uint64 receive_execute();
static void reply_execute(int status, int iter);

#if GOOS_akaros
static void resend_execute(int fd);
#endif

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void receive_handshake();
static void reply_handshake();
#endif

void sync_file(const char *fn);
uint32 *write_stat(struct stat *stat_buf, char *filepath, int xattr_len,
                   struct dirent *dent, bool isDir);

// Place csan.h here is that it requires some function and varialbe definition
#include "../checker/getmetadata.h"

#if SYZ_EXECUTOR_USES_SHMEM
// tao modified
const int kMaxOutput = 1 * 1024 * 1024; // 16 << 20;
// tao end
// const int kInFd = 3;
// const int kOutFd = 4;
int kInFd, kOutFd, kOrderFd;
static uint8 *output_data_org;
static uint32 *output_data;
static uint32 *output_pos;
static uint32 *write_output(uint32 v);
static uint32 *write_output_64(uint64 v);
static uint32 *occupy_nbytes(int n);
static void write_completed(uint32 completed);
static uint32 hash(uint32 a);
static bool dedup(uint32 sig);
#endif

uint64 start_time_ms = 0;

static bool flag_debug;
static bool flag_coverage;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_sandbox_namespace;
static bool flag_sandbox_android;
static bool flag_extra_coverage;
static bool flag_net_injection;
static bool flag_net_devices;
static bool flag_net_reset;
static bool flag_cgroups;
static bool flag_close_fds;
static bool flag_devlink_pci;
static bool flag_vhci_injection;
static bool flag_wifi;

static bool flag_collect_cover;
static bool flag_dedup_cover;
static bool flag_threaded;
static bool flag_collide;
static bool flag_coverage_filter;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

// Tunable timeouts, received with execute_req.
static uint64 syscall_timeout_ms;
static uint64 program_timeout_ms;
static uint64 slowdown_scale;

#define SYZ_EXECUTOR 1
#include "common.h"

// tao modified
const int kMaxInput =
    1 * 1024 * 1024; // 4 << 20; // keep in sync with prog.ExecBufferSize
// tao end
const int kMaxCommands =
    1000; // prog package knows about this constant (prog.execMaxCommands)

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;
const uint64 instr_setprops = -4;

const uint64 arg_const = 0;
const uint64 arg_result = 1;
const uint64 arg_data = 2;
const uint64 arg_csum = 3;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

const uint64 no_copyout = -1;

static int running;
static bool collide;
uint32 completed, last_completed;
bool is_kernel_64_bit = true;

ALIGNED(INPUT_DATA_ALIGNMENT)
// tao modified
char *input_data;
// static char input_data[kMaxInput];
// tao end

// Checksum kinds.
static const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
static const uint64 arg_csum_chunk_data = 0;
static const uint64 arg_csum_chunk_const = 1;

typedef intptr_t(SYSCALLAPI *syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t,
                                        intptr_t, intptr_t, intptr_t, intptr_t,
                                        intptr_t);

struct call_t {
  const char *name;
  int sys_nr;
  call_attrs_t attrs;
  syscall_t call;
};

struct cover_t {
  int fd;
  uint32 size;
  volatile char *volatile data;
  char *data_end;
  // Note: On everything but darwin the first value in data is the count of
  // recorded PCs, followed by the PCs. We therefore set data_offset to the
  // size of one PC.
  // On darwin data points to an instance of the ksancov_trace struct. Here we
  // set data_offset to the offset between data and the structs 'pcs' member,
  // which contains the PCs.
  intptr_t data_offset;
  // Note: On everything but darwin this is 0, as the PCs contained in data
  // are already correct. XNUs KSANCOV API, however, chose to always squeeze
  // PCs into 32 bit. To make the recorded PC fit, KSANCOV substracts a fixed
  // offset (VM_MIN_KERNEL_ADDRESS for AMD64) and then truncates the result to
  // uint32_t. We get this from the 'offset' member in ksancov_trace.
  intptr_t pc_offset;
  int idx;
  unsigned int mode;
};

struct thread_t {
  int id;
  bool created;
  event_t ready;
  event_t done;
  uint64 *copyout_pos;
  uint64 copyout_index;
  bool colliding;
  bool executing;
  int call_index;
  int call_num;
  int num_args;
  intptr_t args[kMaxArgs];
  call_props_t call_props;
  intptr_t res;
  uint32 reserrno;
  bool fault_injected;
  cover_t cov;
  bool soft_fail_state;
  unsigned long long stime;
  unsigned long long etime;
};

static thread_t threads[kMaxThreads];
static thread_t *last_scheduled;
// Threads use this variable to access information about themselves.
static __thread struct thread_t *current_thread;
static cover_t extra_cov;
cover_t usp_covers[SHMCNT];

struct res_t {
  bool executed;
  uint64 val;
};

static res_t results[kMaxCommands];

const uint64 kInMagic = 0xbadc0ffeebadface;
const uint32 kOutMagic = 0xbadf00d;

struct handshake_req {
  uint64 magic;
  uint64 flags; // env flags
  uint64 pid;
};

struct handshake_reply {
  uint32 magic;
};

struct execute_req {
  uint64 magic;
  uint64 env_flags;
  uint64 exec_flags;
  uint64 pid;
  uint64 syscall_timeout_ms;
  uint64 program_timeout_ms;
  uint64 slowdown_scale;
  uint64 execution_index;
  uint64 prog_sizes[64];
  uint64 prog_offsets[64];
};

struct execute_reply {
  uint32 magic;
  uint32 done;
  uint32 status;
};

// call_reply.flags
const uint32 call_flag_executed = 1 << 0;
const uint32 call_flag_finished = 1 << 1;
const uint32 call_flag_blocked = 1 << 2;
const uint32 call_flag_fault_injected = 1 << 3;

struct call_reply {
  execute_reply header;
  uint32 call_index;
  uint32 call_num;
  uint32 reserrno;
  uint32 flags;
  uint32 signal_size;
  uint32 cover_size;
  uint32 comps_size;
  // signal/cover/comps follow
};

enum {
  KCOV_CMP_CONST = 1,
  KCOV_CMP_SIZE1 = 0,
  KCOV_CMP_SIZE2 = 2,
  KCOV_CMP_SIZE4 = 4,
  KCOV_CMP_SIZE8 = 6,
  KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
  // Note: comparisons are always 64-bits regardless of kernel bitness.
  uint64 type;
  uint64 arg1;
  uint64 arg2;
  uint64 pc;

  bool ignore() const;
  void write();
  bool operator==(const struct kcov_comparison_t &other) const;
  bool operator<(const struct kcov_comparison_t &other) const;
};

typedef char
    kcov_comparison_size[sizeof(kcov_comparison_t) == 4 * sizeof(uint64) ? 1
                                                                         : -1];

struct feature_t {
  const char *name;
  void (*setup)();
};

static thread_t *schedule_call(int call_index, int call_num, bool colliding,
                               uint64 copyout_index, uint64 num_args,
                               uint64 *args, uint64 *pos,
                               call_props_t call_props);
static void handle_completion(thread_t *th);
static void copyout_call_results(thread_t *th);
static void write_call_output(thread_t *th, bool finished, cover_t *usp_covers);
static void write_extra_output();
static void execute_call(thread_t *th);
static void thread_create(thread_t *th, int id);
static void *worker_thread(void *arg);
static uint64 read_input(uint64 **input_posp, bool peek = false);
static uint64 read_arg(uint64 **input_posp);
static uint64 read_const_arg(uint64 **input_posp, uint64 *size_p, uint64 *bf,
                             uint64 *bf_off_p, uint64 *bf_len_p);
static uint64 read_result(uint64 **input_posp);
static uint64 swap(uint64 v, uint64 size, uint64 bf);
static void copyin(char *addr, uint64 val, uint64 size, uint64 bf,
                   uint64 bf_off, uint64 bf_len);
static bool copyout(char *addr, uint64 size, uint64 *res);
// static void setup_control_pipes();
static void setup_features(char **enable, int n);
void network_fault_injection(int delay, int loss, int corrupt);
void disk_fault_injection(int prob, int times, int enable);
void write_server_output(cover_t *usp_covers);
void *trace_daemon_log(void *arg);
void *trace_dmesg_log(void *arg);
void *read_dfs_log(void *arg);
void reconfigure_dfs();
// void client_setup(char *);
int in_kernel(int is_server);
void parse_env_flags(uint64 flags);

#include "syscalls.h"

#if GOOS_linux
#include "executor_linux.h"
#elif GOOS_fuchsia
#include "executor_fuchsia.h"
#elif GOOS_akaros
#include "executor_akaros.h"
#elif GOOS_freebsd || GOOS_netbsd || GOOS_openbsd
#include "executor_bsd.h"
#elif GOOS_darwin
#include "executor_darwin.h"
#elif GOOS_windows
#include "executor_windows.h"
#elif GOOS_test
#include "executor_test.h"
#else
#error "unknown OS"
#endif

#include "cov_filter.h"

#include "test.h"

uint64 is_dfs_client = 1, executor_index = 0, prog_data_offset = 0,
       server_num = 0, vm_count = 0, prog_size = 0, in_userspace = 0,
       is_restarting = 0, skip_handshake = 0;
uint32 stat_cnt = 0, kernel_server = 0, kernel_client = 0, lfs_based = 0,
       enable_csan = 0, enable_c2san = 0;
char *dfs_name, *init_ip, *dfs_setup_params;
volatile struct executeControl *execCtl;
volatile struct outputControl *output_ctl_pos;
unsigned char *execute_reply_pos;
uint32 *output_pos_value;

struct callOrderControl *callOrderCtl;
uint8 *callOrders;
char mnt_dir[100];

signed long long int tsc_offset;

#define WRITE_CHECK(var, index) ({ var & 1 << index ? 1 : 0; })

int main(int argc, char **argv) {

  if (argc == 2 && strcmp(argv[1], "version") == 0) {
    puts(GOOS " " GOARCH " " SYZ_REVISION " " GIT_REVISION);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "setup") == 0) {
    setup_features(argv + 2, argc - 2);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "leak") == 0) {
#if SYZ_HAVE_LEAK_CHECK
    check_leaks(argv + 2, argc - 2);
#else
    fail("leak checking is not implemented");
#endif
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "setup_kcsan_filterlist") == 0) {
#if SYZ_HAVE_KCSAN
    setup_kcsan_filterlist(argv + 2, argc - 2, true);
#else
    fail("KCSAN is not implemented");
#endif
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "test") == 0)
    return run_tests();

  if (argc < 2 || strcmp(argv[1], "exec") != 0) {
    fprintf(stderr, "unknown command");
    return 1;
  }

  if (argc < 14) {
    failmsg("not enough arguments for executor", "only %d arguments", argc);
    return 1;
  }

  is_dfs_client = atoi(argv[2]);
  executor_index = atoi(argv[3]);
  dfs_name = argv[4];
  server_num = atoi(argv[5]);
  vm_count = atoi(argv[6]);
  init_ip = argv[7];
  is_restarting = atoi(argv[8]);
#if MDEBUG
  fprintf(stderr, "----- is restarting %lld\n", is_restarting);
#endif
  dfs_setup_params = argv[9];
  kernel_server = !strcmp(argv[10], "true") ? 1 : 0;
  kernel_client = !strcmp(argv[11], "true") ? 1 : 0;
  lfs_based = !strcmp(argv[12], "true") ? 1 : 0;
  enable_csan = !strcmp(argv[13], "true") ? 1 : 0;
  enable_c2san = !strcmp(argv[14], "true") ? 1 : 0;
  tsc_offset = atoll(argv[15]);
  fprintf(stderr, "executor %lld tsc_offset %lld", executor_index, tsc_offset);

  snprintf(mnt_dir, 100, "/root/%s-client", dfs_name);

  if (!strcmp(dfs_name, "nfs") ||
      (!strcmp(dfs_name, "cephfs") && is_dfs_client))
    in_userspace = 0;
  else
    in_userspace = 1;
#if MDEBUG
  fprintf(stderr, "---- dfs_name %s is_dfs_client %llu\n", dfs_name,
          is_dfs_client);
#endif
  start_time_ms = current_time_ms();

  os_init(argc, argv, (char *)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
  current_thread = &threads[0];

#if SYZ_EXECUTOR_USES_SHMEM

  // tao added
  kInFd = open("/sys/bus/pci/devices/0000:00:10.0/resource2", O_RDWR);
  debug("open mmap fd %d\n", kInFd);
  if (kInFd <= 0)
    debug("open mmap input file faied\n");
  // tao end
  // if (mmap(&input_data[0], kMaxInput, PROT_READ, MAP_PRIVATE | MAP_FIXED,
  // kInFd, 0) != &input_data[0])
  input_data =
      (char *)mmap(0, kMaxInput, PROT_READ | PROT_WRITE, MAP_SHARED, kInFd, 0);
  if (input_data < 0) {
    fail("mmap of input file failed");
  }
  execCtl = ((struct executeControl *)input_data);

  // create the lock variable for serializing concurrent syscalls
  kOrderFd = open("/sys/bus/pci/devices/0000:00:11.0/resource2", O_RDWR);
  uint8 *callOrderCtlOrg = (uint8 *)mmap(0, 1024 * 4, PROT_READ | PROT_WRITE,
                                         MAP_SHARED, kOrderFd, 0);
  if (callOrderCtlOrg < 0)
    fail("mmap of lock control file failed");
  callOrderCtl = (struct callOrderControl *)callOrderCtlOrg;
  callOrders = callOrderCtlOrg + sizeof(struct callOrderControl);

  // The output region is the only thing in executor process for which
  // consistency matters. If it is corrupted ipc package will fail to parse its
  // contents and panic. But fuzzer constantly invents new ways of how to
  // currupt the region, so we map the region at a (hopefully) hard to guess
  // address with random offset, surrounded by unmapped pages. The address
  // chosen must also work on 32-bit kernels with 1GB user address space.
  // tao added
  kOutFd = open("/sys/bus/pci/devices/0000:00:12.0/resource2", O_RDWR);
  // tao end
  // void* preferred = (void*)(0x1b2bc20000ull + (1 << 20) * (getpid() % 128));
  // ooutput_data_orgutput_data = (uint32*)mmap(preferred, kMaxOutput,
  //			    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
  // kOutFd, 0); if (output_data != preferred)
  output_data_org = (uint8 *)mmap(0, kMaxOutput, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, kOutFd, 0);
  if (output_data_org < 0) {
    fail("mmap of output file failed");
  }
  output_ctl_pos = (struct outputControl *)output_data_org;
  execute_reply_pos =
      (unsigned char *)(output_data_org + sizeof(outputControl));
  output_pos_value = (uint32 *)(output_data_org + sizeof(outputControl) +
                                sizeof(execute_reply));
  output_data = (uint32 *)((uint8 *)output_pos_value + sizeof(uint32 *));
  if (!is_restarting) {
    memset(output_data_org, 0,
           sizeof(struct outputControl) + sizeof(execute_reply) +
               sizeof(uint32 *));
  }
  // Prevent test programs to mess with these fds.
  // Due to races in collider mode, a program can e.g. ftruncate one of these
  // fds, which will cause fuzzer to crash.
  close(kInFd);
  close(kOutFd);

#endif

  use_temporary_dir();
  install_segv_handler();
  // setup_control_pipes();

  pthread_t daemonThreadId, dmesgThreadId, logThreadId;
  if (pthread_create(&daemonThreadId, NULL, &trace_daemon_log, NULL)) {
    fail("pthread_create for trace_daemon_log failed\n");
  }
  if (pthread_create(&dmesgThreadId, NULL, &trace_dmesg_log, NULL)) {
    fail("pthread_create for trace_dmesg_log failed\n");
  }
  if (pthread_create(&logThreadId, NULL, &read_dfs_log, NULL)) {
    fail("pthread_create for read_dfs_log failed\n");
  }

  if (!is_dfs_client) {
    if (in_kernel(SERVER)) {
      for (int i = 0; i < KCOVREMOTECNT; i++) {
        usp_covers[i].fd = kCoverFd + kMaxThreads + i;
        cover_open(&(usp_covers[i]), false);
        // fprintf(stderr, "------ cov->fd %d\n", usp_covers[i].fd);
      }
    } else
      usrv_cover_open(usp_covers);
  }

#if SYZ_EXECUTOR_USES_FORK_SERVER
  if (!is_restarting)
    receive_handshake();
  else {
    reconfigure_dfs();
    if (output_ctl_pos->executionFinished == CALLOFFSET - 1) {
      // crash consistency mode doesn't need coverage recording, so reset ncmd
      // to 0 during recovery
      output_pos = output_data;
      write_output(0);
      reply_execute(0, 0);
      is_restarting = 0;
    }
    skip_handshake = 1;
#if MDEBUG
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(stderr,
            "node_crash testing: executor %lld starts at %ld:%ld, "
            "executionFinished:%d\n",
            executor_index, tv.tv_sec, tv.tv_usec,
            output_ctl_pos->executionFinished);
#endif
  }
#else
  receive_execute();
#endif

  // sync all scp-ed scripts to disk, incase after crash it disappears.
  if (enable_c2san || enable_csan) {
    system("sync");
  }

  if (flag_coverage && is_dfs_client) {
    uclient_cover_pipe_create();
    for (int i = 0; i < kMaxThreads; i++) {
      threads[i].cov.fd = kCoverFd + i;
      if (in_kernel(CLIENT)) {
        cover_open(&threads[i].cov, false);
      } else {
        uclient_cover_open(&threads[i].cov);
      }
      cover_protect(&threads[i].cov);
    }

    cover_open(&extra_cov, true);
    cover_protect(&extra_cov);
    if (flag_extra_coverage && is_dfs_client) {
      // Don't enable comps because we don't use them in the fuzzer yet.
      cover_enable(&extra_cov, false, true);
    }

    char sep = '/';
#if GOOS_windows
    sep = '\\';
#endif
    char filename[1024] = {0};
    char *end = strrchr(argv[0], sep);
    size_t len = end - argv[0];
    strncpy(filename, argv[0], len + 1);
    strncat(filename, "syz-cover-bitmap", 17);
    filename[sizeof(filename) - 1] = '\0';
    init_coverage_filter(filename);
  }

  int status = 0;
  if (flag_sandbox_none) {
    status = do_sandbox_none();
  }
#if SYZ_HAVE_SANDBOX_SETUID
  else if (flag_sandbox_setuid)
    status = do_sandbox_setuid();
#endif
#if SYZ_HAVE_SANDBOX_NAMESPACE
  else if (flag_sandbox_namespace)
    status = do_sandbox_namespace();
#endif
#if SYZ_HAVE_SANDBOX_ANDROID
  else if (flag_sandbox_android)
    status = do_sandbox_android();
#endif
  else
    fail("unknown sandbox type");

#if SYZ_EXECUTOR_USES_FORK_SERVER
  fprintf(stderr, "executor %lld loop exited with status %d\n", executor_index,
          status);
  // Other statuses happen when fuzzer processes manages to kill loop, e.g.
  // with: ptrace(PTRACE_SEIZE, 1, 0, 0x100040)
  if (status != kFailStatus)
    status = 0;
  // If an external sandbox process wraps executor, the out pipe will be closed
  // before the sandbox process exits this will make ipc package kill the
  // sandbox. As the result sandbox process will exit with exit status 9 instead
  // of the executor exit status (notably kFailStatus). So we duplicate the exit
  // status on the pipe.
  reply_execute(status, -1);
  doexit(status);
  // Unreachable.
  return 1;
#else
  reply_execute(status, -1);
  return status;
#endif
}

/*
void setup_control_pipes()
{
        if (dup2(0, kInPipeFd) < 0)
                fail("dup2(0, kInPipeFd) failed");
        if (dup2(1, kOutPipeFd) < 0)
                fail("dup2(1, kOutPipeFd) failed");
        if (dup2(2, 1) < 0)
                fail("dup2(2, 1) failed");
        // We used to close(0), but now we dup stderr to stdin to keep fd
numbers
        // stable across executor and C programs generated by pkg/csource.
        if (dup2(2, 0) < 0)
                fail("dup2(2, 0) failed");
}
*/

int in_kernel(int is_server) {

  return is_server ? kernel_server : kernel_client;
  /*
  if(!strcmp(dfs_name, "nfs")){
          return 1;
  }
  else if(!strcmp(dfs_name, "cephfs")){
          return (!is_server ? 1 : 0);
  }
  else if(!strcmp(dfs_name, "glusterfs")){
          return 0;
  }
  else {
          fail("no correponding file system");
  }
  */
}

char *has_asan_logfile(char *fn) {
  DIR *d;
  struct dirent *dir;
  d = opendir("/root/");
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      if (strstr(dir->d_name, "daemon-log.")) {
        sprintf(fn, "/root/%s", dir->d_name);
        return fn;
      }
    }
    closedir(d);
  }
  return NULL;
}

static std::map<std::string, std::string> logs = {
    {"orangefs", "/var/log/orangefs-server.log"}};

void *read_dfs_log(void *arg) {

  char dfs_log_buf[512];
  unsigned int total = 0;
  const char *log_fn;

  if (logs.find(dfs_name) == logs.end()) {
    return NULL;
  } else {
    log_fn = logs.at(dfs_name).c_str();
  }

  int fd = open(log_fn, O_RDONLY);
  while (true) {
    lseek(fd, total, SEEK_SET);
    int cnt = read(fd, dfs_log_buf, sizeof(dfs_log_buf) - 1);
    if (cnt > 0) {
      total += cnt;
      dfs_log_buf[cnt] = 0;
      fprintf(stderr, "%s", dfs_log_buf);
    } else if (cnt == 0) {
      usleep(1000000);
    } else {
      fail("read dfs log file failed\n");
    }
  }
  close(fd);
}

#define DAEMON_BUF_SIZE 5119
char daemon_buf[5120];
void read_log_once(char *log_fn) {
  fprintf(stderr, "Node-%lld:%s\n", executor_index, log_fn);

  bool must_wait = false;
  unsigned int tcnt = 0, fpos = 0, times = 0;

  while (true) {
    int fd = open(log_fn, O_RDONLY);
    lseek(fd, fpos, SEEK_SET);
    errno = 0;
    if (tcnt >= DAEMON_BUF_SIZE) {
      daemon_buf[DAEMON_BUF_SIZE] = 0;
      fprintf(stderr, "%s", daemon_buf);
      tcnt = 0;
    }
    int cnt = read(fd, &(daemon_buf[tcnt]), DAEMON_BUF_SIZE - tcnt);
    // fprintf(stderr, "daemon log read: %d\n", cnt);
    if (cnt >= 0) {
      tcnt += cnt;
      fpos += cnt;
    } else {
      fail("read daemon-log file failed\n");
    }
    if (!must_wait && strstr(daemon_buf, "AddressSanitizer")) {
      // fprintf(stderr, "must wait is true\n");
      must_wait = true;
    }
    if (strstr(daemon_buf, "ABORTING") || (times > 1000 && !must_wait)) {
      daemon_buf[tcnt] = 0;
      fprintf(stderr, "%s", daemon_buf);
      close(fd);
      break;
    }
    usleep(1000);
    times++;
    close(fd);
  }
  unlink(log_fn);
}

void *trace_daemon_log(void *arg) {

  char log_fn[250];
  while (1) {
    while (!has_asan_logfile(log_fn)) {
      usleep(1000);
    }
    read_log_once(log_fn);
  }
  return NULL;
}

char dmesg_buf[1000];
void *trace_dmesg_log(void *arg) {

  int fd = open("/var/log/dmesg", O_RDONLY);
  int cnt = 0;
  while (1) {
    lseek(fd, cnt, SEEK_SET);
    int tmp_cnt = read(fd, dmesg_buf, 999);
    if (tmp_cnt != -1 && tmp_cnt != 0) {
      dmesg_buf[tmp_cnt] = 0;
      fprintf(stderr, "%s", dmesg_buf);
      cnt += tmp_cnt;
    }
    usleep(1000);
  }
}

void reconfigure_dfs() {

// wait servers before current node are already setupped
#if MDEBUG
  fprintf(stderr, "executor %lld reconfigure_dfs srvSetupBit %lx\n",
          executor_index, execCtl->srvSetupBit);
#endif
  if (output_ctl_pos->executionFinished < CALLOFFSET) {
    for (uint64 i = 0; i < executor_index; i++) {
      uint64_t mask = ((uint64_t)1) << i;
      while (execCtl->srvSetupBit & mask) {
      }
    }
    __sync_synchronize();

    if (is_dfs_client) {
      usleep(5000000);
    }

#if MDEBUG
    fprintf(stderr, "------ executor %lld reconfigure DFS\n", executor_index);
#endif
    char cmdbuf[200];
    snprintf(cmdbuf, 100, "/root/%s-node-up.sh %s %s %lld", dfs_name, init_ip,
             dfs_setup_params, executor_index);
    if (cmdbuf[0] != 0) {
#if MDEBUG
      fprintf(stderr, "----------executor %lld executing cmd: %s",
              executor_index, cmdbuf);
#endif
      FILE *cmd = popen(cmdbuf, "r");
#if MDEBUG
      char result[1000] = {0x0};
      while (fgets(result, sizeof(result), cmd) != NULL)
        fprintf(stderr, "---- executor %lld config DFS: %s\n", executor_index,
                result);
#endif
      pclose(cmd);
    }

    // Tell other nodes we finished reconfiguration.
    uint64_t mask = ~(((uint64_t)1) << executor_index);
    sync_lock();
    execCtl->srvSetupBit &= mask;
    sync_unlock();
  }

  handshake_req req = {};
  int fd = open("/root/req", O_CREAT | O_RDWR);
  read(fd, &req, sizeof(req));
  close(fd);

  if (req.magic != kInMagic)
    failmsg("bad handshake magic", "magic=0x%llx", req.magic);
  fprintf(stderr, "req.flags %llx\n", req.flags);
  parse_env_flags(req.flags);
  procid = req.pid;
  // read the input before crash to obtain test dir index.
  static execute_req req1;
  memcpy(&req1, ((char *)input_data) + sizeof(struct executeControl),
         sizeof(req1));
  execution_index = req1.execution_index;

#if MDEBUG
  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(stderr, "syz_reboot() time reconfigure finishes at %ld:%ld\n",
          tv.tv_sec, tv.tv_usec);

  fprintf(stderr, "------ executor %lld restarting tag bit %d\n",
          executor_index, output_ctl_pos->executionFinished);
#endif

  // change to work dir
  // server:/root, client:/root/dfs-client
  char cwdbuf[240] = "/root";
  if (is_dfs_client) {
    sprintf(cwdbuf, "/root/%s-client", dfs_name);
  }
  if (chdir(cwdbuf)) {
    char outmsg[1024];
    snprintf(outmsg, 1023, "failed to chdir. ---- is_client: %s\n", cwdbuf);
    fail(outmsg);
  }
}

void network_fault_injection(int delay, int loss, int corrupt) {

  /*
  delay: tc qdisc add dev eth0 root netem delay 200ms
  loss: tc qdisc add dev eth0 root netem loss 10%
  corrupt: tc qdisc change dev eth0 root netem corrupt 5%
  */
  char cmdbuf[240];
  // tc qdisc del dev eth0 root
  snprintf(cmdbuf, 239, "tc qdisc del dev eth0 root; \
                           tc qdisc add dev eth0 root netem delay %dms loss %d%% corrupt %d%%",
           delay, loss, corrupt);
  FILE *cmd = popen(cmdbuf, "r");
#if MDEBUG
  char result[1000] = {0x0};
  while (fgets(result, sizeof(result), cmd) != NULL)
    fprintf(stderr, "----------executor %lld fault injection popen: %s\n",
            executor_index, result);
#endif
  pclose(cmd);

  if (!strcmp(dfs_name, "nfs")) {
    int ret = system("echo 10 > /sys/kernel/debug/fail_sunrpc/probability; \
                printf %#x 30 > /sys/kernel/debug/fail_sunrpc/times; \
                echo 2 > /sys/kernel/debug/fail_sunrpc/verbose");
    if (ret < 0)
      fail("setup fail_sunrpc failed\n");
  }
}

void disk_fault_injection(int prob, int times, int enable) {

  if ((!strcmp(dfs_name, "nfs") && !is_dfs_client) ||
      (!strcmp(dfs_name, "cephfs") && !is_dfs_client && executor_index != 0)) {
    char cmdbuf[540];
    snprintf(cmdbuf, 539,
             "echo %d > /sys/kernel/debug/fail_make_request/probability; \
                          printf %%#x %d > /sys/kernel/debug/fail_make_request/times; \
                          echo 2 > /sys/kernel/debug/fail_make_request/verbose; \
                          echo %d >  /sys/devices/pci0000:00/0000:00:05.0/virtio2/block/vda/make-it-fail",
             prob, times, enable);
    int ret = system(cmdbuf);
    if (ret < 0)
      fail("set fail_make_request for IO disk failed\n");
  }
}

void parse_env_flags(uint64 flags) {
  // Note: Values correspond to ordering in pkg/ipc/ipc.go, e.g.
  // FlagSandboxNamespace
  flag_debug = flags & (1 << 0);
  flag_coverage = flags & (1 << 1);
  if (flags & (1 << 2))
    flag_sandbox_setuid = true;
  else if (flags & (1 << 3))
    flag_sandbox_namespace = true;
  else if (flags & (1 << 4))
    flag_sandbox_android = true;
  else
    flag_sandbox_none = true;
  flag_extra_coverage = flags & (1 << 5);
  flag_net_injection = flags & (1 << 6);
  flag_net_devices = flags & (1 << 7);
  flag_net_reset = flags & (1 << 8);
  flag_cgroups = flags & (1 << 9);
  flag_close_fds = flags & (1 << 10);
  flag_devlink_pci = flags & (1 << 11);
  flag_vhci_injection = flags & (1 << 12);
  flag_wifi = flags & (1 << 13);
}
/*
void client_setup(char *dfs_name) {
  int loop_times = 0;

  //system("systemctl restart nfs-kernel-server");
  //mount(":/", "/root/nfs-client", "nfs", 0, "vers=4.2,addr=127.0.0.1");
  //return;

  while (loop_times < 1000) {
    sleep(1);
    if (!strcmp(dfs_name, "nfs")) {
      char data[120];
      snprintf(data, 119, "vers=4.2,addr=%s,timeo=1,retrans=1", init_ip);
      if (mount(":/", "/root/nfs-client", "nfs", 0, data) != -1) {
        break;
      }
    } else if (!strcmp(dfs_name, "cephfs") || !strcmp(dfs_name, "glusterfs")) {
      break;
    } else {
      fail("Unsupported DFS");
    }
    loop_times++;
  }
  if (loop_times == 1000) {
    fail("mount DFS failed");
  }
}
*/

void recordReq(handshake_req req) {
  int fd = open("/root/req", O_CREAT | O_RDWR);
  write(fd, &req, sizeof(req));
  close(fd);
  sync_file("/root/req");
}

#if SYZ_EXECUTOR_USES_FORK_SERVER
void receive_handshake() {
#if MDEBUG
  fprintf(stderr, "executor %lld before receiving handshake request\n", executor_index);
#endif

  // mount dfs and chdir
  if (executor_index == 0) {
    char cmdbuf[120];
    snprintf(cmdbuf, 119, "/root/%s-config.sh %s %s 2>&1", dfs_name, init_ip,
             dfs_setup_params);
    FILE *cmd = popen(cmdbuf, "r");
    if (cmd != NULL) {
#if MDEBUG
      char result[1000] = {0x0};
      while (fgets(result, sizeof(result), cmd) != NULL)
        fprintf(stderr, "---- executor %lld config DFS: %s\n", executor_index,
                result);
#endif
      pclose(cmd);
    }
  }

  // change to work dir
  // server:/root, client:/root/dfs-client
  char cwdbuf[240] = "/root";
  if (is_dfs_client) {
    sprintf(cwdbuf, "/root/%s-client", dfs_name);
  }
  if (chdir(cwdbuf)) {
    char outmsg[1024];
    snprintf(outmsg, 1023, "failed to chdir. ---- is_client: %s\n", cwdbuf);
    fail(outmsg);
  }

  handshake_req req = {};
  // int n = read(kInPipeFd, &req, sizeof(req));
  // tao added
  while (!execCtl->hasTestcase[executor_index]) {
  }
  __sync_synchronize();

  execCtl->hasTestcase[executor_index] = 0;
  memcpy(&req, ((char *)input_data) + sizeof(struct executeControl),
         sizeof(req));
  // record handshake request for reboot.
  recordReq(req);
  // tao end
  // if (n != sizeof(req))
  //	failmsg("handshake read failed", "read=%d", n);
  if (req.magic != kInMagic)
    failmsg("bad handshake magic", "magic=0x%llx", req.magic);
  fprintf(stderr, "req.flags %llx\n", req.flags);
  parse_env_flags(req.flags);
  procid = req.pid;
}

void reply_handshake() {
  handshake_reply reply = {};
  reply.magic = kOutMagic;
  memcpy(execute_reply_pos, &reply, sizeof(reply));
  debug("executor %lld handshake send reply %x %lx\n", executor_index,
        reply.magic, (char *)(execute_reply_pos) - (char *)output_data_org);
  output_ctl_pos->executionFinished = 1;
  // if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
  //	fail("control pipe write failed");
}
#endif

static execute_req last_execute_req;
uint64 execution_index = 0;

void sync_file(const char *fn) {
  int fd = open(fn, O_RDONLY);
  fsync(fd);
#if MDEBUG
  fprintf(stderr, "fsync test_dir %s %d\n", fn, fd);
#endif
  close(fd);
}

bool make_test_dir(char *cwdbuf) {
  for (int i = 0; i < 100; i++) {
    if (!mkdir(cwdbuf, 0777)) {
      if (enable_c2san) {
        // sync_file(cwdbuf);
        sync_file(mnt_dir);
      }
      return true;
    }
    usleep(100000);
  }
  return false;
}

uint64 receive_execute() {

  execute_req &req = last_execute_req;
  // tao del
  // if (read(kInPipeFd, &req, sizeof(req)) != (ssize_t)sizeof(req))
  //	fail("control pipe read failed");
  // tao end
  fprintf(stderr, "before receive testcase: %lld %d\n", is_restarting,
          output_ctl_pos->executionFinished);
  // tao added
  while (!execCtl->hasTestcase[executor_index] &&
         !(is_restarting && output_ctl_pos->executionFinished >= CALLOFFSET)) {
  }
  __sync_synchronize();

  // initialize synchBit
  // execCtl->synchBit = 0;

#if MDEBUG
  fprintf(stderr, "----- executor %lld receive testcase\n", executor_index);
#endif
  execCtl->hasTestcase[executor_index] = 0;
  memcpy(&req, ((char *)input_data) + sizeof(struct executeControl),
         sizeof(req));
  if (req.magic != kInMagic)
    failmsg("bad execute request magic", "magic=0x%llx", req.magic);

  execution_index = req.execution_index;

  // update progData offset from execute_req
  prog_data_offset = req.prog_offsets[executor_index];
  prog_size = req.prog_sizes[executor_index];
  fprintf(stderr, "executor %lld: prog_data_offset %lld, prog_size %lld\n",
          executor_index, prog_data_offset, prog_size);

  if (req.prog_sizes[executor_index] > kMaxInput)
    failmsg("bad execute prog size", "size=0x%llx",
            req.prog_sizes[executor_index]);

  parse_env_flags(req.env_flags);
  procid = req.pid;
  syscall_timeout_ms = req.syscall_timeout_ms;
  program_timeout_ms = req.program_timeout_ms * 100;
  slowdown_scale = req.slowdown_scale;
  flag_collect_cover = req.exec_flags & (1 << 0);
  flag_dedup_cover = req.exec_flags & (1 << 1);
  flag_comparisons = req.exec_flags & (1 << 2);
  // tao added
  flag_threaded = req.exec_flags & (1 << 3);
  if (executor_index < server_num) {
    flag_threaded = 0;
  }
  // flag_threaded = 0;
  //  tao end
  flag_collide = req.exec_flags & (1 << 4);
  flag_coverage_filter = req.exec_flags & (1 << 5);

  if (!flag_threaded)
    flag_collide = false;
  debug("[%llums] exec opts: executor=%lld procid=%llu threaded=%d collide=%d "
        "cover=%d extra-cover=%d comps=%d dedup=%d"
        " timeouts=%llu/%llu/%llu prog=%llu filter=%d\n",
        current_time_ms() - start_time_ms, executor_index, procid,
        flag_threaded, flag_collide, flag_collect_cover, flag_extra_coverage,
        flag_comparisons, flag_dedup_cover, syscall_timeout_ms,
        program_timeout_ms, slowdown_scale, req.prog_sizes[executor_index],
        flag_coverage_filter);

  if (syscall_timeout_ms == 0 || program_timeout_ms <= syscall_timeout_ms ||
      slowdown_scale == 0)
    failmsg("bad timeouts", "syscall=%llu, program=%llu, scale=%llu",
            syscall_timeout_ms, program_timeout_ms, slowdown_scale);

  if (SYZ_EXECUTOR_USES_SHMEM) {
    if (!req.prog_sizes[executor_index] && is_dfs_client)
      fail("need_prog: no program");
  }

  // network_fault_injection(10, 5, 5);
  // disk_fault_injection(10, 10, 1);

  char cwdbuf[200], lastcwdbuf[200];
  // snprintf(cwdbuf, 199, "/root/%s-client/", dfs_name);
  snprintf(cwdbuf, 199, "/root/%s-client/dfs-%lld-%lld", dfs_name, req.pid,
           execution_index);

  if (executor_index == server_num) {
    if (execution_index > 0) {
      snprintf(lastcwdbuf, 199, "/root/%s-client/dfs-%lld-%lld", dfs_name,
               req.pid, execution_index - 1);
      fprintf(stderr, "remove dir: %s\n", lastcwdbuf);
      remove_dir(lastcwdbuf);
    }

#if MDEBUG
    fprintf(stderr, "-----finish removing dir\n");
#endif

    if (!make_test_dir(cwdbuf)) {
      debug("mdkir error %s %s\n", cwdbuf, strerror(errno));
      fail("failed to mkdir");
    }

    fprintf(stderr, "executor %lld create dir %s successfully\n",
            executor_index, cwdbuf);
    // sleep(1);
    // tell other clients the current execution dir is ready!
    execCtl->tmpDirEstablished = 1;
  } else {
    while (execCtl->tmpDirEstablished != 1) {
    }
    __sync_synchronize();
  }

  if (is_dfs_client) {
    fprintf(stderr, "current dir: executor %lld: %s\n", executor_index, cwdbuf);
    int times = 0;
    while (chdir(cwdbuf)) {
      if (times < 100000)
        times++;
      else {
        char errbuf[500];
        snprintf(errbuf, 499, "%d executor %lld failed to chdir %s, %s \n", 123,
                 executor_index, cwdbuf, strerror(errno));
        fprintf(stderr, "%s", errbuf);
        fail("executor failed to chdir");
        break;
      }
    }
    fprintf(stderr, "executor %lld chdir times %d\n", executor_index, times);
  }

  if (!is_dfs_client) {
    if (in_kernel(SERVER)) {
      remote_cover_enable(usp_covers, flag_comparisons);
    } else {
      // TODO: why?
      if (!is_restarting)
        usrv_cover_enable(usp_covers, flag_comparisons);
    }
    execCtl->coverEnabled[executor_index] = 1;
  } else {
    // for (uint64 i = 0; i < server_num; i++) {
    execCtl->coverEnabled[executor_index] = 1;
    __sync_synchronize();
    for (uint64 i = 0; i < vm_count; i++) {
      while (!execCtl->coverEnabled[i]) {
      }
    }
    __sync_synchronize();
  }

  return req.pid;
  // not used in DFS fuzzer
  /*
      if (req.prog_sizes[executor_index - server_num] == 0)
              fail("need_prog: no program");
      uint64 pos = 0;
      for (;;) {
              ssize_t rv = read(kInPipeFd, input_data + pos, sizeof(input_data)
     - pos); if (rv < 0) fail("read failed"); pos += rv; if (rv == 0 || pos >=
     req.prog_sizes[executor_index - server_num]) break;
      }
      if (pos != req.prog_sizes[executor_index - server_num])
              failmsg("bad input size", "size=%lld, want=%lld", pos,
     req.prog_sizes[executor_index - server_num]);
  */
}

#if GOOS_akaros
void resend_execute(int fd) {
  execute_req &req = last_execute_req;
  if (write(fd, &req, sizeof(req)) != sizeof(req))
    fail("child pipe header write failed");
  if (write(fd, input_data, req.prog_sizes[executor_index]) !=
      (ssize_t)req.prog_sizes[executor_index])
    fail("child pipe program write failed");
}
#endif

#if SYZ_EXECUTOR_USES_SHMEM
template <typename cover_data_t>
void write_coverage_signal(cover_t *cov, uint32 *signal_count_pos,
                           uint32 *cover_count_pos, uint32 org_signal_cnt,
                           uint32 org_cover_cnt) {
  // Write out feedback signals.
  // Currently it is code edges computed as xor of two subsequent basic block
  // PCs.
  cover_data_t *cover_data = (cover_data_t *)(cov->data + cov->data_offset);
  uint32 nsig = 0;
  cover_data_t prev_pc = 0;
  bool prev_filter = true;
#if MDEBUG
  /*
  fprintf(stderr,
          "----- executor %lld executes write_coverage_signal cov->size %d, "
          "flag collect %d\n",
          executor_index, cov->size, flag_collect_cover);
  */
#endif
  for (uint32 i = 0; i < cov->size; i++) {
    cover_data_t pc = cover_data[i] + cov->pc_offset;
    uint32 sig = pc;
    // if (executor_index == 3)
    //  fprintf(stderr, "pc cover:0x%x\n", sig);
    if (in_userspace || use_cover_edges(pc))
      sig ^= ::hash(prev_pc);
    bool filter = coverage_filter(pc);
    // Ignore the edge only if both current and previous PCs are filtered out
    // to capture all incoming and outcoming edges into the interesting code.
    bool ignore = !filter && !prev_filter;
    prev_pc = pc;
    prev_filter = filter;
    if (ignore || dedup(sig))
      continue;
    write_output(sig);
    nsig++;
  }
  // Write out number of signals.
  *signal_count_pos = nsig + org_signal_cnt;

  if (!flag_collect_cover) {
#if MDEBUG
    // fprintf(stderr, "----- executor %lld signal number : %d\n", executor_index,
    //        nsig);
#endif
    return;
  }
  // Write out real coverage (basic block PCs).
  uint32 cover_size = cov->size;
  if (flag_dedup_cover) {
    cover_data_t *end = cover_data + cover_size;
    cover_unprotect(cov);
    std::sort(cover_data, end);
    cover_size = std::unique(cover_data, end) - cover_data;
    cover_protect(cov);
  }
  // Truncate PCs to uint32 assuming that they fit into 32-bits.
  // True for x86_64 and arm64 without KASLR.
  for (uint32 i = 0; i < cover_size; i++)
    write_output(cover_data[i] + cov->pc_offset);
#if MDEBUG
  // fprintf(stderr, "----- executor %lld cover number : %d, signal number : %d\n",
  //        executor_index, cover_size, nsig);
#endif
  *cover_count_pos = cover_size + org_cover_cnt;
}
#endif

void wait_other_clts() {
  for (uint64 i = server_num; i < vm_count; i++) {
    while (!(execCtl->executionsFinish[executor_index])) {
    }
  }
  __sync_synchronize();
}

void clt_finish() {
  if (is_dfs_client) {
    // tell servers clients have finished testcases
    execCtl->executionsFinish[executor_index] = 1;
  }
}

#if defined(__i386__)

static __inline__ unsigned long long rdtsc(void) {
  unsigned long long int x;
  __asm__ volatile(".byte 0x0f, 0x31" : "=A"(x));
  return x;
}

#elif defined(__x86_64__)

static __inline__ unsigned long long rdtsc(void) {
  // struct timespec time;
  // clock_gettime(CLOCK_REALTIME, &time);
  // return time.tv_nsec + time.tv_sec * 1000000000;
  unsigned a, d;
  asm volatile("rdtscp" : "=a" (a), "=d" (d));
  asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx");
  return (((unsigned long)a) | (((unsigned long)d) << 32));
}

#endif

void collect_srv_cover(bool wait) {
  // we might call if somewhere client can also enter
  if (!is_dfs_client) {
    // When injecting crash failures to kernel servers, we don't need to wait
    // clients finished.
    if (wait) {
      // wait all clients finished
      for (uint64 i = server_num; i < vm_count; i++) {
        while (!(execCtl->executionsFinish[i])) {
        }
      }
      __sync_synchronize();
    }
#if MDEBUG
    fprintf(stderr, "executor %lld write_server_output\n", executor_index);
#endif
    thread_t placeholder;
    memset(&placeholder, 0, sizeof(placeholder));
    placeholder.stime = rdtsc();
    placeholder.etime = rdtsc();
    placeholder.call_index = -1;
    write_call_output(&placeholder, true, usp_covers);
  }
}

void reply_execute(int status, int iter) {

  clt_finish();
  write_metadata(execution_index);

  execute_reply reply = {};
  reply.magic = kOutMagic;
  reply.done = true;
  reply.status = status;
  memcpy(execute_reply_pos, &reply, sizeof(reply));

  if (in_kernel(SERVER)) {
#if MDEBUG
    fprintf(stderr, "----- executor %lld remote_cover_disable\n",
            executor_index);
#endif
    remote_cover_disable();
  }
  if (is_restarting)
    is_restarting = 0;
  output_ctl_pos->executionFinished = 1;
  // if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
  //	fail("control pipe write failed");
}

void process_before_reboot() {

  return;

  if (!is_dfs_client || (is_dfs_client && in_kernel(CLIENT))) {
    thread_t placeholder;
    memset(&placeholder, 0, sizeof(placeholder));
    write_call_output(&placeholder, true, usp_covers);
    // write_server_output(usp_covers);
  }
  output_ctl_pos->cntTmp = *output_data;
  output_ctl_pos->outputPosTmp = output_pos;

#if MDEBUG
  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(stderr, "----- syz_reboot() time shutdown at %ld:%ld\n", tv.tv_sec,
          tv.tv_usec);
#endif

  FILE *cmd = popen("reboot -f", "r");
  char result[1000] = {0x0};
  while (fgets(result, sizeof(result), cmd) != NULL)
    fprintf(stderr, "----------executor %lld reboot node: %s\n", executor_index,
            result);
  pclose(cmd);
  fprintf(stderr, "----- shutdown finished\n");
}

// execute_one executes program stored in input_data.
int global_call_index = 0;
void execute_one() {

  int time1 = time_now();
#if MDEBUG
  fprintf(stderr,
          "----- execute_one begin, executor %lld restarting execute_one %d, "
          "is_restarting %lld\n",
          executor_index, output_ctl_pos->executionFinished, is_restarting);
#endif

  // Duplicate global collide variable on stack.
  // Fuzzer once come up with ioctl(fd, FIONREAD, 0x920000),
  // where 0x920000 was exactly collide address, so every iteration reset
  // collide to 0.
  bool colliding = false;
#if SYZ_EXECUTOR_USES_SHMEM
  // if (is_restarting) {
  //   output_pos = output_ctl_pos->outputPosTmp;
  //   completed = output_ctl_pos->cntTmp;
  //   output_pos = output_data + *output_pos_value;
  // } else {
  // output_pos = output_data + *output_pos_value;
  // }
  if (!is_restarting) {
    memset(output_data_org, 0,
           sizeof(struct outputControl) + sizeof(execute_reply) +
               sizeof(uint32 **));
    output_pos = output_data;
    *output_pos_value = 0;
    write_output(0); // Number of executed syscalls (updated later).
    // Get the inode of test dir for CephFS concurrent semantic checker.
    if (is_dfs_client) {
        struct stat tmp_stat;
        char cwdbuf[256];
        getcwd(cwdbuf, 256);
        if (stat(cwdbuf, &tmp_stat) != 0) {
            fail("failed to stat the test dir");
        }
        fprintf(stderr, "tmp.stat.st_ino: %lx\n", tmp_stat.st_ino);
        write_output_64(tmp_stat.st_ino);
    } else {
        write_output_64(0);
    }
  } else {
    output_pos = output_data + *output_pos_value;
  }

  /*
  output_pos = output_data;// + *output_pos_value;
  write_output(0);
  */
  fprintf(stderr, "output_pos: %ld, output_pos_value %d\n",
          output_pos - output_data, *output_pos_value);

#endif
  uint64 start = current_time_ms();

retry:
  uint64 *input_pos = (uint64 *)(input_data + prog_data_offset);

  if (flag_coverage && !colliding && is_dfs_client) {
    if (!flag_threaded)
      cover_enable(&threads[0].cov, flag_comparisons, false);
    if (flag_extra_coverage)
      cover_reset(&extra_cov);
  }
  global_call_index = 0;
  uint64 prog_extra_timeout = 0;
  uint64 prog_extra_cover_timeout = 0;
  bool has_fault_injection = false;
  call_props_t call_props;
  memset(&call_props, 0, sizeof(call_props));

  int time2 = time_now();

  for (;;) {
    int time21 = time_now();
    uint64 call_num = read_input(&input_pos);
    if (call_num == instr_eof)
      break;
    if (call_num == instr_copyin) {
      char *addr = (char *)read_input(&input_pos);
      uint64 typ = read_input(&input_pos);
      switch (typ) {
      case arg_const: {
        uint64 size, bf, bf_off, bf_len;
        uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
        copyin(addr, arg, size, bf, bf_off, bf_len);
        break;
      }
      case arg_result: {
        uint64 meta = read_input(&input_pos);
        uint64 size = meta & 0xff;
        uint64 bf = meta >> 8;
        uint64 val = read_result(&input_pos);
        copyin(addr, val, size, bf, 0, 0);
        break;
      }
      case arg_data: {
        uint64 size = read_input(&input_pos);
        size &= ~(1ull << 63); // readable flag
        NONFAILING(memcpy(addr, input_pos, size));
        // Read out the data.
        for (uint64 i = 0; i < (size + 7) / 8; i++)
          read_input(&input_pos);
        break;
      }
      case arg_csum: {
        debug_verbose("checksum found at %p\n", addr);
        uint64 size = read_input(&input_pos);
        char *csum_addr = addr;
        uint64 csum_kind = read_input(&input_pos);
        switch (csum_kind) {
        case arg_csum_inet: {
          if (size != 2)
            failmsg("bag inet checksum size", "size=%llu", size);
          debug_verbose("calculating checksum for %p\n", csum_addr);
          struct csum_inet csum;
          csum_inet_init(&csum);
          uint64 chunks_num = read_input(&input_pos);
          uint64 chunk;
          for (chunk = 0; chunk < chunks_num; chunk++) {
            uint64 chunk_kind = read_input(&input_pos);
            uint64 chunk_value = read_input(&input_pos);
            uint64 chunk_size = read_input(&input_pos);
            switch (chunk_kind) {
            case arg_csum_chunk_data:
              debug_verbose("#%lld: data chunk, addr: %llx, size: %llu\n",
                            chunk, chunk_value, chunk_size);
              NONFAILING(csum_inet_update(&csum, (const uint8 *)chunk_value,
                                          chunk_size));
              break;
            case arg_csum_chunk_const:
              if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8)
                failmsg("bad checksum const chunk size", "size=%lld",
                        chunk_size);
              // Here we assume that const values come to us big endian.
              debug_verbose("#%lld: const chunk, value: %llx, size: %llu\n",
                            chunk, chunk_value, chunk_size);
              csum_inet_update(&csum, (const uint8 *)&chunk_value, chunk_size);
              break;
            default:
              failmsg("bad checksum chunk kind", "kind=%llu", chunk_kind);
            }
          }
          uint16 csum_value = csum_inet_digest(&csum);
          debug_verbose("writing inet checksum %hx to %p\n", csum_value,
                        csum_addr);
          copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
          break;
        }
        default:
          failmsg("bad checksum kind", "kind=%llu", csum_kind);
        }
        break;
      }
      default:
        failmsg("bad argument type", "type=%llu", typ);
      }
      continue;
    }
    if (call_num == instr_copyout) {
      read_input(&input_pos); // index
      read_input(&input_pos); // addr
      read_input(&input_pos); // size
      // The copyout will happen when/if the call completes.
      continue;
    }
    if (call_num == instr_setprops) {
      read_call_props_t(call_props, read_input(&input_pos, false));
      continue;
    }
    int time22 = time_now();

    // Normal syscall.
    if (call_num >= ARRAY_SIZE(syscalls))
      failmsg("invalid syscall number",
              "executor %lld : prog_data_offset %lld org_prog_data_offset %lld "
              "call_num=%llu input_pos=%ld prog_size=%lld",
              executor_index, prog_data_offset,
              last_execute_req.prog_offsets[executor_index], call_num,
              ((char *)input_pos) - (input_data + prog_data_offset), prog_size);
    const call_t *call = &syscalls[call_num];
    if (call->attrs.disabled)
      failmsg("executing disabled syscall", "syscall=%s", call->name);
    if (prog_extra_timeout < call->attrs.prog_timeout)
      prog_extra_timeout = call->attrs.prog_timeout * slowdown_scale;
    if (strncmp(syscalls[call_num].name, "syz_usb", strlen("syz_usb")) == 0)
      prog_extra_cover_timeout =
          std::max(prog_extra_cover_timeout, 500 * slowdown_scale);
    if (strncmp(syscalls[call_num].name, "syz_80211_inject_frame",
                strlen("syz_80211_inject_frame")) == 0)
      prog_extra_cover_timeout =
          std::max(prog_extra_cover_timeout, 300 * slowdown_scale);
    has_fault_injection |= (call_props.fail_nth > 0);
    uint64 copyout_index = read_input(&input_pos);
    uint64 num_args = read_input(&input_pos);
    if (num_args > kMaxArgs)
      failmsg("command has bad number of arguments",
              "executor %lld: prog_data_offset %lld org_prog_data_offset %lld "
              "args=%llu input_pos=%ld prog_size=%lld",
              executor_index, prog_data_offset,
              last_execute_req.prog_offsets[executor_index], num_args,
              ((char *)input_pos) - (input_data + prog_data_offset), prog_size);
    uint64 args[kMaxArgs] = {};
    for (uint64 i = 0; i < num_args; i++)
      args[i] = read_arg(&input_pos);
    for (uint64 i = num_args; i < kMaxArgs; i++)
      args[i] = 0;

    // skip the syscalls before reboot or shutdown
    if (is_restarting) {
      if (output_ctl_pos->executionFinished < CALLOFFSET) {
        char buf[100];
        snprintf(buf, 99,
                 "The call index (%d) is smaller than %d during restarting",
                 output_ctl_pos->executionFinished, CALLOFFSET);
        fail(buf);
        // fail("The call index is smaller than 2 during restarting\n");
      }
      if ((!flag_threaded &&
           global_call_index <=
               (output_ctl_pos->executionFinished - CALLOFFSET)) ||
          (flag_threaded && !strcmp(syscalls[call_num].name, "syz_reboot"))) {
        memset(&call_props, 0, sizeof(call_props));
        global_call_index++;
        continue;
      }
    }

    int time23 = time_now();

    thread_t *th =
        schedule_call(global_call_index++, call_num, colliding, copyout_index,
                      num_args, args, input_pos, call_props);

    if (colliding && (global_call_index % 2) == 0) {
      // Don't wait for every other call.
      // We already have results from the previous execution.
    } else if (flag_threaded && is_dfs_client) {
      // Wait for call completion.
      uint64 timeout_ms =
          syscall_timeout_ms + call->attrs.timeout * slowdown_scale;
      // This is because of printing pre/post call. Ideally we print everything
      // in the main thread and then remove this (would also avoid intermixed
      // output).
      if (flag_debug && timeout_ms < 1000)
        timeout_ms = 1000;
      if (event_timedwait(&th->done, timeout_ms))
        handle_completion(th);

      // Check if any of previous calls have completed.
      for (int i = 0; i < kMaxThreads; i++) {
        th = &threads[i];
        if (th->executing && event_isset(&th->done))
          handle_completion(th);
      }
    } else {
      // Execute directly.
      // int time231 = time_now();
      if (th != &threads[0])
        fail("using non-main thread in non-thread mode");
      event_reset(&th->ready);
      // int time232 = time_now();
      execute_call(th);
      // int time233 = time_now();
      event_set(&th->done);
      // int time234 = time_now();
      handle_completion(th);
      // int time235 = time_now();
      // fprintf(stderr, "execute_call %d, %d, %d, %d\n", time232 - time231,
      //         time233 - time232, time234 - time233, time235 - time234);
    }
    memset(&call_props, 0, sizeof(call_props));
    int time24 = time_now();
    fprintf(stderr, "execute_one loop: %d, %d, %d\n", time22 - time21,
            time23 - time22, time24 - time23);
  }

  int time3 = time_now();

  if (!colliding && !collide && running > 0) {
    // Give unfinished syscalls some additional time.
    last_scheduled = 0;
    uint64 wait_start = current_time_ms();
    uint64 wait_end = wait_start + 2 * syscall_timeout_ms;
    wait_end = std::max(wait_end, start + program_timeout_ms / 6);
    wait_end = std::max(wait_end, wait_start + prog_extra_timeout);
    while (running > 0 && current_time_ms() <= wait_end) {
      sleep_ms(1 * slowdown_scale);
      for (int i = 0; i < kMaxThreads; i++) {
        thread_t *th = &threads[i];
        if (th->executing && event_isset(&th->done))
          handle_completion(th);
      }
    }
    // Write output coverage for unfinished calls.
    if (running > 0) {
      for (int i = 0; i < kMaxThreads; i++) {
        thread_t *th = &threads[i];
        if (th->executing) {
          if (flag_coverage)
            cover_collect(&th->cov);
          write_call_output(th, false, NULL);
        }
      }
    }
  }

#if SYZ_HAVE_CLOSE_FDS
  close_fds();
#endif

  if (!colliding && !collide && is_dfs_client && in_kernel(CLIENT)) {
    write_extra_output();
    // Check for new extra coverage in small intervals to avoid situation
    // that we were killed on timeout before we write any.
    // Check for extra coverage is very cheap, effectively a memory load.
    const uint64 kSleepMs = 100;
    for (uint64 i = 0; i < prog_extra_cover_timeout / kSleepMs; i++) {
      sleep_ms(kSleepMs);
      write_extra_output();
    }
  }

  if (flag_collide && !colliding && !has_fault_injection && !collide) {
    debug("enabling collider\n");
    collide = colliding = true;
    goto retry;
  }

  /*
  if (is_dfs_client && !in_kernel(CLIENT)) {
        #if MDEBUG
    fprintf(stderr, "------ executor %lld write fuse client code\n",
  executor_index); #endif write_server_output(usp_covers);
  }
  */
  int time4 = time_now();
  fprintf(stderr, "executor %lld, execute_one inner time: %d, %d, %d\n",
          executor_index, time2 - time1, time3 - time2, time4 - time3);
}

thread_t *schedule_call(int call_index, int call_num, bool colliding,
                        uint64 copyout_index, uint64 num_args, uint64 *args,
                        uint64 *pos, call_props_t call_props) {
  // Find a spare thread to execute the call.
  int i = 0;
  for (; i < kMaxThreads; i++) {
    thread_t *th = &threads[i];
    if (!th->created)
      thread_create(th, i);
    if (event_isset(&th->done)) {
      if (th->executing)
        handle_completion(th);
      break;
    }
  }
  if (i == kMaxThreads)
    exitf("out of threads");
  thread_t *th = &threads[i];
  if (event_isset(&th->ready) || !event_isset(&th->done) || th->executing)
    failmsg("bad thread state in schedule", "ready=%d done=%d executing=%d",
            event_isset(&th->ready), event_isset(&th->done), th->executing);
  last_scheduled = th;
  th->colliding = colliding;
  th->copyout_pos = pos;
  th->copyout_index = copyout_index;
  event_reset(&th->done);
  th->executing = true;
  th->call_index = call_index;
  th->call_num = call_num;
  th->num_args = num_args;
  th->call_props = call_props;
  for (int i = 0; i < kMaxArgs; i++)
    th->args[i] = args[i];
  event_set(&th->ready);
  running++;
  return th;
}

/*
#if SYZ_EXECUTOR_USES_SHMEM
template <typename cover_data_t>
void write_coverage_signal(cover_t* cov, uint32* signal_count_pos, uint32*
cover_count_pos)
{
        // Write out feedback signals.
        // Currently it is code edges computed as xor of two subsequent basic
block PCs. cover_data_t* cover_data = (cover_data_t*)(cov->data +
cov->data_offset); uint32 nsig = 0; cover_data_t prev_pc = 0; bool prev_filter =
true; for (uint32 i = 0; i < cov->size; i++) { cover_data_t pc = cover_data[i] +
cov->pc_offset; uint32 sig = pc; if (use_cover_edges(pc)) sig ^= hash(prev_pc);
                bool filter = coverage_filter(pc);
                // Ignore the edge only if both current and previous PCs are
filtered out
                // to capture all incoming and outcoming edges into the
interesting code. bool ignore = !filter && !prev_filter; prev_pc = pc;
                prev_filter = filter;
                if (ignore || dedup(sig))
                        continue;
                write_output(sig);
                nsig++;
        }
        // Write out number of signals.
    fprintf(stderr, "----- signal number: %d\n", nsig);
        *signal_count_pos = nsig;

        if (!flag_collect_cover)
                return;
        // Write out real coverage (basic block PCs).
        uint32 cover_size = cov->size;
        if (flag_dedup_cover) {
                cover_data_t* end = cover_data + cover_size;
                cover_unprotect(cov);
                std::sort(cover_data, end);
                cover_size = std::unique(cover_data, end) - cover_data;
                cover_protect(cov);
        }
        // Truncate PCs to uint32 assuming that they fit into 32-bits.
        // True for x86_64 and arm64 without KASLR.
        for (uint32 i = 0; i < cover_size; i++)
                write_output(cover_data[i] + cov->pc_offset);
        *cover_count_pos = cover_size;
}
#endif
*/

void handle_completion(thread_t *th) {
  if (event_isset(&th->ready) || !event_isset(&th->done) || !th->executing)
    failmsg("bad thread state in completion", "ready=%d done=%d executing=%d",
            event_isset(&th->ready), event_isset(&th->done), th->executing);
  if (th->res != (intptr_t)-1)
    copyout_call_results(th);
  if (!collide && !th->colliding) {
    write_call_output(th, true, NULL);
    write_extra_output();
  }
  th->executing = false;
  running--;
  if (running < 0) {
    // This fires periodically for the past 2 years (see issue #502).
    fprintf(stderr,
            "running=%d collide=%d completed=%d flag_threaded=%d "
            "flag_collide=%d current=%d\n",
            running, collide, completed, flag_threaded, flag_collide, th->id);
    for (int i = 0; i < kMaxThreads; i++) {
      thread_t *th1 = &threads[i];
      fprintf(stderr,
              "th #%2d: created=%d executing=%d colliding=%d"
              " ready=%d done=%d call_index=%d res=%lld reserrno=%d\n",
              i, th1->created, th1->executing, th1->colliding,
              event_isset(&th1->ready), event_isset(&th1->done),
              th1->call_index, (uint64)th1->res, th1->reserrno);
    }
    exitf("negative running");
  }
}

void copyout_call_results(thread_t *th) {
  if (th->copyout_index != no_copyout) {
    if (th->copyout_index >= kMaxCommands)
      failmsg("result overflows kMaxCommands", "index=%lld", th->copyout_index);
    results[th->copyout_index].executed = true;
    results[th->copyout_index].val = th->res;
  }
  for (bool done = false; !done;) {
    uint64 instr = read_input(&th->copyout_pos);
    switch (instr) {
    case instr_copyout: {
      uint64 index = read_input(&th->copyout_pos);
      if (index >= kMaxCommands)
        failmsg("result overflows kMaxCommands", "index=%lld", index);
      char *addr = (char *)read_input(&th->copyout_pos);
      uint64 size = read_input(&th->copyout_pos);
      uint64 val = 0;
      if (copyout(addr, size, &val)) {
        results[index].executed = true;
        results[index].val = val;
      }
      debug_verbose("copyout 0x%llx from %p\n", val, addr);
      break;
    }
    default:
      done = true;
      break;
    }
  }
}

uint32 read_completed() {
  return __atomic_load_n(output_data, __ATOMIC_ACQUIRE);
}

void write_completed(uint32 completed) {
  __atomic_store_n(output_data, completed, __ATOMIC_RELEASE);
}

void write_server_output(cover_t *usp_covers, uint32 *signal_count_pos,
                         uint32 *cover_count_pos, uint32 *comps_count_pos) {

  /*if (in_kernel(SERVER)) {
          #if MDEBUG
      fprintf(stderr, "----- executor %lld remote_cover_disable\n",
  executor_index); #endif remote_cover_disable();
  }*/

  // uint32 usp_completed = read_completed();
  // if (is_restarting) {
  //  usp_completed = output_ctl_pos->cntTmp;
  //  output_ctl_pos->cntTmp = 0;
  //}

  for (int i = 0; i < SHMCNT; i++) {
    // for (int i = 0; i < 100; i++) {

    cover_t *cov = &(usp_covers[i]);
    if (cov->data == NULL) {
      continue;
    }

    cover_collect(cov);
    if (cov->size == 0) {
      continue;
    }

    if (flag_comparisons) {
      continue;
      // Collect only the comparisons
      uint32 ncomps = cov->size;
      // kcov_comparison_t *start = (kcov_comparison_t *)(cov->data +
      // sizeof(uint64));
      kcov_comparison_t *start =
          (kcov_comparison_t *)(cov->data + cov->data_offset);
      kcov_comparison_t *end = start + ncomps;
      if ((char *)end > cov->data_end)
        failmsg("too many comparisons", "ncomps=%u", ncomps);
      // cover_unprotect(&th->cov);
      std::sort(start, end);
      ncomps = std::unique(start, end) - start;
      // cover_protect(&th->cov);
      uint32 comps_size = 0;
      for (uint32 i = 0; i < ncomps; ++i) {
        if (start[i].ignore())
          continue;
        comps_size++;
        start[i].write();
      }
      // Write out number of comparisons.
      uint32 org_comps_cnt = *comps_count_pos;
      *comps_count_pos = comps_size + org_comps_cnt;
    } else if (flag_coverage) {
      uint32 org_signal_cnt = *signal_count_pos;
      uint32 org_cover_cnt = *cover_count_pos;
      if (is_kernel_64_bit)
        write_coverage_signal<uint64>(cov, signal_count_pos, cover_count_pos,
                                      org_signal_cnt, org_cover_cnt);
      else
        write_coverage_signal<uint32>(cov, signal_count_pos, cover_count_pos,
                                      org_signal_cnt, org_cover_cnt);
    }
  }
}

#define INFOLIMIT 144

void write_call_output(thread_t *th, bool finished, cover_t *usp_covers) {

  fprintf(stderr, "write_call_output executor %lld\n", executor_index);
  uint32 reserrno = 999;
  const bool blocked = finished && th != last_scheduled;
  uint32 call_flags = call_flag_executed | (blocked ? call_flag_blocked : 0);
  completed = read_completed();
  if (finished) {
    reserrno = th->res != -1 ? 0 : th->reserrno;
    call_flags |= call_flag_finished |
                  (th->fault_injected ? call_flag_fault_injected : 0);
  }
#if SYZ_EXECUTOR_USES_SHMEM
  write_output(th->call_index);
  write_output(th->call_num);
  write_output(reserrno);
  uint32 *infotype = write_output(-1);
  uint32 *info = occupy_nbytes(INFOLIMIT);
  // uint32 *infosize = write_output(0);
  // fprintf(stderr, "th->call_num: %d, th->args: %p\n", th->call_num, th->args);
  const call_t *call1 = &syscalls[th->call_num];
  // fprintf(stderr, "th->call_num: %d, th->args: %p, call1->call: %p\n",
  //        syscalls[th->call_num].sys_nr, th->args, call1->call);
  // Not pseudo syscall and not the last coverage collection from servers
  if (call1->call == NULL && th->args != NULL) {
    switch (syscalls[th->call_num].sys_nr) {
    case 0:  // read     (0)
    case 17: // pread64  (17)
    case 89: // readlink (89)
      if (th->res != -1) {
        uint32_t crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (unsigned char *)th->args[1], th->res);
        // fprintf(stderr, "crc32: %s %ld %u\n", (char *)th->args[1], th->res,
        //        crc);
        *info = crc;
        *infotype = 89;
      }
      break;
    case 4: // stat  (4)
    case 5: // fstat (5)
      if (th->res != -1) {
        memcpy((char *)info, (char *)th->args[1], sizeof(struct stat));
        *infotype = 4;
      }
      break;
    case 191: // getxattr  (191)
    case 192: // lgetxattr (192)
    case 193: // fgetxattr (193)
      if (th->res > 0) {
        // int namelen = strlen((char *)th->args[1]);
        int total = 4 + th->res;
        if (total > INFOLIMIT)
          break;
        *(int *)info = total;
        // memcpy((char *)info + 4, (char *)th->args[1], namelen);
        // memcpy((char *)info + 4 + namelen, ":", 1);
        memcpy((char *)info + 4, (char *)th->args[2], th->res);
        *infotype = 191;
      }
      break;
    case 194: // listxattr  (194)
    case 195: // llistxattr (195)
    case 196: // flistxattr (196)
      if (th->res > 0) {
        // listxattr returns the lenght of xattr even if buf is null
        if (th->args[2] && th->args[1]) {
          memcpy((char *)info, (char *)th->args[1], th->res);
          char *info_c = (char *)info;
          for (int pos = 0; pos < th->res and pos <= INFOLIMIT; pos++) {
            if (info_c[pos] == '\0')
              info_c[pos] = ';';
          }
          if (th->res == 0) {
            info_c[th->res] = 0;
          } else {
            info_c[th->res - 1] = 0;
          }
          // fprintf(stderr, "xattr: %s\n", (char *)info_c);
          *infotype = 194;
        }
      }
      break;
    case 78: // getdents (78) : Success: number of bytes, End of directory: 0,
             // Error: -1
      if (th->res > 0) {
        struct dirent *startp = (struct dirent *)th->args[1];
        for (struct dirent *cur = startp;
             (cur - startp) * sizeof(struct dirent) <=
             (long unsigned int)th->res;
             cur++) {
          // if (cur != startp) strcat((char *)info, ";");
          strcat((char *)info, cur->d_name);
          strcat((char *)info, ";");
        }
        strcat((char *)info, ";");
        fprintf(stderr, "dents:%s\n", (char *)info);
        *infotype = 78;
        break;
      }
    default:
      break;
    }
    fprintf(stderr, "infotype: %d\n", *infotype);
  }

  // starting and ending time
  write_output_64(th->stime);
  write_output_64(th->etime);
  write_output(call_flags);

  if (th->cov.data) {
    fprintf(stderr,
            "----- executor %lld write_call_output, size %d, pid %d, write "
            "pid:%ld\n",
            executor_index, th->cov.size, gettid(),
            ((uint64_t *)(th->cov.data))[2]);
  }

  uint32 *signal_count_pos = write_output(0); // filled in later
  uint32 *cover_count_pos = write_output(0);  // filled in later
  uint32 *comps_count_pos = write_output(0);  // filled in later

  if (usp_covers) {
    write_server_output(usp_covers, signal_count_pos, cover_count_pos,
                        comps_count_pos);
  }
  // Only write back the per-syscall coverage at clients
  else if (is_dfs_client) {
    if (flag_comparisons) {
      // Collect only the comparisons
      uint32 ncomps = th->cov.size;
      kcov_comparison_t *start =
          (kcov_comparison_t *)(th->cov.data + th->cov.data_offset);
      kcov_comparison_t *end = start + ncomps;
      if ((char *)end > th->cov.data_end)
        failmsg("too many comparisons\n", "ncomps=%u", ncomps);
      cover_unprotect(&th->cov);
      std::sort(start, end);
      ncomps = std::unique(start, end) - start;
      cover_protect(&th->cov);
      uint32 comps_size = 0;
      for (uint32 i = 0; i < ncomps; ++i) {
        if (start[i].ignore())
          continue;
        comps_size++;
        start[i].write();
      }
      // Write out number of comparisons.
      *comps_count_pos = comps_size;
    } else if (flag_coverage) {
      if (is_kernel_64_bit)
        write_coverage_signal<uint64>(&th->cov, signal_count_pos,
                                      cover_count_pos, 0, 0);
      else
        write_coverage_signal<uint32>(&th->cov, signal_count_pos,
                                      cover_count_pos, 0, 0);
    }
  }

  // tao added
  write_output_64(th->res);
  // tao end
  debug_verbose("out #%u: index=%u num=%u errno=%d finished=%d blocked=%d "
                "sig=%u cover=%u comps=%u\n",
                completed, th->call_index, th->call_num, reserrno, finished,
                blocked, *signal_count_pos, *cover_count_pos, *comps_count_pos);
  completed++;
  write_completed(completed);
#else
  call_reply reply;
  reply.header.magic = kOutMagic;
  reply.header.done = 0;
  reply.header.status = 0;
  reply.call_index = th->call_index;
  reply.call_num = th->call_num;
  reply.reserrno = reserrno;
  reply.flags = call_flags;
  reply.signal_size = 0;
  reply.cover_size = 0;
  reply.comps_size = 0;
  if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
    fail("control pipe call write failed");
  debug_verbose("out: index=%u num=%u errno=%d finished=%d blocked=%d\n",
                th->call_index, th->call_num, reserrno, finished, blocked);
#endif
}

void write_extra_output() {
#if SYZ_EXECUTOR_USES_SHMEM
  if (!flag_coverage || !flag_extra_coverage || flag_comparisons ||
      !is_dfs_client)
    return;
  cover_collect(&extra_cov);
  if (!extra_cov.size)
    return;
  write_output(-1);                           // call index
  write_output(-1);                           // call num
  write_output(999);                          // errno
  write_output(0);                            // call flags
  uint32 *signal_count_pos = write_output(0); // filled in later
  uint32 *cover_count_pos = write_output(0);  // filled in later
  write_output(0);                            // comps_count_pos
  if (is_kernel_64_bit)
    write_coverage_signal<uint64>(&extra_cov, signal_count_pos, cover_count_pos,
                                  0, 0);
  else
    write_coverage_signal<uint32>(&extra_cov, signal_count_pos, cover_count_pos,
                                  0, 0);
  cover_reset(&extra_cov);
  debug_verbose("extra: sig=%u cover=%u\n", *signal_count_pos,
                *cover_count_pos);
  completed++;
  write_completed(completed);
#endif
}

void thread_create(thread_t *th, int id) {
  th->created = true;
  th->id = id;
  th->executing = false;
  event_init(&th->ready);
  event_init(&th->done);
  event_set(&th->done);
  if (flag_threaded)
    thread_start(worker_thread, th);
}

void *worker_thread(void *arg) {
  thread_t *th = (thread_t *)arg;
  current_thread = th;
  if (flag_coverage && is_dfs_client)
    cover_enable(&th->cov, flag_comparisons, false);
  for (;;) {
    event_wait(&th->ready);
    event_reset(&th->ready);
    execute_call(th);
    event_set(&th->done);
  }
  return 0;
}

void execute_call(thread_t *th) {
  const call_t *call = &syscalls[th->call_num];
  debug("#%lld:%d [%llums] -> %s(", executor_index, th->id,
        current_time_ms() - start_time_ms, call->name);
  for (int i = 0; i < th->num_args; i++) {
    if (i != 0)
      debug(", ");
    debug("0x%llx", (uint64)th->args[i]);
  }

  char tmp_buf[1024] = {0};
#if MDEBUG
  if (getcwd(tmp_buf, 1024) == NULL)
    debug("getcwd in execute_call error");
#endif

  debug(") %d %s\n", th->call_num, tmp_buf);

  // if (th->call_num == 2551) {
  //  debug("the second argument of openat: %s\n", (char *)th->args[1]);
  //}

  int fail_fd = -1;
  th->soft_fail_state = false;
  if (th->call_props.fail_nth > 0) {
    if (collide)
      fail("both collide and fault injection are enabled");
    fail_fd = inject_fault(th->call_props.fail_nth);
    th->soft_fail_state = true;
  }

  if (flag_coverage && is_dfs_client) {
    fprintf(stderr, "cover_reset in execute_call\n");
    cover_reset(&th->cov);
  }
  // For pseudo-syscalls and user-space functions NONFAILING can abort before
  // assigning to th->res. Arrange for res = -1 and errno = EFAULT result for
  // such case.
  th->res = -1;
  errno = EFAULT;
  // Get the syscall execution starting time
  th->stime = rdtsc();
  if (!strcmp(call->name, "syz_failure_down")) {
    write_call_output(th, false, NULL);
  }
  NONFAILING(th->res = execute_syscall(call, th->args, th->call_index));
  // Get the syscall execution ending time
  th->etime = rdtsc();
  // Save the output of read-type syscalls
  th->reserrno = errno;
  // Our pseudo-syscalls may misbehave.
  if ((th->res == -1 && th->reserrno == 0) || call->attrs.ignore_return)
    th->reserrno = EINVAL;
  // Reset the flag before the first possible fail().
  th->soft_fail_state = false;

  if (flag_coverage && is_dfs_client) {
    cover_collect(&th->cov);
    if (th->cov.size >= kCoverSize)
      failmsg("too much cover", "thr=%d, cov=%u", th->id, th->cov.size);
  }
  th->fault_injected = false;

  if (th->call_props.fail_nth > 0)
    th->fault_injected = fault_injected(fail_fd);

  debug("#%lld:%d [%llums] <- %s=0x%llx errno=%d ", executor_index, th->id,
        current_time_ms() - start_time_ms, call->name, (uint64)th->res,
        th->reserrno);
  if (flag_coverage && is_dfs_client)
    debug("cover=%u ", th->cov.size);
  if (th->call_props.fail_nth > 0)
    debug("fault=%d ", th->fault_injected);
  debug(" %s\n", tmp_buf);
}

/*
void execute_call(thread_t *th) {
  const call_t *call = &syscalls[th->call_num];
  debug("#%d [%llums] -> %s(", th->id, current_time_ms() - start_time_ms,
        call->name);
  for (int i = 0; i < th->num_args; i++) {
    if (i != 0)
      debug(", ");
    debug("0x%llx", (uint64)th->args[i]);
  }

  debug(") %d\n", th->call_num);

  if (strstr(call->name, "write"))
     fprintf(stderr, "write's 3th arg: %lu\n", th->args[2]);

  int fail_fd = -1;
  th->soft_fail_state = false;
  if (th->call_props.fail_nth > 0) {
    if (collide)
      fail("both collide and fault injection are enabled");
    fail_fd = inject_fault(th->call_props.fail_nth);
    th->soft_fail_state = true;
  }

  if (flag_coverage)
    cover_reset(&th->cov);
  // For pseudo-syscalls and user-space functions NONFAILING can abort before
  // assigning to th->res. Arrange for res = -1 and errno = EFAULT result for
  // such case.
  th->res = -1;
  errno = EFAULT;
  int time1 = time_now();
  NONFAILING(th->res = execute_syscall(call, th->args));
  int time2 = time_now();
  fprintf(stderr, "execute_syscall %d %d\n", call->sys_nr, time2-time1);
  th->reserrno = errno;
  // Our pseudo-syscalls may misbehave.
  if ((th->res == -1 && th->reserrno == 0) || call->attrs.ignore_return)
    th->reserrno = EINVAL;
  // Reset the flag before the first possible fail().
  th->soft_fail_state = false;

  if (flag_coverage) {
    cover_collect(&th->cov);
    if (th->cov.size >= kCoverSize)
      failmsg("too much cover", "thr=%d, cov=%u", th->id, th->cov.size);
  }
  th->fault_injected = false;

  if (th->call_props.fail_nth > 0)
    th->fault_injected = fault_injected(fail_fd);

  debug("#%d [%llums] <- %s=0x%llx",
              th->id, current_time_ms() - start_time_ms, call->name,
(uint64)th->res); if (flag_coverage) debug("cover=%u ", th->cov.size); if
(th->call_props.fail_nth > 0) debug("fault=%d ", th->fault_injected);
  debug("\n");
}
*/

#if SYZ_EXECUTOR_USES_SHMEM
static uint32 hash(uint32 a) {
  a = (a ^ 61) ^ (a >> 16);
  a = a + (a << 3);
  a = a ^ (a >> 4);
  a = a * 0x27d4eb2d;
  a = a ^ (a >> 15);
  return a;
}

const uint32 dedup_table_size = 8 << 10;
uint32 dedup_table[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
// The hashmap is global which means that we deduplicate across different calls.
// This is OK because we are interested only in new signals.
static bool dedup(uint32 sig) {
  for (uint32 i = 0; i < 4; i++) {
    uint32 pos = (sig + i) % dedup_table_size;
    if (dedup_table[pos] == sig)
      return true;
    if (dedup_table[pos] == 0) {
      dedup_table[pos] = sig;
      return false;
    }
  }
  dedup_table[sig % dedup_table_size] = sig;
  return false;
}
#endif

template <typename T>
void copyin_int(char *addr, uint64 val, uint64 bf, uint64 bf_off,
                uint64 bf_len) {
  if (bf_off == 0 && bf_len == 0) {
    *(T *)addr = swap(val, sizeof(T), bf);
    return;
  }
  T x = swap(*(T *)addr, sizeof(T), bf);
  debug_verbose("copyin_int<%zu>: old x=0x%llx\n", sizeof(T), (uint64)x);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  const uint64 shift = sizeof(T) * CHAR_BIT - bf_off - bf_len;
#else
  const uint64 shift = bf_off;
#endif
  x = (x & ~BITMASK(shift, bf_len)) | ((val << shift) & BITMASK(shift, bf_len));
  debug_verbose("copyin_int<%zu>: new x=0x%llx\n", sizeof(T), (uint64)x);
  *(T *)addr = swap(x, sizeof(T), bf);
}

void copyin(char *addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off,
            uint64 bf_len) {
  debug_verbose(
      "copyin: addr=%p val=0x%llx size=%llu bf=%llu bf_off=%llu bf_len=%llu\n",
      addr, val, size, bf, bf_off, bf_len);
  if (bf != binary_format_native && bf != binary_format_bigendian &&
      (bf_off != 0 || bf_len != 0))
    failmsg("bitmask for string format", "off=%llu, len=%llu", bf_off, bf_len);
  switch (bf) {
  case binary_format_native:
  case binary_format_bigendian:
    NONFAILING(switch (size) {
      case 1:
        copyin_int<uint8>(addr, val, bf, bf_off, bf_len);
        break;
      case 2:
        copyin_int<uint16>(addr, val, bf, bf_off, bf_len);
        break;
      case 4:
        copyin_int<uint32>(addr, val, bf, bf_off, bf_len);
        break;
      case 8:
        copyin_int<uint64>(addr, val, bf, bf_off, bf_len);
        break;
      default:
        failmsg("copyin: bad argument size", "size=%llu", size);
    });
    break;
  case binary_format_strdec:
    if (size != 20)
      failmsg("bad strdec size", "size=%llu", size);
    NONFAILING(sprintf((char *)addr, "%020llu", val));
    break;
  case binary_format_strhex:
    if (size != 18)
      failmsg("bad strhex size", "size=%llu", size);
    NONFAILING(sprintf((char *)addr, "0x%016llx", val));
    break;
  case binary_format_stroct:
    if (size != 23)
      failmsg("bad stroct size", "size=%llu", size);
    NONFAILING(sprintf((char *)addr, "%023llo", val));
    break;
  default:
    failmsg("unknown binary format", "format=%llu", bf);
  }
}

bool copyout(char *addr, uint64 size, uint64 *res) {
  return NONFAILING(switch (size) {
    case 1:
      *res = *(uint8 *)addr;
      break;
    case 2:
      *res = *(uint16 *)addr;
      break;
    case 4:
      *res = *(uint32 *)addr;
      break;
    case 8:
      *res = *(uint64 *)addr;
      break;
    default:
      failmsg("copyout: bad argument size", "size=%llu", size);
  });
}

uint64 read_arg(uint64 **input_posp) {
  uint64 typ = read_input(input_posp);
  switch (typ) {
  case arg_const: {
    uint64 size, bf, bf_off, bf_len;
    uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
    if (bf != binary_format_native && bf != binary_format_bigendian)
      failmsg("bad argument binary format", "format=%llu", bf);
    if (bf_off != 0 || bf_len != 0)
      failmsg("bad argument bitfield", "off=%llu, len=%llu", bf_off, bf_len);
    return swap(val, size, bf);
  }
  case arg_result: {
    uint64 meta = read_input(input_posp);
    uint64 bf = meta >> 8;
    if (bf != binary_format_native)
      failmsg("bad result argument format", "format=%llu", bf);
    return read_result(input_posp);
  }
  default:
    failmsg("bad argument type", "type=%llu", typ);
  }
}

uint64 swap(uint64 v, uint64 size, uint64 bf) {
  if (bf == binary_format_native)
    return v;
  if (bf != binary_format_bigendian)
    failmsg("bad binary format in swap", "format=%llu", bf);
  switch (size) {
  case 2:
    return htobe16(v);
  case 4:
    return htobe32(v);
  case 8:
    return htobe64(v);
  default:
    failmsg("bad big-endian int size", "size=%llu", size);
  }
}

uint64 read_const_arg(uint64 **input_posp, uint64 *size_p, uint64 *bf_p,
                      uint64 *bf_off_p, uint64 *bf_len_p) {
  uint64 meta = read_input(input_posp);
  uint64 val = read_input(input_posp);
  *size_p = meta & 0xff;
  uint64 bf = (meta >> 8) & 0xff;
  *bf_off_p = (meta >> 16) & 0xff;
  *bf_len_p = (meta >> 24) & 0xff;
  uint64 pid_stride = meta >> 32;
  val += pid_stride * procid;
  *bf_p = bf;
  return val;
}

uint64 read_result(uint64 **input_posp) {
  uint64 idx = read_input(input_posp);
  uint64 op_div = read_input(input_posp);
  uint64 op_add = read_input(input_posp);
  uint64 arg = read_input(input_posp);
  if (idx >= kMaxCommands)
    failmsg("command refers to bad result", "result=%lld", idx);
  if (results[idx].executed) {
    arg = results[idx].val;
    if (op_div != 0)
      arg = arg / op_div;
    arg += op_add;
  }
  return arg;
}

uint64 read_input(uint64 **input_posp, bool peek) {
  uint64 *input_pos = *input_posp;
  if ((char *)input_pos >= input_data + kMaxInput)
    failmsg("input command overflows input", "pos=%p: [%p:%p)", input_pos,
            input_data, input_data + kMaxInput);
  if (!peek)
    *input_posp = input_pos + 1;
  return *input_pos;
}

#if SYZ_EXECUTOR_USES_SHMEM
uint32 *write_output(uint32 v) {
  if (output_pos < output_data ||
      (char *)output_pos >= (char *)output_data + kMaxOutput)
    failmsg("output overflow", "pos=%p region=[%p:%p]", output_pos, output_data,
            (char *)output_data + kMaxOutput);
  *output_pos = v;
  uint32 *prev = output_pos;
  output_pos++;
  // save output_pos value to this memory for write_metadata function use.
  *output_pos_value = output_pos - output_data;
  // weird bug: return a++ will return a instead of a++
  return prev;
}

uint32 *occupy_nbytes(int n) {
  if (output_pos < output_data ||
      (char *)output_pos >= (char *)output_data + kMaxOutput)
    failmsg("output overflow", "pos=%p region=[%p:%p]", output_pos, output_data,
            (char *)output_data + kMaxOutput);

  uint32 *prev = output_pos;
  output_pos = (uint32 *)((char *)output_pos + n);
  return prev;
}

uint32 *write_output_64(uint64 v) {
  if (output_pos < output_data ||
      (char *)(output_pos + 1) >= (char *)output_data + kMaxOutput)
    failmsg("output overflow", "pos=%p region=[%p:%p]", output_pos, output_data,
            (char *)output_data + kMaxOutput);
  *(uint64 *)output_pos = v;
  output_pos += 2;
  // save output_pos value to this memory for write_metadata function use.
  *output_pos_value = output_pos - output_data;
  return output_pos;
}

#endif

#if SYZ_EXECUTOR_USES_SHMEM
void kcov_comparison_t::write() {
  if (type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK))
    failmsg("invalid kcov comp type", "type=%llx", type);

  // Write order: type arg1 arg2 pc.
  write_output((uint32)type);

  // KCOV converts all arguments of size x first to uintx_t and then to
  // uint64. We want to properly extend signed values, e.g we want
  // int8 c = 0xfe to be represented as 0xfffffffffffffffe.
  // Note that uint8 c = 0xfe will be represented the same way.
  // This is ok because during hints processing we will anyways try
  // the value 0x00000000000000fe.
  switch (type & KCOV_CMP_SIZE_MASK) {
  case KCOV_CMP_SIZE1:
    arg1 = (uint64)(long long)(signed char)arg1;
    arg2 = (uint64)(long long)(signed char)arg2;
    break;
  case KCOV_CMP_SIZE2:
    arg1 = (uint64)(long long)(short)arg1;
    arg2 = (uint64)(long long)(short)arg2;
    break;
  case KCOV_CMP_SIZE4:
    arg1 = (uint64)(long long)(int)arg1;
    arg2 = (uint64)(long long)(int)arg2;
    break;
  }
  bool is_size_8 = (type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8;
  if (!is_size_8) {
    write_output((uint32)arg1);
    write_output((uint32)arg2);
  } else {
    write_output_64(arg1);
    write_output_64(arg2);
  }
}

bool kcov_comparison_t::ignore() const {
  // Comparisons with 0 are not interesting, fuzzer should be able to guess 0's
  // without help.
  if (arg1 == 0 && (arg2 == 0 || (type & KCOV_CMP_CONST)))
    return true;
  if ((type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8) {
    // This can be a pointer (assuming 64-bit kernel).
    // First of all, we want avert fuzzer from our output region.
    // Without this fuzzer manages to discover and corrupt it.
    uint64 out_start = (uint64)output_data; //(uint64)(((char *)output_data) + 1
                                            //+ sizeof(struct execute_reply));
    uint64 out_end = out_start + kMaxOutput;
    if (arg1 >= out_start && arg1 <= out_end)
      return true;
    if (arg2 >= out_start && arg2 <= out_end)
      return true;
#if defined(GOOS_linux)
    // Filter out kernel physical memory addresses.
    // These are internal kernel comparisons and should not be interesting.
    // The range covers first 1TB of physical mapping.
    uint64 kmem_start = (uint64)0xffff880000000000ull;
    uint64 kmem_end = (uint64)0xffff890000000000ull;
    bool kptr1 = arg1 >= kmem_start && arg1 <= kmem_end;
    bool kptr2 = arg2 >= kmem_start && arg2 <= kmem_end;
    if (kptr1 && kptr2)
      return true;
    if (kptr1 && arg2 == 0)
      return true;
    if (kptr2 && arg1 == 0)
      return true;
#endif
  }
  return !coverage_filter(pc);
}

bool kcov_comparison_t::operator==(
    const struct kcov_comparison_t &other) const {
  // We don't check for PC equality now, because it is not used.
  return type == other.type && arg1 == other.arg1 && arg2 == other.arg2;
}

bool kcov_comparison_t::operator<(const struct kcov_comparison_t &other) const {
  if (type != other.type)
    return type < other.type;
  if (arg1 != other.arg1)
    return arg1 < other.arg1;
  // We don't check for PC equality now, because it is not used.
  return arg2 < other.arg2;
}
#endif

void setup_features(char **enable, int n) {
  // This does any one-time setup for the requested features on the machine.
  // Note: this can be called multiple times and must be idempotent.
  flag_debug = true;
#if SYZ_HAVE_FEATURES
  setup_sysctl();
  setup_cgroups();
#endif
  for (int i = 0; i < n; i++) {
    bool found = false;
#if SYZ_HAVE_FEATURES
    for (unsigned f = 0; f < sizeof(features) / sizeof(features[0]); f++) {
      if (strcmp(enable[i], features[f].name) == 0) {
        features[f].setup();
        found = true;
        break;
      }
    }
#endif
    if (!found)
      failmsg("setup features: unknown feature", "feature=%s", enable[i]);
  }
}

void failmsg(const char *err, const char *msg, ...) {
  int e = errno;
  fprintf(stderr, "SYZFAIL: executor %lld: %s\n", executor_index, err);
  if (msg) {
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
  }

  char log_fn[250];
  if (has_asan_logfile(log_fn)) {
    read_log_once(log_fn);
  }

  fprintf(stderr, " (errno %d: %s)\n", e, strerror(e));

  // fail()'s are often used during the validation of kernel reactions to
  // queries that were issued by pseudo syscalls implementations. As fault
  // injection may cause the kernel not to succeed in handling these queries
  // (e.g. socket writes or reads may fail), this could ultimately lead to
  // unwanted "lost connection to test machine" crashes. In order to avoid this
  // and, on the other hand, to still have the ability to signal a disastrous
  // situation, the exit code of this function depends on the current context.
  // All fail() invocations during system call execution with enabled fault
  // injection lead to termination with zero exit code. In all other cases, the
  // exit code is kFailStatus.
  if (current_thread && current_thread->soft_fail_state)
    doexit(0);
  doexit(kFailStatus);
}

void fail(const char *err) { failmsg(err, 0); }

void exitf(const char *msg, ...) {
  int e = errno;
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  va_end(args);
  fprintf(stderr, " (errno %d)\n", e);
  doexit(0);
}

void debug(const char *msg, ...) {
  if (!flag_debug)
    return;
  int err = errno;
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  va_end(args);
  fflush(stderr);
  errno = err;
}

void debug_dump_data(const char *data, int length) {
  if (!flag_debug)
    return;
  int i = 0;
  for (; i < length; i++) {
    debug("%02x ", data[i] & 0xff);
    if (i % 16 == 15)
      debug("\n");
  }
  if (i % 16 != 0)
    debug("\n");
}

// consistency sanitizer agent
void write_metadata(int iter) {
  output_pos = output_data + *output_pos_value;
  uint32 *stat_cnt_ptr = output_pos;
  write_output(0);
  // if the storage of servers are local file system based, extract fs
  // metadata from servers as well.
  if (output_pos &&
      ((((is_dfs_client) || (!is_dfs_client && lfs_based)) && enable_csan) ||
       (is_dfs_client && enable_c2san))) {

    // wait for other clients finish to collect consistency metadata
    for (uint64 i = server_num; i < vm_count; i++) {
      while (!(execCtl->executionsFinish[i])) {
      }
    }
    __sync_synchronize();

#if MDEBUG
    fprintf(stderr, "executor %lld write_metadata\n", executor_index);
#endif

    char cwdbuf[240], orgcwdbuf[240];
    // save original dir
    getcwd(orgcwdbuf, 239);
    if (is_dfs_client)
      snprintf(cwdbuf, 239, "/root/%s-client/dfs-%lld-%d", dfs_name,
               last_execute_req.pid, iter);
    else
      snprintf(cwdbuf, 239, "/root/%s-server/dfs-%lld-%d", dfs_name,
               last_execute_req.pid, iter);

    // Workaround for GlusterFS crash consistency bug
    struct stat tmp;
    errno = 0;
    if (!strcmp(dfs_name, "glusterfs") && stat(cwdbuf, &tmp) < 0) {
      fprintf(stderr,
              "executor %lld write_metadata returns as stat %s errors %s\n",
              executor_index, cwdbuf, strerror(errno));
      return;
    }

    stat_cnt = 0;
    mnt_path_len = strlen(cwdbuf) + 1;
    write_dir_info(cwdbuf, NULL);
#ifdef MDEBUG
    fprintf(stderr,
            "executor %lld write_dir_info begins is_dfs_client:%lld %p %p %d "
            "%ld\n",
            executor_index, is_dfs_client, output_pos, output_data, stat_cnt,
            ((char *)output_pos - (char *)output_data));
#endif
    *stat_cnt_ptr = stat_cnt;
    // restore original dir
    chdir(orgcwdbuf);
  } else {
    *stat_cnt_ptr = -1;
  }
  __sync_synchronize();
}

void print_dirent_stat(struct stat *stat_buf, char *filepath, char *xattr_buf) {

  if (stat_buf) {
    fprintf(stderr, "executor %lld stat file %s:\n \
					 st_dev: %lu \n \
					 st_ino: %lu \n \
					 st_mode: %d \n \
					 st_nlink: %lu \n \
					 st_uid:   %d \n \
					 st_gid:   %d \n \
					 st_rdev:  %lu \n \
					 st_size:  %ld \n \
					 st_blksize: %ld \n \
					 st_blocks:  %ld \n \
					 st_atim:    %ld.%.9ld \n \
					 st_mtim:	 %ld.%.9ld \n \
					 st_ctim:	 %ld.%.9ld \n \
					 xattr_buf:  %s\n",
            executor_index, filepath, stat_buf->st_dev, stat_buf->st_ino,
            stat_buf->st_mode, stat_buf->st_nlink, stat_buf->st_uid,
            stat_buf->st_gid, stat_buf->st_rdev, stat_buf->st_size,
            stat_buf->st_blksize, stat_buf->st_blocks, stat_buf->st_atim.tv_sec,
            stat_buf->st_atim.tv_nsec, stat_buf->st_mtim.tv_sec,
            stat_buf->st_mtim.tv_nsec, stat_buf->st_ctim.tv_sec,
            stat_buf->st_ctim.tv_nsec, xattr_buf);

    switch (stat_buf->st_mode & S_IFMT) {
    case S_IFBLK:
      fprintf(stderr, "file type: block device\n");
      break;
    case S_IFCHR:
      fprintf(stderr, "file type: character device\n");
      break;
    case S_IFDIR:
      fprintf(stderr, "file type: directory\n");
      break;
    case S_IFIFO:
      fprintf(stderr, "file type: FIFO/pipe\n");
      break;
    case S_IFLNK:
      fprintf(stderr, "file type: symlink\n");
      break;
    case S_IFREG:
      fprintf(stderr, "file type: regular file\n");
      break;
    case S_IFSOCK:
      fprintf(stderr, "file type: socket\n");
      break;
    default:
      fprintf(stderr, "file type: unknown?\n");
      break;
    }
  }
}

struct stat stat_zero = {0};
struct dirent dent_zero = {0};

uint32 *write_stat(struct stat *stat_buf, char *filepath, int xattr_len,
                   struct dirent *dent, bool isDir) {

  if (output_pos < output_data ||
      ((char *)output_pos + sizeof(struct stat) + sizeof(struct dirent)) >=
          (char *)output_data + kMaxOutput) {
    failmsg("output overflow", "pos=%p region=[%p:%p]", output_pos, output_data,
            (char *)output_data + kMaxOutput);
  }

  //|size_of_file_path | size_of_xattr | size_of_checksum | size_of_symlink_path
  //| filepath | xattr | checksum | symlink path |  stat metadata |

  // File checksum
  uint32_t crc = 0;
  if (stat_buf && S_ISREG(stat_buf->st_mode))
    crc = get_file_chksum(filepath);

  // symlink_path
  char symlink_path[4096] = {
      0,
  };
  int link_len = 0;
  if (stat_buf && S_ISLNK(stat_buf->st_mode)) {
    link_len = readlink(filepath, symlink_path, sizeof(symlink_path));
    if (link_len < 0) {
      snprintf(errmsg, 599, "write_stat: readlink error %d %s : %s\n", link_len,
               filepath, strerror(errno));
      fail(errmsg);
    }
  }

  // relative path
  char relative_filepath[100];
  snprintf(relative_filepath, 100, "./%s", relative_path(filepath));
  // Write the filepath size, xattr size, checksum size, symlink path size.
  int filepath_size = strlen(relative_filepath);
  write_output(filepath_size);
  write_output(xattr_len);
  write_output(link_len);
  fprintf(stderr, "filepath_size %d xattr_len %d symlink_len %d\n",
          filepath_size, xattr_len, link_len);

  // filepath
  memcpy((void *)output_pos, (const void *)relative_filepath, filepath_size);
  output_pos = (uint32 *)((char *)output_pos + filepath_size);

  // Extended attributes
  memcpy((void *)output_pos, (const void *)xattr_buf, xattr_len);
  output_pos = (uint32 *)((char *)output_pos + xattr_len);

  // checksum
  memcpy((void *)output_pos, (const void *)&crc, sizeof(crc));
  output_pos = (uint32 *)((char *)output_pos + sizeof(crc));

  // symlink path
  memcpy((void *)output_pos, (const void *)symlink_path, link_len);
  output_pos = (uint32 *)((char *)output_pos + link_len);

  // File/directory metadata (stat)
  if (!stat_buf) {
    stat_buf = &stat_zero;
  }
  memcpy((void *)output_pos, (const void *)stat_buf, sizeof(struct stat));
  output_pos = (uint32 *)((char *)output_pos + sizeof(struct stat));

  fprintf(stderr, "print_dirent_stat\n");
  print_dirent_stat(stat_buf, relative_filepath, xattr_buf);

  stat_cnt++;
  return output_pos;
}
