/*
 * Entry point from instrumented code.
 * This is called once per basic-block/edge.
 */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

#include "userspace-kcov.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define notrace __attribute__((no_instrument_function))
#define _RET_IP_    (unsigned long)__builtin_return_address(0)
#define UCOV_CMP_SIZE(n)        ((n) << 1)
#define UCOV_WORDS_PER_CMP 4
#define UCOV_CMP_CONST          (1 << 0)
#define UCOV_TRACE_PC  0
#define UCOV_TRACE_CMP 1

typedef struct {
	unsigned long *area;
	int			  shmid;
}shm_info;

pthread_mutex_t cpy_mutex;
pthread_mutex_t global_info_mutex;

#define shmInfoLen 300
static shm_info shm_infos[shmInfoLen];
static unsigned long *spec_areas[kMaxThreads] = {0};
static uint8_t  spec_areas_init = 0;

static __thread unsigned long *unspec_area = NULL, *dst_spec_area = NULL,
							  *spec_area = NULL, *tls_spec_area = NULL; //[2] = {0}; //AREA_SIZE
static __thread uint8_t unspec_init = 0;
static __thread int shmid, cur_cnt;
static __thread int program_id;
static notrace unsigned long canonicalize_ip(unsigned long ip) {
#ifdef CONFIG_RANDOMIZE_BASE
    ip -= kaslr_offset();
#endif
	ip ^= program_id;
    return ip;
}

static pthread_key_t key1, key2;
static int value = 1, value2 = 2;

void write_log(const char *out){
    int fd = open("/root/log", O_RDWR | O_CREAT | O_APPEND);
    write(fd, out, strlen(out));
    close(fd);
}

int hashProgramName() {
	char commfname[100];
	char progName[100];
	snprintf(commfname, 99, "/proc/%d/comm", getpid());
	int fd = open(commfname, O_RDONLY);
	int n = read(fd, progName, 99);
    long long p = 31, m = 1e9 + 7;
    long long hash = 0;
    long long p_pow = 1;
    for(int i = 0; i < n; i++) {
        hash = (hash + (progName[i] - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash;
}

static void notrace destr_fn(void* argv){

	extern int errno;
	void *tmp = unspec_area;
	fprintf(stderr, "destr_fn: before unspec_area == NULL, shmid %d, thread %d, pid %d\n", shmid, gettid(), getpid());

	if (*(int *)argv == 1) {
		if (unspec_area){
	        shmdt(unspec_area);
	        unspec_area = NULL;
        
	        pthread_mutex_lock(&global_info_mutex);
			if (cur_cnt >= 0 && cur_cnt <= shmInfoLen) {
	        	shm_infos[cur_cnt].area = NULL;
			}
	        pthread_mutex_unlock(&global_info_mutex);
        
	        fprintf(stderr, "destr_fn: executor send back shm %p shmid %d\n", tmp, shmid);
	        int fd2 = open(FIFONAME2, O_RDWR);
	        write(fd2, &shmid, sizeof(shmid));
	        //close(fd2);
    	}
	} else if (*(int *)argv == 2) {
		for(int i=0; i< shmInfoLen; i++) {
			if (shm_infos[i].area) {
				int fd2 = open(FIFONAME2, O_RDWR);
        		write(fd2, &(shm_infos[i].shmid), sizeof(shm_infos[i].shmid));
				shm_infos[i].area = NULL;
			}
		}
	}
}

static void notrace free_tls_area(){
	free(tls_spec_area);
}

static void notrace proc_exit(){
	fprintf(stderr, "proc_exit destr_fn\n");
    destr_fn((void *)&value2);
}

unsigned long* search_area(unsigned long req_pid) {
	for (int i=0; i < kMaxThreads; i++) {
		if (!spec_areas[i]) continue;
		volatile long int cur_pid = spec_areas[i][2];
		if (cur_pid == req_pid) {
			return spec_areas[i];
		}
	}
	return NULL;
}

static void ucov_move_area(int mode, void *dst_area, void *src_area) {
    uint64_t word_size = sizeof(unsigned long);
    uint64_t count_size, entry_size_log;
    uint64_t dst_len, src_len;
    void *dst_entries, *src_entries;
    uint64_t dst_occupied, dst_free, bytes_to_move, entries_moved;

    switch (mode) {
    case UCOV_TRACE_PC:
        dst_len = *(unsigned long *)dst_area;
        src_len = *(unsigned long *)src_area;
        count_size = sizeof(unsigned long) * 3;
        entry_size_log = 3;//__ilog2_u64(sizeof(unsigned long));
        break;
    case UCOV_TRACE_CMP:
        dst_len = *(uint64_t *)dst_area;
        src_len = *(uint64_t *)src_area;
        count_size = sizeof(uint64_t) * 3;
        //BUILD_BUG_ON(!is_power_of_2(KCOV_WORDS_PER_CMP));
        entry_size_log = 5;//__ilog2_u64(sizeof(uint64_t) * UCOV_WORDS_PER_CMP);
        break;
    }

    // As arm can't divide u64 integers use log of entry size.
    if (dst_len > ((AREA_SIZE * word_size - count_size) >>
                entry_size_log))
        return;
    dst_occupied = count_size + (dst_len << entry_size_log);
    dst_free = AREA_SIZE * word_size - dst_occupied;
    bytes_to_move = MIN(dst_free, src_len << entry_size_log);
    dst_entries = dst_area + dst_occupied;
    src_entries = src_area + count_size;
    memcpy(dst_entries, src_entries, bytes_to_move);
    entries_moved = bytes_to_move >> entry_size_log;

    switch (mode) {
    case UCOV_TRACE_PC:
        *(unsigned long *)dst_area = dst_len + entries_moved;
        break;
    case UCOV_TRACE_CMP:
        *(uint64_t *)dst_area = dst_len + entries_moved;
        break;
    default:
        break;
    }
}

void notrace __ucov_start(unsigned int req_pid) {

	if (!req_pid) return;

	//retrieve shared memory
	uint8_t init = 1, non_init = 0, cnt = 0;
	if (!spec_areas_init && atomic_compare_exchange_strong(&spec_areas_init, &non_init, init)) {
        int tmp_shmid, ret;
        int fd = open(FIFONAME3, O_RDONLY | O_NONBLOCK);
        if (fd == -1) {
            return;
        }
        while (1){
            ret = read(fd, &tmp_shmid, sizeof(tmp_shmid));
            if (cnt >= kMaxThreads) break;
            if (ret == sizeof(tmp_shmid)) {
                unsigned long *tmp_area = shmat(tmp_shmid, NULL, 0);
                spec_areas[cnt] = tmp_area;
                cnt ++;
            }
        }
    }
    dst_spec_area = search_area(req_pid);
	if (!dst_spec_area) return;

	if (!tls_spec_area) {
        tls_spec_area = (unsigned long*)malloc(sizeof(unsigned long)*AREA_SIZE);
		//TODO
		if (pthread_key_create(&key2, free_tls_area) < 0) {
        	fprintf(stderr, "pthread_key_create error %s\n", strerror(errno));
    	}
	    pthread_setspecific(key2, (void *)&value);
	}

	//reset cnt
	tls_spec_area[0] = 0;
	//copy cov type
	tls_spec_area[1] = dst_spec_area[1];
	//set spec_area
	spec_area = tls_spec_area;
}

void notrace __ucov_stop(void) {
	if (!dst_spec_area) return;

	//copy spec_area to dst_area
	pthread_mutex_lock(&cpy_mutex);
	int cnt = spec_area[0];
	if (cnt > 0) {
		ucov_move_area(dst_spec_area[1], dst_spec_area, spec_area); //sizeof(unsigned long)*(spec_area[0]+2));
	}
	pthread_mutex_unlock(&cpy_mutex);

	//reset spec_area
	spec_area = NULL;
	dst_spec_area = NULL;
}

void notrace __setup_unspec_area(void) {

	if (unspec_init) return;
	unspec_init = 1;

	//testcase level coverage
	if(access(FIFONAME, F_OK)){
		fprintf(stderr, "executor __sanitizer_cov_trace_pc: no pipe file\n");
	    return;
	}
	int fd = open(FIFONAME, O_RDWR | O_NONBLOCK);
	if (read(fd, &shmid, sizeof(shmid)) != sizeof(shmid)){
		fprintf(stderr, "executor __sanitizer_cov_trace_pc: no shmid remained\n");
		return;
	}

	extern int errno;
    errno = 0;
	//Send finished shmids back through callbacks
	if (getpid() == gettid()) {
		fprintf(stderr, "call atexit in pid %d tid %d\n", getpid(), gettid());
		atexit(proc_exit);
	}
	if (pthread_key_create(&key1, destr_fn) != 0) {
		fprintf(stderr, "pthread_key_create error %s\n", strerror(errno));
	}
	pthread_setspecific(key1, (void *)&value);

	fprintf(stderr, "executor __sanitizer_cov_trace_pc: retrieve shmid %d, thread %d, pid %d, value %d\n",
				shmid, gettid(), getpid(), *(int *)pthread_getspecific(key1));	

	//shmat
	errno = 0;
    unspec_area = (unsigned long *)shmat(shmid, NULL, 0);
    if (unspec_area == (unsigned long *)-1){
		unspec_area = NULL;
		fprintf(stderr, "Executor shmat error %s, shmid %d shmem -1 pthread_key_create\n",
 				strerror(errno), shmid);
    }

	//assign a unique id to different programs
	program_id = hashProgramName();

	pthread_mutex_lock(&global_info_mutex);
	shm_info cur_info = {unspec_area, shmid};
	//cur_cnt = shm_cnt;
	for(int i=0; i < shmInfoLen; i++) {
		if (shm_infos[i].area == NULL) {
			cur_cnt = i;
			shm_infos[cur_cnt] = cur_info;
			break;
		}
	}
	if (shmInfoLen == 0) cur_cnt = -1;
	//shm_cnt ++;
	pthread_mutex_unlock(&global_info_mutex);

	/*
	char buf[100];
	sprintf(buf, "Executor Process %d %d shmid %d shmem %p pthread_key_create\n", getpid(), gettid(), shmid, unspec_area);
	write_log(buf);
	*/
    //unspec_area[0] = 1;
}

void notrace __sanitizer_cov_trace_pc(void) {

	if (!unspec_area) __setup_unspec_area();

	unsigned long *cur_area = spec_area ? spec_area : unspec_area;
	if (!cur_area) return;

	if (cur_area[1] !=  UCOV_TRACE_PC) {
		/*
		char buf[100];
		sprintf(buf, "__sanitizer_cov_trace_pc: %d\n", cur_area[1]);
		write_log(buf);
		*/
		return;
	}

	/*
	char buf[100];
    sprintf(buf, "Executor Process %d %d shmid %d shmem %p trace_pc\n", getpid(), gettid(), shmid, cur_area);
    write_log(buf);
	*/

    // cur_area[0]: the number of subsequent PCs, cur_area[2]: KCOV_MODE_TRACE_CMP and KCOV_MODE_TRACE_PC
	unsigned long cnt, pos;
    cnt = cur_area[0] + 1;
	pos = cnt + 2;
	
    if (likely(pos < AREA_SIZE)) {
        cur_area[pos] = _RET_IP_; //canonicalize_ip(_RET_IP_);
        cur_area[0] = cnt;
    }
}

static void notrace write_comp_data(uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t ip) {

	//write_log("write_comp_data\n");

	if (!unspec_area) __setup_unspec_area();

	//write_log("after __setup_unspec_area\n");

    unsigned long *cur_area = spec_area ? spec_area : unspec_area;
    if (!cur_area) return;

	/*
	char buf[100];
	sprintf(buf, "after if (!cur_area) return; %d, %d, %d\n", cur_area[0], cur_area[1], cur_area[2]);
	write_log(buf);
	*/

	//KCOV_TRACE_PC = 0; KCOV_TRACE_CMP = 1;
    if (cur_area[1] !=  UCOV_TRACE_CMP) return;

	//write_log("after cur_area[1] !=  UCOV_TRACE_CMP\n");
	
	uint64_t count, start_index, end_pos, max_pos, pos;
	max_pos = AREA_BYTESIZE;
	//ip = canonicalize_ip(ip);
    count = cur_area[0];
	//pos = count + 2;

    /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
    start_index = 3 + count * UCOV_WORDS_PER_CMP;
    end_pos = (start_index + UCOV_WORDS_PER_CMP) * sizeof(uint64_t);
    if (likely(end_pos <= max_pos)) {
        cur_area[start_index] = type;
        cur_area[start_index + 1] = arg1;
        cur_area[start_index + 2] = arg2;
        cur_area[start_index + 3] = ip;
        cur_area[0] = count + 1;
    }
}

void notrace __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {
	//write_log("__sanitizer_cov_trace_cmp1\n");
    write_comp_data(UCOV_CMP_SIZE(0), arg1, arg2, _RET_IP_);
}
void notrace __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {
	//write_log("__sanitizer_cov_trace_cmp2");
    write_comp_data(UCOV_CMP_SIZE(1), arg1, arg2, _RET_IP_);
}
void notrace __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {
	//write_log("__sanitizer_cov_trace_cmp4");
    write_comp_data(UCOV_CMP_SIZE(2), arg1, arg2, _RET_IP_);
}
void notrace __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2)
{
	//write_log("__sanitizer_cov_trace_cmp8");
    write_comp_data(UCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
}
void notrace __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {
    write_comp_data(UCOV_CMP_SIZE(0) | UCOV_CMP_CONST, arg1, arg2,
            _RET_IP_);
}
void notrace __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {
    write_comp_data(UCOV_CMP_SIZE(1) | UCOV_CMP_CONST, arg1, arg2,
            _RET_IP_);
}
void notrace __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {
    write_comp_data(UCOV_CMP_SIZE(2) | UCOV_CMP_CONST, arg1, arg2,
            _RET_IP_);
}
void notrace __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
    write_comp_data(UCOV_CMP_SIZE(3) | UCOV_CMP_CONST, arg1, arg2,
            _RET_IP_);
}
void notrace __sanitizer_cov_trace_cmpf(float Arg1, float Arg2) {
	return;
}

void notrace __sanitizer_cov_trace_cmpd (double Arg1, double Arg2) {
	return;
}

void notrace __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    uint64_t i;
    uint64_t count = cases[0];
    uint64_t size = cases[1];
    uint64_t type = UCOV_CMP_CONST;

    switch (size) {
    case 8:
        type |= UCOV_CMP_SIZE(0);
        break;
    case 16:
        type |= UCOV_CMP_SIZE(1);
        break;
    case 32:
        type |= UCOV_CMP_SIZE(2);
        break;
    case 64:
        type |= UCOV_CMP_SIZE(3);
        break;
    default:
        return;
    }
    for (i = 0; i < count; i++)
        write_comp_data(type, cases[i + 2], val, _RET_IP_);
}

#include <sys/types.h>
#include <unistd.h>
pid_t notrace fork(void){
	fprintf(stderr, "fork hook\n");
    pid_t pid = __libc_fork();
    if (pid == 0) {
        unspec_area = NULL;
        unspec_init = 0;
    }
    return pid;
}
/*
pid_t notrace vfork(void){
    fprintf(stderr, "vfork hook\n");
    pid_t pid = __libc_vfork();
    if (pid == 0) {
        unspec_area = NULL;
        unspec_init = 0;
    }
    return pid;
}
*/
int execvp (const char *file, char *const argv[]) {
	int op = 2;
	fprintf(stderr, "execvp hook\n");
	destr_fn(&op);
	execvpe(file, argv, __environ);
}
