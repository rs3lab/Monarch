#define _GNU_SOURCE
#include <sys/mman.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void print_stat_info(const struct stat *stat_buf) {
    printf("File type:                ");

    switch (stat_buf->st_mode & S_IFMT) {
        case S_IFBLK:  printf("block device\n");            break;
        case S_IFCHR:  printf("character device\n");        break;
        case S_IFDIR:  printf("directory\n");               break;
        case S_IFIFO:  printf("FIFO/pipe\n");               break;
        case S_IFLNK:  printf("symlink\n");                 break;
        case S_IFREG:  printf("regular file\n");            break;
        case S_IFSOCK: printf("socket\n");                   break;
        default:       printf("unknown file type\n");      break;
    }

    printf("Device ID (inode):        %lu\n", (unsigned long)stat_buf->st_ino);
    printf("File mode:                %o\n", stat_buf->st_mode & 0777);
    printf("Link count:               %lu\n", (unsigned long)stat_buf->st_nlink);
    printf("User ID of owner:         %u\n", stat_buf->st_uid);
    printf("Group ID of owner:        %u\n", stat_buf->st_gid);
    printf("Device ID (if special):   %lu\n", (unsigned long)stat_buf->st_rdev);
    printf("Total size, in bytes:     %ld\n", stat_buf->st_size);
    printf("Block size for filesystem: %ld\n", stat_buf->st_blksize);
    printf("Number of 512B blocks:    %ld\n", stat_buf->st_blocks);

    printf("Last access time:         %s", ctime(&stat_buf->st_atime));
    printf("Last modification time:   %s", ctime(&stat_buf->st_mtime));
    printf("Last status change time:  %s", ctime(&stat_buf->st_ctime));
}

int clt3(void) {
  syscall(__NR_open, "./file0\x00", 0x8943ul, 0ul);
}

int clt4(void) {
  
  uint64_t r[1] = {0xffffffffffffffff};

  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  intptr_t res = 0;

  syscall(__NR_unlink, "./file0\000");
  
  *(uint32_t*)0x20000280 = 0x3000000;
  *(uint32_t*)0x20000284 = 6;
  *(uint32_t*)0x20000288 = 0;
  *(uint32_t*)0x2000028c = 1;
  *(uint32_t*)0x20000290 = 0;
  *(uint32_t*)0x20000294 = 0xee01;
  syscall(__NR_setxattr, "./file0\000", "security.capability\000", 0x20000280ul, 0x18ul, 0ul);

  syscall(__NR_setxattr, "./file0\000", "security.SMACK64\000", "\x28\x27\x5b\xff\x00\xed\x48\x0f\x29\x35\x7e\x80\x6c\xbb\x6c\xb7\x45\x2a\x0a\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 8ul, 2ul);


  syscall(__NR_mkdir, "./file0\000", 8ul);
  syscall(__NR_symlink, "./file0\000", "./file0\000");
  res = syscall(__NR_open, "./file0\000", 0ul, 0x20ul);
  //if (res != -1)
  //  r[0] = res;
  return 0;
}

void main(int argc, char **argv){

	int clt = atoi(argv[1]);

	//loop for star
	int mfd = open("/sys/bus/pci/devices/0000:00:10.0/resource2", O_RDWR);
	if (mfd <= 0) printf("open IVSHM error\n");
	volatile char *msg = (char *)mmap(0, 1 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
	if(msg == NULL) printf("mmap failed\n");

	if (clt == 3) {
		//clt4 starts
		while(!msg[1]) {}
		//create file0
		syscall(__NR_open, "./file0", 0x8943ul, 0ul);
		//ping clt4
		msg[0] = 1;
		//wait clt4 finish
		while(!msg[2]) {}
		struct stat stat_buf;
		stat("./file0", &stat_buf);
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
		//print_stat_info(stat_buf);
	} else if (clt == 4) {
		msg[1] = 1;
		while(!msg[0]) {}
		clt4();
		msg[2] = 1;
		struct stat stat_buf;
        	stat("./file0", &stat_buf);
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
		//print_stat_info(stat_buf);
	}
}
