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
		syscall(__NR_open, "./file0", 0x40, 0xa);
		//ping clt4
		msg[0] = 1;
		//wait clt4 finish
		while(!msg[2]) {}
        syscall(__NR_chmod, "./file0", 0x0);
        msg[3] = 1;

		struct stat stat_buf;
		stat("./file0", &stat_buf);
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
		//print_stat_info(stat_buf);
	} else if (clt == 4) {
		msg[1] = 1;
		while(!msg[0]) {}
        int r0 = syscall(__NR_open, "./file0", 0x80e82, 0x0);
        //syscall(__NR_ftruncate, r0, 0x8);
        //syscall(__NR_open, "./file0", 0x0, 0x0);
		msg[2] = 1;

        while(!msg[3]) {}
		struct stat stat_buf;
        stat("./file0", &stat_buf);
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
		//print_stat_info(stat_buf);
	}
}
