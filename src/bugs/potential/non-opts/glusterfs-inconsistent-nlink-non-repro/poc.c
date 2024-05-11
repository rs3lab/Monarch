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
#include <time.h>

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
		while(!msg[0]) {}

        char tmpbuf[100];
        mkdir("./file0", 0x0);
        mkdir("./file0/file0", 0x2);
        symlink("./file0/file0", "./file0./file0");
        lgetxattr("./file0", "trusted.overlay.opaque", tmpbuf, 0x1e);
        int r0 = open("./file0/file0", 0x0, 0x0);
        int r1 = dup2(r0, 0xffffffffffffffff);
        fsetxattr(r1, "6f7308e30eb699899d6abe0db960bbdf77af283392a900cdb105ad34bff63805da51c89294182691f62fb844b5c3bd11d6cb7ff57cd5ff18228316c3c6a4e92ee66e605d496402feddbc7fb32786952e188fb4b38315", tmpbuf, 0x1, 0x3);

        msg[1] = 1;

		struct stat stat_buf;
		stat("./file0", &stat_buf);
		print_stat_info(&stat_buf);
	} else if (clt == 4) {

        char tmpbuf[100];
        fstat(0xffffffffffffffff, tmpbuf);
        fsync(0xffffffffffffffff);

        msg[0] = 1;
        while(!msg[1]) {}
		
        struct stat stat_buf;
        stat("./file0", &stat_buf);
		print_stat_info(&stat_buf);
	}
}
