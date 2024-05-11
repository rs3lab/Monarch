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
		while(!msg[1]) {}
        syscall(__NR_mkdir, "./file0", 0x88);
        syscall(__NR_mkdir, "./file1", 0x80);
        syscall(__NR_lsetxattr, "trusted.overlay.opaque", ".");

        msg[0] = 1;
		while(!msg[2]) {}

        syscall(__NR_rename, "file1", "file2");
        syscall(__NR_lsetxattr, "user.incfs.id", "\x00", 0x1, 0x1);
        syscall(__NR_lsetxattr, "security.user.syz", "system.advise", 0xe, 0x1);
        syscall(__NR_open, "file0", 0x10000, 0x100);

        msg[3] = 1;

        char xattr1[100];
        syscall(__NR_getxattr, "trusted.overlay.opaque", xattr1, 100);
        printf("trusted.overlay.opaque:%s\n", xattr1);
		struct stat stat_buf;
		stat("./file0", &stat_buf);
		print_stat_info(&stat_buf);
	} else if (clt == 4) {
		msg[1] = 1;
		while(!msg[0]) {}

        char buf[100];
        syscall(__NR_llistxattr, "./file0", &buf, 0x53);
        syscall(__NR_chmod, "./file0", 0x2);

		msg[2] = 1;

        while(!msg[3]) {}

        char xattr2[100];
        syscall(__NR_getxattr, "trusted.overlay.opaque", xattr2, 100);
		struct stat stat_buf;
        stat("./file0", &stat_buf);
        printf("trusted.overlay.opaque:%s\n", xattr2);
		print_stat_info(&stat_buf);
	}
}
