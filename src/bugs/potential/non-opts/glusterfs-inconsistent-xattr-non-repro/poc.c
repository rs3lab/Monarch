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

    if (clt == 0) {

        while(!msg[0]) {}
        
        system("/root/glusterfs-node-down.sh");

        msg[1] = 1;
        while(!msg[2]) {}

        system("./glusterfs-node-up.sh 192.168.0.10 3 2 'replica 3' 0");
        msg[3] = 1;

    } else if (clt == 3) {
		//clt4 starts
		while(!msg[4]) {}

        int r0 = syscall(__NR_open, "./file0", 0x103042, 0x110);
        syscall(__NR_close, r0);
        int r1 = syscall(__NR_open, "./file0", 0x8001, 0x11);
        syscall(__NR_fallocate, r1, 0x8, 0x3, 0x7);
        int r2 = syscall(__NR_dup, r1);
        syscall(__NR_dup2, r2, r1);
        syscall(__NR_pwrite64, r0, "\xfc\x52\x3b\x00", 0x3, 0x6c611564);
        syscall(__NR_fallocate, r2, 0x52, 0x2, 0x8001);
        syscall(__NR_lsetxattr, "./file0", "user..\x00", ",#\x16\x00", 0x4, 0x0);
        syscall(__NR_fremovexattr, r2, "os2..\x00");
        int r3 = syscall(__NR_dup, r2);
        char tmpbuf[500];
        syscall(__NR_lgetxattr, "./file0", "73797b2fc574fa7900424580641873687374656d2e2a5cf2213a262d00\x00", tmpbuf, 0x30);
        syscall(__NR_lremovexattr, "./file0", "system.]},\'-\\x00");
        int r4 = syscall(__NR_open, "./file0", 0x12b300, 0x95d98458658b2404);
        syscall(__NR_pread64, 0xffffffffffffffff, tmpbuf, 0xa0, 0x0);
        int r5 = syscall(__NR_dup2, r4, r4);
        syscall(__NR_fallocate, r5, 0x0, 0x2, 0x9);
        syscall(__NR_pread64, r2, tmpbuf, 0xae, 0x6);
        int r6 = syscall(__NR_dup, r3);
        syscall(__NR_ftruncate, r6, 0x8);

        msg[5] = 1;

        char xattr1[100]={'\x00'};
        int ret = syscall(__NR_listxattr, "./file0", xattr1, 100);
        printf("user..:%s\nret %d\n", xattr1, ret);
		// struct stat stat_buf;
		// stat("./file0", &stat_buf);
		// print_stat_info(&stat_buf);
	} else if (clt == 4) {

        msg[0] = 1;
        while(!msg[1]) {}

        syscall(__NR_syncfs, 0xffffffffffffffff);
        int r0 = syscall(__NR_dup2, 0xffffffffffffffff, 0xffffffffffffffff);
        syscall(__NR_fremovexattr, r0, "6f73782e747275737465642e6f7665726c61792e696d4443c8ec0238fe7075726500950067f3d002b6f0e4a3393c89cf455f63fd90d85287a998fc571c9f5d1f89ee76a7f63e39e6cca1e8a83e7102c3a38f0cfa8ff1312dfd8a409f0a39ff259a16bf513cb0128a08929d119b32cc47b22c01b9de0c99831b37e31da812d469f9a4e3a53bfe942f1781822f8df17a1ef9dcd6237ed1707c407b1cb14fcb");
        syscall(__NR_ftruncate, r0, 0x10001);
        int r1 = syscall(__NR_dup2, r0, 0xffffffffffffffff);
        int r2 = syscall(__NR_dup2, r0, r1);
        int r3 = syscall(__NR_dup2, r2, r1);
        int r4 = syscall(__NR_open, "./file0", 0x800, 0x5a);
        syscall(__NR_fchmod, r4, 0x5);
        int r5 = syscall(__NR_dup, r0);
        syscall(__NR_dup, r5);

        msg[2] = 1;
        while(!msg[3]) {}

        syscall(__NR_lseek, r0, 0xf, 0x1);
        syscall(__NR_dup, r3);
        char tmpbuf[500];
        syscall(__NR_flistxattr, r2, tmpbuf, 0xfc);
        int r6 = syscall(__NR_dup, r1);
        syscall(__NR_read, r6, tmpbuf, 0x61);
        syscall(__NR_read, r0, tmpbuf, 0x28);
        syscall(__NR_fstat, r2, tmpbuf);
        syscall(__NR_readlink, "./file0", tmpbuf, 0xe);
        syscall(__NR_close, r1);

        msg[4] = 1;
        while(!msg[5]) {}

        char xattr2[100]={'\x00'};
        int ret = syscall(__NR_listxattr, "./file0", xattr2, 100);
		// struct stat stat_buf;
        // stat("./file0", &stat_buf);
        printf("user..:%s\nreturn %d\n", xattr2, ret);
		// print_stat_info(&stat_buf);
	}
}
