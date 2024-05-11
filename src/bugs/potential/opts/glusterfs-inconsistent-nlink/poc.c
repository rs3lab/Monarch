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

void main(int argc, char **argv){

	int clt = atoi(argv[1]);

	//loop for star
	int mfd = open("/sys/bus/pci/devices/0000:00:10.0/resource2", O_RDWR);
	if (mfd <= 0) printf("open IVSHM error\n");
	volatile char *msg = (char *)mmap(0, 1 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
	if(msg == NULL) printf("mmap failed\n");

	if (clt == 3) {
		//clt4 starts
        msg[0] = 1;
		while(!msg[1]) {}
		//create file0
        syscall(__NR_open, "./file0\x00", 0x108c0, 0ul);
        msg[2] = 1;
        while(!msg[3]) {}
		struct stat stat_buf;
		stat("./file0", &stat_buf);
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
	} else if (clt == 4) {
		while(!msg[0]) {}
        syscall(__NR_fallocate, -1, 1ul, 0x5e7ul, 0x1000ul);
        msg[1] = 1;
        while(!msg[2]) {}
		struct stat stat_buf;
        stat("./file0", &stat_buf);
        msg[3] = 1;
		printf("stat: %d, %d\n", stat_buf.st_mode, S_ISREG(stat_buf.st_mode));
	}
}
