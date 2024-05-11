#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
        int fd = 0, ret = 0;
        struct stat sb;

        fd = open("../glusterfs-client/a.txt", O_RDWR, 0666);
        if (fd <= 0) {
                printf("Failed to open file with ret %d\n", fd);
                exit(1);
        }

        sleep(5);

        ret = fstat(fd, &sb);
        if (ret == -1) {
                printf("fstat failed with errno %d\n", errno);
        } else {
                printf("fstat succeeded\n");
        }

        return 0;
}
