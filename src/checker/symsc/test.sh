python2.7 ./monarch-emul.py -v -p 'v0[] = "./file0";
v1[] = "./file0";
v2[100];
v3[100];
v4[] = "./file0";
v5[100];
syscall(SYS_open, v0, 66, 0777);
syscall(SYS_setxattr, v1, v2, v3, 0, 0);
syscall(SYS_sync);
syscall(SYS_removexattr, v4, v5);' -c './file0	2	10730540012440475651	2	4096	131072	8	755	0		'
