#define FIFONAME "/root/areas"
#define FIFONAME2 "/root/areas-collect"
#define FIFONAME3 "/root/shmid-tid"
#define AREA_BYTESIZE (256 << 10)
#define AREA_SIZE     (AREA_BYTESIZE/sizeof(unsigned long))
#define SHMCNT 210

#define kMaxThreads 16
//const int kMaxThreads = 16;
