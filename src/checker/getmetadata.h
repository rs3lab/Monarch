#include "../executor/debug.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <zlib.h>

extern uint64 is_dfs_client, executor_index;

int file_stat(int file_type, char *fn, struct stat *stat_buf) {
  int ret;
  errno = 0;
  if (file_type == DT_LNK) {
    ret = lstat(fn, stat_buf);
  } else {
    ret = stat(fn, stat_buf);
  }
  fprintf(stderr, "executor %lld file_stat %s, %s\n", executor_index, fn,
          strerror(errno));
  if (ret < 0) {
    if (access(fn, F_OK) == 0) {
      fprintf(stderr, "executor %lld access %s exists\n", executor_index, fn);
    } else {
      fprintf(stderr, "executor %lld access %s doesn't exist\n", executor_index,
              fn);
    }
    int tmpret;
    struct stat tmp_buf;
    errno = 0;
    if (file_type == DT_LNK) {
      tmpret = lstat(fn, &tmp_buf);
    } else {
      tmpret = stat(fn, &tmp_buf);
    }
    fprintf(stderr, "stat again: %s, %s, %d\n", fn, strerror(errno), tmpret);
  }
  return ret;
}

// grep -rn "\#define .* \".*\..*\""|grep "_XATTR_"|awk '{print $3}'
char glusterfs_xattrs[17][40] = {
    "trusted.gfid",
    "trusted.glusterfs",
    "trusted.cloudsync.",
    "trusted.ec.",
    "distribute.fix.layout",
    "trusted.distribute.migrate-data",
    "user.ftest",
    ".glusterfs_xattr_inode",
    "glusterfs.",
    "trusted.io-stats-dump",
    "user.glusterfs",
    "trusted.distribute.linkinfo",
    "trusted.gfid",
    "trusted.pgfid.",
    "trusted.gfid2path.",
    "trusted.afr",
    "trusted.cloudsync.uuid",
};

bool should_filter(char *name) {
  for (int i = 0; i < 17; i++) {
    if (strstr(name, glusterfs_xattrs[i]))
      return true;
  }
  return false;
}

#define BUF_LEN 500 // Remember to modify XATTR_BUF_LEN at parseConsistencySan()
#define XATTR_BUF_LEN 1000
char name_buf[BUF_LEN];
char value_buf[BUF_LEN];
char xattr_buf[XATTR_BUF_LEN];

int next_name(char *name, int cur_idx) {
  while (name[cur_idx] != 0) {
    cur_idx++;
  }
  cur_idx++;
  return cur_idx;
}

int file_xattr(int file_type, char *fn) {
  xattr_buf[0] = 0;

  int size = listxattr(fn, 0, 0);
  fprintf(stderr, "executor %lld %s llistxattr returns size %d\n", executor_index, fn,
          size);
  if (size == -1) {
    struct stat stat_tmp;
    fprintf(stderr, "executor %lld %s lstat ret %d listxattr ret %ld\n",
            executor_index, fn, lstat(fn, &stat_tmp), listxattr(fn, 0, 0));
    // fail("llistxattr size is -1\n");
    return 0;
  } else if (size == 0) {
    return 0;
  }
  size = llistxattr(fn, name_buf, size > (BUF_LEN - 1) ? BUF_LEN : size);
  int cur_len = 0;
  for (int i = 0; i < size;) {
    char *name = name_buf + i;
    if (should_filter(name)) {
      fprintf(stderr, "filterd %s", name);
      i = next_name(name_buf, i);
      continue;
    }
    int value_size = lgetxattr(fn, name, 0, 0);
    lgetxattr(fn, name, value_buf,
              value_size > (BUF_LEN - 1) ? BUF_LEN : value_size);
    cur_len +=
        snprintf(xattr_buf + cur_len, XATTR_BUF_LEN - cur_len, "%s:", name);
    fprintf(stderr, "executor %lld: %s: %d\n", executor_index, name,
            value_size);
    memcpy(xattr_buf + cur_len, value_buf, value_size);
    cur_len += value_size;
    i = next_name(name_buf, i);
    cur_len += snprintf(xattr_buf + cur_len, XATTR_BUF_LEN - cur_len, ";");
  }
  if (xattr_buf[cur_len - 1] == ';')
    xattr_buf[cur_len - 1] = '\0';
  return cur_len; // strlen(xattr_buf)+1;
}

char errmsg[600];
void write_dir_info(char *dn, struct dirent *dent) {

  struct dirent *sub_ent = NULL;
  struct stat stat_buf;
  char sub_fn[510];
  int xattr_len = 0;

  fprintf(stderr, "----- executor %lld write_dir_info %s\n", executor_index,
          dn);

  errno = 0;
  if (dent) {
    if (file_stat(DT_DIR, dn, &stat_buf) == 0 &&
        (xattr_len = file_xattr(DT_DIR, dn)) >= 0) {
      write_stat(&stat_buf, dn, xattr_len, dent,
                 true); // dent will be ignored in write_stat()
    } else {
      snprintf(errmsg, 599, "file_stat %s failed %s\n", dn, strerror(errno));
      fail(errmsg);
    }
  }

  extern int errno;
  errno = 0;
  DIR *dir = opendir(dn);

  //
  char cwdbuf[200];
  getcwd(cwdbuf, 199);
  //
  snprintf(errmsg, 499, "opendir %s(%s) failed %s\n", dn, cwdbuf,
           strerror(errno));
  // servers might doesn't contain some directories, e.g., some mode of
  // glusterfs. Thus, we have skip them.
  if (dir == NULL) {
    if (is_dfs_client) {
      // debug_cmd("df; ls /root/glusterfs-client");
      fail(errmsg);
    } else
      return;
  }

  // TODO: multiple-thread
  errno = 0;
  while ((sub_ent = readdir(dir)) != NULL) {

    if (!strcmp(sub_ent->d_name, ".") || !strcmp(sub_ent->d_name, "..") ||
        !strcmp(sub_ent->d_name, "cgroup") ||
        !strcmp(sub_ent->d_name, "cgroup.cpu") ||
        !strcmp(sub_ent->d_name, "cgroup.net") ||
        !strcmp(sub_ent->d_name, "binderfs"))
      continue;

    fprintf(stderr, "subfile: %s\n", sub_ent->d_name);
    snprintf(sub_fn, 510, "%s/%s", dn, sub_ent->d_name);
    if (sub_ent->d_type == DT_DIR) {
      write_dir_info(sub_fn, sub_ent);
    } else {
      errno = 0;
      if (file_stat(sub_ent->d_type, sub_fn, &stat_buf) == 0 &&
          (xattr_len = file_xattr(sub_ent->d_type, sub_fn)) >= 0) {
        write_stat(&stat_buf, sub_fn, xattr_len, sub_ent,
                   false); // dent will be ignored in write_stat()
      } else {
        snprintf(errmsg, 599, "file_stat %s failed %s\n", sub_fn,
                 strerror(errno));
        fail(errmsg);
      }
    }
  }
  fprintf(stderr, "executor %lld readdir finishes: %s\n", executor_index,
          strerror(errno));
  closedir(dir);
}

static uint32_t get_file_chksum(const char *file_path) {
  long fd;
  char buf[4096];
  char errmsg[600];
  int len;

  errno = 0;
  fd = open(file_path, O_RDONLY, 0);
  if (fd < 0) {
    snprintf(errmsg, 599, "get_file_checksum open failed %s : %s\n", file_path,
             strerror(errno));
    fail(errmsg);
    return 0;
  }

  uint32_t crc = crc32(0L, Z_NULL, 0);

  do {
    len = read(fd, buf, sizeof(buf));
    if (len > 0) {
      crc = crc32(crc, (unsigned char *)buf, len);
    }
    if (len < 0) {
      snprintf(errmsg, 599, "get_file_checksum error reading file %s : %s\n",
               file_path, strerror(errno));
      fail(errmsg);
      return 0;
    }
  } while (len > 0);

  close(fd);
  return crc;
}

uint32 mnt_path_len = 0;
char *relative_path(char *complete_path) {
  return complete_path + mnt_path_len;
}
