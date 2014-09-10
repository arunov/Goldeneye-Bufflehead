#include "policy.h"

#define UID_BUF_LEN (sizeof(unsigned int) * 2)
#define INODE_BUF_LEN (sizeof(unsigned long) *2)
#define POLICY_FILE "/etc/gebh_policy"
#define IS_HEX(x) ((x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F'))

static inline int read_hex(int fd, char *buf, int len, char *x, int *out_len) {
    char c = *x;
    int i;
    if(out_len) *out_len = 0;
    for(i = 0; i < len; i ++) {
        if(!IS_HEX(c)) {
            *x = c;
            if(out_len) *out_len = i;
            return -1;
        }
        *(buf + i) = c;
        if(sys_read(fd, &c, 1) == 0) {
            *x = '\0';
            if(out_len) *out_len = i;
            return -2;
        }
    }
    if(out_len) *out_len = i;
    *x = c;
    return 0;
}

static inline int read_line(int fd, char *uid_buf, char *inode_buf, int *eof) {
    char c;
    int len;
    int ret;
    if(eof) *eof = 0;
    while(1) {
        // check end of file
        if(sys_read(fd, &c, 1) == 0) {
            if(eof) *eof = 1;
            return -1;
        }
        // check empty line
        if(c == ' ' || c == '\t' || c == '\n')
            continue;
        // check comment
        if(c == '#') {
            goto ignore_line;
        }
        // read uid
        ret = read_hex(fd, uid_buf, UID_BUF_LEN, &c, &len);
        printk(KERN_INFO "gebh: uid read_hex returned %d, len %d", ret, len);
        if(ret == -1) goto ignore_line;
        if(ret == -2) {
            if(eof) *eof == 1;
            return -1;
        }
        if(c != ':') goto ignore_line;
        if(sys_read(fd, &c, 1) == 0) {
            if(eof) *eof = 1;
            return -1;
        }
        // read inode
        ret = read_hex(fd, inode_buf, INODE_BUF_LEN, &c, &len);
        printk(KERN_INFO "gebh: inode read_hex returned %d, len %d", ret, len);
        if(ret == -1) goto ignore_line;
        if(ret == -2) {
            if(eof) *eof = 1;
            if(len >= INODE_BUF_LEN)
                return 0;
            else
                return -1;
        }
        return 0;
    ignore_line:
        while(c != '\n') {
            if(sys_read(fd, &c, 1) == 0) {
                if(eof) *eof = 1;
                return -1;
            }
        }
    }
}

static inline unsigned long charhex2num(char c) {
    if(c >= '0' && c <= '9')
        return (unsigned long)(c - '0');
    if(c >= 'a' && c <= 'f')
        return (unsigned long)(c - 'a' + 10);
    if(c >= 'A' && c <= 'F')
        return (unsigned long)(c - 'A' + 10);
    return 0;
}

static inline unsigned long strhex2num(char *buf, int len) {
    int i;
    unsigned long place = 1;
    unsigned long value = 0;
    for(i = len-1; i >= 0; i --) {
        if(!IS_HEX(*(buf+i))) return 0;
        value += place * charhex2num(*(buf+i));
        place *= 16;
    }
    return value;
}

int check_perm(unsigned int uid, unsigned long inode) {
    char uid_buf[UID_BUF_LEN + 1];
    char inode_buf[INODE_BUF_LEN + 1];
    int fd;
    int eof;
    int ret;
    unsigned int uid_in_policy;
    unsigned long inode_in_policy;
    mm_segment_t old_fs;
    uid_buf[UID_BUF_LEN] = '\0';
    inode_buf[INODE_BUF_LEN] = '\0';
    // if root, allow
    if(uid == 0) return 0;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    // open policy file
    fd = sys_open(POLICY_FILE, O_RDONLY, 0);
    if(fd < 0) {
        printk(KERN_INFO "gebh: unable to open policy file");
        set_fs(old_fs);
        return -EACCES;
    }
    ret = -EACCES;
    while(1) {
        // read line
        if(read_line(fd, uid_buf, inode_buf, &eof) == -1) {
            printk(KERN_INFO "gebh: read_line returned -1");
            break;
        }
        // convert to hex
        uid_in_policy = (unsigned int)strhex2num(uid_buf, UID_BUF_LEN);
        inode_in_policy = strhex2num(inode_buf, INODE_BUF_LEN);
        printk(KERN_INFO "%u:%lu\n", uid_in_policy, inode_in_policy);
        // match
        if(uid_in_policy == uid) {
            if(inode_in_policy == inode) {
                ret = 0;
                break;
            }
        }
        if(eof) break;
    }
    sys_close(fd);
    set_fs(old_fs);
    return ret;
}

