#include "policy.h"

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

static inline int read_line(int fd, char *buf1, int len1, char *buf2, int len2, int *eof) {
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
        ret = read_hex(fd, buf1, len1, &c, &len);
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
        ret = read_hex(fd, buf2, len2, &c, &len);
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

static inline int search_line(const char *filename, unsigned long val1, int len1, unsigned long *val2, int len2, int match) {
    char buf1[len1 + 1];
    char buf2[len2 + 1];
    int fd;
    int eof;
    int ret;
    unsigned long fval1;
    unsigned long fval2;
    mm_segment_t old_fs;
    buf1[len1] = '\0';
    buf2[len2] = '\0';
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    // open file
    fd = sys_open(filename, O_RDONLY, 0);
    if(fd < 0) {
        printk(KERN_INFO "gebh: unable to open file %s\n", filename);
        set_fs(old_fs);
        return -1;
    }
    ret = -1;
    while(1) {
        // read line
        if(read_line(fd, buf1, len1, buf2, len2, &eof) == -1) {
            printk(KERN_INFO "gebh: read_line returned -1");
            break;
        }
        // convert to hex
        fval1 = strhex2num(buf1, len1);
        fval2 = strhex2num(buf2, len2);
        if(val1 == fval1) {
            // match
            if(match && *val2 == fval2) {
                ret = 0;
                break;
            } else if (!match) {
                // get val2
                *val2 = fval2;
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

int check_perm(unsigned int uid, unsigned long inode) {
    unsigned long active_role = 0;
    // if root, allow
    if(uid == 0) return 0;
    // get active role
    if(0 != search_line(ACTIVE_ROLE_FILE, (unsigned long)uid, UID_BUF_LEN, &active_role, ROLE_BUF_LEN, 0)) {
        return -EACCES;
    }
    // check permission
    if(0 == search_line(POLICY_FILE, active_role, ROLE_BUF_LEN, &inode, INODE_BUF_LEN, 1)) {
        return 0;
    } else {
        return -EACCES;
    }
}

