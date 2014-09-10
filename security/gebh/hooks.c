#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include "policy.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Goldeneye Bufflehead, a Role Based Access Control security\
 solution");
MODULE_AUTHOR("Arun Olappamanna Vasudevan <arunov1986@gmail.com>");

/*static void read_file(char *filename) {
  int fd;
  char buf[1];
  char x = 'x';

  mm_segment_t old_fs = get_fs();
  set_fs(KERNEL_DS);

  fd = sys_open(filename, O_RDWR, 0);

  if (fd >= 0) {
    printk(KERN_DEBUG);
    while (sys_read(fd, buf, 1) == 1)
      printk("%c", buf[0]);
    printk("\n");
    sys_lseek(fd, -1, SEEK_CUR);
    sys_write(fd, &x, 1);
    sys_close(fd);
  }
  set_fs(old_fs);
}*/

int gebh_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "%s, %lu\n", __func__, dir->i_ino);
    printk(KERN_INFO "%s, Current user id: %u\n", __func__, current_uid().val);
    if(dir->i_ino == 202738620) {
        printk(KERN_INFO "%s, permission denied\n", __func__);
        return -EACCES;
    }
    //read_file("/root/tfile");
    check_perm(current_uid().val, dir->i_ino);
    return 0;
}

int gebh_inode_unlink(struct inode *dir, struct dentry *dentry) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int gebh_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int gebh_inode_rmdir(struct inode *dir, struct dentry *dentry) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int gebh_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry) {
    return 0;
}

struct security_operations gebh_ops = {
    .name = "gebh",
    .inode_create = gebh_inode_create,
    .inode_unlink = gebh_inode_unlink,
    .inode_mkdir = gebh_inode_mkdir,
    .inode_rmdir = gebh_inode_rmdir,
    .inode_rename = gebh_inode_rename,
};

static int __init gebh_init(void) {
    printk(KERN_INFO "Initializing gebh security module\n");
    if(register_security(&gebh_ops) != 0) {
        printk(KERN_INFO "Failed to initialize gebh security module\n");
    }
    return 0;
}

static void __exit gebh_exit(void) {
    printk(KERN_INFO "Exiting gebh security module\n");
}

module_init(gebh_init);
module_exit(gebh_exit);

