#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Goldeneye Bufflehead, a Role Based Access Control security\
 solution");
MODULE_AUTHOR("Arun Olappamanna Vasudevan <arunov1986@gmail.com>");

int gebh_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
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

