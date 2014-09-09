#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RBAC security");
MODULE_AUTHOR("Arun Olappamanna Vasudevan");

int rbac_inode_link(struct dentry *old_dentry, struct inode *dir,
                                                    struct dentry *new_dentry) {
    printk(KERN_INFO "%s, %lu\n", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_unlink(struct inode *dir, struct dentry *dentry) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_symlink(struct inode *dir, struct dentry *dentry,
                                                        const char *old_name) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_rmdir(struct inode *dir, struct dentry *dentry) {
    printk(KERN_INFO "%s, %lu", __func__, dir->i_ino);
    return 0;
}

int rbac_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry) {
    return 0;
}

struct security_operations rbac_ops = {
    .name = "rbac",
    .inode_link = rbac_inode_link,
    .inode_create = rbac_inode_create,
    .inode_unlink = rbac_inode_unlink,
    .inode_symlink = rbac_inode_symlink,
    .inode_mkdir = rbac_inode_mkdir,
    .inode_rmdir = rbac_inode_rmdir,
    .inode_rename = rbac_inode_rename,
};

static int __init rbac_init(void) {
    printk(KERN_INFO "Initializing rbac security module\n");
    if(register_security(&rbac_ops) != 0) {
        printk(KERN_INFO "Failed to initialize rbac security module\n");
    }
    return 0;
}

static void __exit rbac_exit(void) {
    printk(KERN_INFO "Exiting rbac security module\n");
}

module_init(rbac_init);
module_exit(rbac_exit);

