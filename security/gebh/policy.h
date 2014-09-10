#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
//#include <linux/fs.h>

int check_perm(unsigned int uid, unsigned long inode);

