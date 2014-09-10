#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>

#define POLICY_FILE "/etc/gebh_policy"
#define ACTIVE_ROLE_FILE "/etc/gebh_active_role"

#define UID_BUF_LEN (sizeof(unsigned int) * 2)
#define INODE_BUF_LEN (sizeof(unsigned long) * 2)
#define ROLE_BUF_LEN (sizeof(unsigned int) * 2)

int check_perm(unsigned int uid, unsigned long inode);

