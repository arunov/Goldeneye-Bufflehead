#!/usr/bin/python

import os
import pwd
import argparse
import getpass
import sys

FILE_ROLE_ID='/etc/gebh_role_id'
FILE_USER_ROLE='/etc/gebh_user_role'
FILE_POLICY='/etc/gebh_policy'
FILE_ACTIVE_ROLE='/etc/gebh_active_role'

def check_root():
    if (0 == os.getuid()):
        return
    print 'This operation requires admin (root) permission'
    sys.exit(0)

def add_role(rolename):
    if not rolename.isalpha():
        print ('Error: rolename should be alphabets')
        return
    if not os.path.exists(FILE_ROLE_ID):
        open(FILE_ROLE_ID, 'w').close()
    roleid_file = open(FILE_ROLE_ID, 'r+')
    lines = roleid_file.readlines()
    found = False
    largest = 0
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        if rolename == vals[0]:
            found = True
            print ('Error: '+rolename+' is already a role with id '+id_in_file)
            return
        if int(id_in_file) > largest:
            largest = int(id_in_file)
    roleid_file.write(rolename+':'+str(largest+1)+'\n')
    roleid_file.close
    print ('Successfully added '+rolename+' with id '+str(largest+1))
    return

def del_role(rolename):
    if not rolename.isalpha():
        print ('Error: rolename should be alphabets')
        return
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r+')
    lines = roleid_file.readlines()
    found = False
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        if rolename == vals[0]:
            found = True
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    role_list.pop(pos)
    remid = role_id_list.pop(pos)
    roleid = open(FILE_ROLE_ID, 'w')
    for pair in zip(role_list, role_id_list):
        roleid.write(pair[0]+':'+pair[1]+'\n')
    roleid.close
    if not os.path.exists(FILE_POLICY):
        print('Successfully removed '+rolename+' with id '+str(remid))
        return
    fd = open(FILE_POLICY, 'r')
    lines = fd.readlines()
    fd.close()
    role_list = list()
    inode_list = list()
    pos = -1
    i = 0
    for line in lines:
        vals = line.split(':', 1)
        role_in_file = vals[0]
        if not ishex(role_in_file):
            continue
        inode_in_file = vals[1][0:len(vals[1])-1]
        if not ishex(inode_in_file):
            continue
        if int(role_in_file, 16) == int(roleid):
            continue
        role_list.append(int(role_in_file, 16))
        inode_list.append(int(inode_in_file, 16))
    fd = open(FILE_POLICY, 'w')
    for pair in zip(role_list, inode_list):
        fd.write(("%x" % pair[0]).zfill(8)+':'+("%x" % pair[1]).zfill(16)+'\n')
    fd.close
    print('Successfully removed '+rolename+' with id '+str(remid))
    return

def auth_role_for_user(user, rolename):
    if not rolename.isalpha():
        print ('Error: rolename should be alphabets')
        return
    uid = pwd.getpwnam(user).pw_uid
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r')
    lines = roleid_file.readlines()
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    roleid = role_id_list[pos]
    if not os.path.exists(FILE_USER_ROLE):
        open(FILE_USER_ROLE, 'w').close()
    fd = open(FILE_USER_ROLE, 'r+')
    lines = fd.readlines()
    for line in lines:
        vals = line.split(':', 1)
        uid_in_file = vals[0]
        if not uid_in_file.isdigit():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        if int(uid_in_file) == uid and int(id_in_file) == int(roleid):
            print ('Error: User '+user+' with id '+str(uid)+' is already authorized to play role '+rolename+' with id '+roleid)
            return
    fd.write(str(uid)+':'+roleid+'\n')
    fd.close
    print ('Successfully added user '+user+' with id '+str(uid)+' to role '+rolename+' with id '+roleid)
    return

def unauth_role_for_user(user, rolename):
    if not rolename.isalpha():
        print ('Error: rolename should be alphabets')
        return
    uid = pwd.getpwnam(user).pw_uid
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r')
    lines = roleid_file.readlines()
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    roleid = role_id_list[pos]
    if not os.path.exists(FILE_USER_ROLE):
        print ('Error: '+FILE_USER_ROLE+' does not exist')
        return
    fd = open(FILE_USER_ROLE, 'r')
    lines = fd.readlines()
    user_list=list()
    auth_list=list()
    pos = -1
    i = 0
    for line in lines:
        vals = line.split(':', 1)
        uid_in_file = vals[0]
        if not uid_in_file.isdigit():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        user_list.append(uid_in_file)
        auth_list.append(id_in_file)
        if(int(uid_in_file) == uid and int(id_in_file) == int(roleid)):
            pos=i
        i = i+1
    fd.close
    if(pos == -1):
        print ('Error: User '+user+' with id '+str(uid)+' does not have authority to play role '+rolename+' with id '+roleid)
        return
    user_list.pop(pos)
    auth_list.pop(pos)
    fd = open(FILE_USER_ROLE, 'w')
    for pair in zip(user_list, auth_list):
        fd.write(pair[0]+':'+pair[1]+'\n')
    fd.close
    print ('Successfully unauthorized user '+user+' with id '+str(uid)+' from role '+rolename+' with id '+roleid)
    return

def ishex(string):
    for i in range(0, len(string)):
        c = string[i]
        if not ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')):
            return False
    return True

def add_folder_in_policy(folder, rolename):
    if not os.path.isdir(folder):
        print ('Error: Cannot find folder '+folder)
        return
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r')
    lines = roleid_file.readlines()
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    roleid = role_id_list[pos]
    inode = os.stat(folder).st_ino
    if not os.path.exists(FILE_POLICY):
        open(FILE_POLICY, 'w').close()
    fd = open(FILE_POLICY, 'r+')
    lines = fd.readlines()
    for line in lines:
        vals = line.split(':', 1)
        role_in_file = vals[0]
        if not ishex(role_in_file):
            continue
        inode_in_file = vals[1][0:len(vals[1])-1]
        if not ishex(inode_in_file):
            continue
        if int(role_in_file, 16) == int(roleid) and int(inode_in_file, 16) == inode:
            print ('Error: '+folder+' with inode '+str(inode)+' is already accessible for role '+rolename+' with id '+str(roleid))
            return
    fd.write(("%x" % int(roleid)).zfill(8)+':'+("%x" % int(inode)).zfill(16)+'\n')
    print ('Successfully added '+folder+' with inode '+str(inode)+' for role '+rolename+' with id '+str(roleid))
    return

def rm_folder_in_policy(folder, rolename):
    if not os.path.isdir(folder):
        print ('Error: Cannot find folder '+folder)
        return
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r')
    lines = roleid_file.readlines()
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    roleid = role_id_list[pos]
    inode = os.stat(folder).st_ino
    if not os.path.exists(FILE_POLICY):
        print ('Error: '+FILE_POLICY+' does not exist')
        return
    fd = open(FILE_POLICY, 'r')
    lines = fd.readlines()
    fd.close()
    role_list = list()
    inode_list = list()
    pos = -1
    i = 0
    for line in lines:
        vals = line.split(':', 1)
        role_in_file = vals[0]
        if not ishex(role_in_file):
            continue
        inode_in_file = vals[1][0:len(vals[1])-1]
        if not ishex(inode_in_file):
            continue
        if int(role_in_file, 16) == int(roleid) and int(inode_in_file, 16) == inode:
            pos = i
        i = i+1
        role_list.append(int(role_in_file, 16))
        inode_list.append(int(inode_in_file, 16))
    if pos == -1:
        print ('Error: Role '+rolename+' with id '+roleid+' does not does not have access to '+folder+' with inode '+str(inode))
        return
    role_list.pop(pos)
    inode_list.pop(pos)
    fd = open(FILE_POLICY, 'w')
    for pair in zip(role_list, inode_list):
        fd.write(("%x" % pair[0]).zfill(8)+':'+("%x" % pair[1]).zfill(16)+'\n')
    fd.close
    print ('Successfully removed '+folder+' with inode '+str(inode)+' for role '+rolename+' with id '+str(roleid))
    return

def activate_role(user, rolename):
    if not rolename.isalpha():
        print ('Error: rolename should be alphabets')
        return
    uid = pwd.getpwnam(user).pw_uid
    if not os.path.exists(FILE_ROLE_ID):
        print ('Error: '+FILE_ROLE_ID+' does not exist')
        return
    roleid_file = open(FILE_ROLE_ID, 'r')
    lines = roleid_file.readlines()
    role_list = list()
    role_id_list = list()
    for line in lines:
        vals = line.split(':', 1)
        if not vals[0].isalpha():
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not id_in_file.isdigit():
            continue
        role_list.append(vals[0])
        role_id_list.append(id_in_file)
    roleid_file.close
    if(role_list.count(rolename)!=1):
        print ('Error: '+rolename+' not found')
        return
    pos = role_list.index(rolename)
    roleid = role_id_list[pos]
    if not os.path.exists(FILE_ACTIVE_ROLE):
        open(FILE_ACTIVE_ROLE, 'w').close
        os.chmod(FILE_ACTIVE_ROLE, 0666)
    fd = open(FILE_ACTIVE_ROLE, 'r')
    lines = fd.readlines()
    user_list=list()
    role_list=list()
    pos = -1
    i = 0
    for line in lines:
        vals = line.split(':', 1)
        uid_in_file = vals[0]
        if not ishex(uid_in_file):
            continue
        id_in_file = vals[1][0:len(vals[1])-1]
        if not ishex(id_in_file):
            continue
        user_list.append(int(uid_in_file, 16))
        role_list.append(int(id_in_file,16))
        if(int(uid_in_file, 16) == uid):
            if(int(id_in_file, 16) == int(roleid)):
                print 'Error: User '+user+' with id '+str(uid)+' is already active as '+rolename+' with id '+roleid
                return
            pos=i
        i = i+1
    fd.close
    if(pos == -1):
        user_list.append(uid)
        pos = i
        role_list.append(int(roleid))
    else:
        role_list[pos] = int(roleid)
    fd = open(FILE_ACTIVE_ROLE, 'w')
    for pair in zip(user_list, role_list):
        fd.write(("%x" % pair[0]).zfill(8)+':'+("%x" % pair[1]).zfill(8)+'\n')
    fd.close
    print ('Successfully activated user '+user+' with id '+str(uid)+' to role '+rolename+' with id '+roleid)
    return

parser = argparse.ArgumentParser(description='manage goldeneye bufflehead (gebh) security policies')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--addrole', help='add a new role (admin only)', action='store_true')
group.add_argument('--auth',type=str, metavar='USER', help='authorize role for USER (admin only)')
group.add_argument('--deauth', type=str, metavar='USER', help='deauthorize role for USER (admin only)')
group.add_argument('--adddir', type=str, metavar='DIR', help='add DIR in policy (admin only)')
group.add_argument('--rmdir', type=str, metavar='DIR', help='rm DIR from policy (admin only)')
group.add_argument('-a', '--activate', action='store_true', help='activate role (admin should use with -u)')
parser.add_argument('-r', '--role', type=str, help='role name', required=True)
parser.add_argument('-u', '--user', type=str, help='user name')
args=parser.parse_args()


if args.addrole:
    check_root
    add_role(args.role)

if args.auth:
    check_root
    auth_role_for_user(args.auth, args.role)

if args.deauth:
    check_root
    deauth_role_for_user(args.deauth, args.role)

if args.adddir:
    check_root
    add_folder_in_policy(args.adddir, args.role)

if args.rmdir:
    check_root
    rm_folder_in_policy(args.rmdir, args.role)

if args.activate:
    if (0 == os.getuid()):
        if not args.user:
            print 'mention user name to activate using -u'
            sys.exit(0)
        activate_role(args.user, args.role)
    else:
        activate_role(getpass.getuser(), args.role)

