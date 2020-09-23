import win32api
import win32con
import win32security

# Test your file path here
FILENAME = "C:/Users/kktay/Downloads/setup-x86_64.exe"

print("I am", win32api.GetUserNameEx (win32con.NameSamCompatible))

sd = win32security.GetFileSecurity (FILENAME, win32security.OWNER_SECURITY_INFORMATION)
owner_sid = sd.GetSecurityDescriptorOwner ()
name, domain, type = win32security.LookupAccountSid (None, owner_sid)

print("File owned by %s\\%s" % (domain, name))


import os

print(os.stat(FILENAME))
# - st_mode - protection bits,
# - st_ino - inode number,
# - st_dev - device,
# - st_nlink - number of hard links,
# - st_uid - user id of owner,
# - st_gid - group id of owner,
# - st_size - size of file, in bytes,
# - st_atime - time of most recent access,
# - st_mtime - time of most recent content modification,
# - st_ctime - platform dependent; time of most recent metadata change on Unix, or the time of creation on Windows)