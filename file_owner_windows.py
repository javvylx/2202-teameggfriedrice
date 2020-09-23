# Using window API to get file owner and domain in text
# pwd is a unix/linux module which can produce a better result, however windows don't have
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

############################################################################################################################################

# Attempt on finding file's permission
import os
import stat

print(os.lstat(FILENAME))
print("Permisssion in Unix: {}".format(oct(stat.S_IMODE(os.lstat(FILENAME).st_mode))[2:]))
# print it in rwx form
# print("Permisssion in Unix: {}".format(stat.filemode(os.lstat(FILENAME).st_mode)))
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

############################################################################################################################################

# Using this method is faster than using subprocess 
# https://stackoverflow.com/questions/40367961/how-to-read-or-write-the-a-s-h-r-i-file-attributes-on-windows-using-python-and-c
from ctypes import WinDLL, WinError, get_last_error
from stat import \
    FILE_ATTRIBUTE_ARCHIVE as A, FILE_ATTRIBUTE_SYSTEM as S, \
    FILE_ATTRIBUTE_HIDDEN as H, FILE_ATTRIBUTE_READONLY as R, \
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED as I
from os import scandir, stat
    
def myattrib(kernel32, entry, update=False, a=None, s=None, h=None, r=None, i=None):

    # get the file attributes as an integer.
    if not update: # faster
        attrs = entry.stat(follow_symlinks=False).st_file_attributes
    else: # slower but reflects changes
        # notice that this will raise a WinError Access denied on some entries,
        # for example C:\System Volume Information\
        attrs = stat(entry.path, follow_symlinks=False).st_file_attributes

    # construct the new attributes
    newattrs = attrs
    def set(attr, value):
        nonlocal newattrs
        # use '{0:032b}'.format(number) to understand what this does.
        if value is True: newattrs = newattrs | attr
        elif value is False: newattrs = newattrs & ~attr
    set(A, a)
    set(S, s)
    set(H, h)
    set(R, r)
    set(I, i if i is None else not i)
    # optional add more attributes here, see
    # https://docs.python.org/3/library/stat.html#stat.FILE_ATTRIBUTE_ARCHIVE

    # write the new attributes if they changed
    if newattrs != attrs:
        if not kernel32.SetFileAttributesW(entry.path, newattrs):
            raise WinError(get_last_error())

    # return an info tuple
    return (
        bool(newattrs & A),
        bool(newattrs & S),
        bool(newattrs & H),
        bool(newattrs & R),
        not bool(newattrs & I)
    )

path = 'C:/Users/kktay/Downloads/'
# https://docs.python.org/3/library/ctypes.html#ctypes.WinDLL
kernel32 = WinDLL('kernel32', use_last_error=True)

print('\nReading the ashri attributes:')
# https://docs.python.org/3/library/os.html#os.DirEntry
for entry in scandir(path):
    a,s,h,r,i = myattrib(kernel32, entry)
    print(entry.path, "| Archive: {}, System: {}, Hidden: {}, ReadOnly: {}, Content Not Indexed: {}".format(a, s, h, r, i))