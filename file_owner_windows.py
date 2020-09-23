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