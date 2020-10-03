import binascii
import json
import ctypes
import struct
import os
import sys

#? - MFT Overview - ?#
#? https://www.sciencedirect.com/topics/computer-science/master-file-table ?#

#? - MFT Entry Header Format - ?#
#? https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#mft-entry-header ?#

#? - MFT structure explained - ?#
#? https://flylib.com/books/en/2.48.1/basic_concepts.html ?#

#? - Struct Lib format - ?#
#? https://docs.python.org/3/library/struct.html ?#

#* Get the args
print(str(sys.argv[1]))

#*Open file
f = open("mtf.raw", "rb")

#*MFT file size
print(os.path.getsize("mtf.raw")/1024) 

#*Start reading from offset 0x00
f.seek(0) 

#*read the first 1024 bytes
#!print(f.read(1024)) 

f.seek(0)
x = f.read(1024)
print(struct.unpack("<I", x[:4])[0]) # Signature; "<": little endian, "I": unsigned int (4 bytes)
print(struct.unpack("<H", x[4:6])[0]) # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<H", x[6:8])[0]) # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<d", x[8:16])[0]) # LogFile Seq Number; "<": little endian, "d": double (8 bytes)
print(struct.unpack("<H", x[16:18])[0]) # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<H", x[18:20])[0]) # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<H", x[20:22])[0]) # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<H", x[22:24])[0]) # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<I", x[24:28])[0]) # used entry size; "<": little endian, "I": unsigned int (4 bytes)
print(struct.unpack("<I", x[28:32])[0]) # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
print(struct.unpack("<Ixx", x[32:38])[0]) # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
print(struct.unpack("<H", x[38:40])[0]) # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<H", x[40:42])[0]) # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
print(struct.unpack("<I", x[44:48])[0]) # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)


#!print("Signature: " + str(struct.unpack("<I", x[:4])[0])) # Signature; "<": little endian, "I": unsigned int (4 bytes)
#!print("Fix-up offset: " + str(struct.unpack("<H", x[4:6])[0])) # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
#!print("Fix-up values: " + str(struct.unpack("<H", x[6:8])[0])) # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
#!print("LogFile Seq Number: " + str(struct.unpack("<d", x[8:16])[0])) # LogFile Seq Number; "<": little endian, "d": double (8 bytes)
#!print("Seq Number: " + str(struct.unpack("<H", x[16:18])[0])) # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
#!print("Reference Count: " + str(struct.unpack("<H", x[18:20])[0])) # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
#!print("Attribute offset: " + str(struct.unpack("<H", x[20:22])[0])) # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
#!print("Entry Flags: " + str(struct.unpack("<H", x[22:24])[0])) # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
#!print("used entry size: " + str(struct.unpack("<I", x[24:28])[0])) # used entry size; "<": little endian, "I": unsigned int (4 bytes)
#!print("Total entry size: " + str(struct.unpack("<I", x[28:32])[0])) # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
#!print("Base record file reference: " + str(struct.unpack("<Ixx", x[32:38])[0])) # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
#!print("Base record file seq: " + str(struct.unpack("<H", x[38:40])[0])) # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
#!print("Next attribute identifier: " + str(struct.unpack("<H", x[40:42])[0])) # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
#!print("MFT Entry record number: " + str(struct.unpack("<I", x[44:48])[0])) # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)

