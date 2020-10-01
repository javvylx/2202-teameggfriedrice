import binascii, json, ctypes, struct, os, sys, getopt

def get_mft_eh_val(file):
    #Currently only first header
    file.seek(0)
    x = file.read(1024)
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


def main(args):
    try:
        print("test")
        opts, args = getopt.getopt(args, "hf:")
        print(opts)
    except getopt.GetoptError:
        print("test")
        print("ICT2202_Tool.py -f <raw MFT filename>")
    for opt,arg in opts:
        if opt == "-h":
            print("ICT2202_Tool.py -f <raw MFT filename>")
            sys.exit(2) #exit with a syntax error
        elif opt == "-f":
            f = open(arg, "rb")
            get_mft_eh_val(f)


if __name__ == "__main__":
    main(sys.argv[1:])

