import binascii, json, ctypes, struct, os, sys, getopt

def body_extraction(dec):
    switcher = {
        16: "$STANDARD_INFORMATION",
        32: "$ATTRIBUTE_LIST",
        48: "$FILE_NAME",
        64: "$VOLUME_VERSISON",
        80: "$OBJECT_ID",
        96: "$VOLUME_NAME",
        112: "$VOLUME_INFORMATION",
        128: "$DATA",
        144: "$INDEX_ROOT",
        160: "$INDEX_ALLOCATION",
        176: "$BITMAP",
        192: "$SYMBOLIC_LINK",
        208: "$EA_INFORMATION",
        224: "$EA",
        240: "$PROPERTY_SET",
        256: "$LOGGED_UTILITY_STREAM"
    }
    return (switcher.get(dec))


def is_AttributeIdentifier(dec):
    Sample = (16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256)
    if dec in Sample:
        return True
    else:
        return False

def get_mft_eh_val(file):
    #Currently only first header
    result = open("r.txt", "w")
    count = 0
    file.seek(0) #Start from 0
    while(True):
        count+=1
        header = file.read(1024)
        if(header[:4] == b'\x00\x00\x00\x00'):
            #file.read(1024-48)
            continue
        if header!="":
            result.write("Signature: " + str(struct.unpack("<I", header[:4])[0])) # Signature; "<": little endian, "I": unsigned int (4 bytes)\
            result.write("\r\n")
            result.write("Fix-up offset: " + str(struct.unpack("<H", header[4:6])[0])) # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("Fix-up values: " + str(struct.unpack("<H", header[6:8])[0])) # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("LogFile Seq Number: " + str(struct.unpack("<d", header[8:16])[0])) # LogFile Seq Number; "<": little endian, "d": double (8 bytes)
            result.write("\r\n")
            result.write("Seq Number: " + str(struct.unpack("<H", header[16:18])[0])) # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("Reference Count: " + str(struct.unpack("<H", header[18:20])[0])) # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("Attribute offset: " + str(struct.unpack("<H", header[20:22])[0])) # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("Entry Flags: " + str(struct.unpack("<H", header[22:24])[0])) # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("used entry size: " + str(struct.unpack("<I", header[24:28])[0])) # used entry size; "<": little endian, "I": unsigned int (4 bytes)
            result.write("\r\n")
            result.write("Total entry size: " + str(struct.unpack("<I", header[28:32])[0])) # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
            result.write("\r\n")
            result.write("Base record file reference: " + str(struct.unpack("<Ixx", header[32:38])[0])) # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
            result.write("\r\n")
            result.write("Base record file seq: " + str(struct.unpack("<H", header[38:40])[0])) # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("Next attribute identifier: " + str(struct.unpack("<H", header[40:42])[0])) # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
            result.write("\r\n")
            result.write("MFT Entry record number: " + str(struct.unpack("<I", header[44:48])[0])) # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)
            result.write("\r\n")




            #TO DETERMINE ATTRIBUTE OFFSET
            AOList = []
            AIList = []

            AO = struct.unpack("<H", header[20:22])#Attribute offset
            AOList.append(AO[0])
            a = 0
            for i in AOList:
            #Determine the attribute header
                AI = (struct.unpack("<I", header[i:i + 4])[0])
                AIList.append(AI)
                print ("AI", AI)
                result.write("-" * 300 + "\r\n")
                result.write("ATTR HEADER" + "\r\n")
                result.write("-" * 300 + "\r\n")
                result.write("Attribute Type: " + str(struct.unpack("<I", header[i:i+4])[0]))  # Attribute Type 4Bytes
                result.write("\r\n")
                result.write("Attribute Length (including header): " + str(struct.unpack("<I", header[i+4:i+8])[0]))  # Attribute Length (include header) 4Bytes
                result.write("\r\n")
                result.write("Non-Resident Flag: " + str(struct.unpack("<B", header[i+8:i+9])[0]))  # Non-resident Flag 1Byte
                result.write("\r\n")
                result.write("Name Length: " + str(struct.unpack("<B", header[i+9:i+10])[0]))  # Name Length 1Byte
                result.write("\r\n")
                result.write("Offset to the name: " + str(struct.unpack("<H", header[i+10:i+12])[0]))  # Offset to the Name 2Bytes
                result.write("\r\n")
                result.write("Flags: " + str(struct.unpack("<H", header[i+12:i+14])[0]))  # Flags 2Bytes
                result.write("\r\n")
                result.write("Attribute ID: " + str(struct.unpack("<H", header[i+14:i+16])[0]))  # Attribute ID 2Bytes
                result.write("\r\n")
                result.write("Length of the attribute: " + str(struct.unpack("<I", header[i+16:i+20])[0]))  # Length of the attribute 4Bytes
                result.write("\r\n")
                result.write("Offset to the attribute: " + str(struct.unpack("<H", header[i+20:i+22])[0]))  # Offset to the attribute 2Bytes
                result.write("\r\n")
                result.write("Indexed flag: " + str(struct.unpack("<B", header[i+22:i+23])[0]))  # Indexed Flag 1Byte
                result.write("\r\n")
                result.write("Padding: " + str(struct.unpack("<B", header[i+23:i+24])[0]))  # Padding 1Byte
                result.write("\r\n")
                result.write("-" * 300 + "\r\n")
                NextAI = struct.unpack("<I", header[i + 4:i + 8])[0] + i
                print("NAI: ", NextAI)
                if NextAI < 1024:
                    is_AI = is_AttributeIdentifier(struct.unpack("<I", header[NextAI:NextAI+4])[0])

                    if is_AI == True:
                        AOList.append(NextAI)
                print ("I", i)
                if (AI == 16):  # 16 is decimal for 0x10, $STAND_INFO
                    result.write("STAND INFO" + "\r\n")
                    result.write("-" * 300 + "\r\n")
                    result.write("\r\n")
                    SI = i+24
                    result.write("File Creation Time: " + str(struct.unpack(">Q", header[SI:SI+8])[0]))  # Creation Time 8Bytes
                    result.write("\r\n")
                    result.write("File Altered Time: " + str(struct.unpack("<Q", header[SI+8:SI+16])[0]))  # Altered Time 8Bytes
                    result.write("\r\n")
                    result.write("File MFT Time: " + str(struct.unpack("<Q", header[SI+16:SI+24])[0]))  # MFT Time 8Bytes
                    result.write("\r\n")
                    result.write("File Read Time: " + str(struct.unpack("<Q", header[SI+24:SI+32])[0]))  # Read Time 8Bytes
                    result.write("\r\n")
                    result.write("File Altered Time: " + str(struct.unpack("<I", header[SI+32:SI+36])[0]))  # Dos File Permission 4Bytes
                    result.write("\r\n")
                    result.write("-" * 300 + "\r\n")


            result.write("AI LIST: ")
            for x in AIList:
                result.write(body_extraction(x) + " ")
            result.write("\r\n")
            result.write("-" * 300 + "\r\n")
            print(count)
            try:
                print("number:")
                print(struct.unpack("<I", header[28:32])[0])
                print("--------")
                # file.read(struct.unpack("<I", header[28:32])[0]-48)
            except:
                print("test")
                break
        else:
            result.close()
            break




    # x = file.read(48)
    # print("Signature: " + str(struct.unpack("<I", x[:4])[0])) # Signature; "<": little endian, "I": unsigned int (4 bytes)
    # print("Fix-up offset: " + str(struct.unpack("<H", x[4:6])[0])) # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
    # print("Fix-up values: " + str(struct.unpack("<H", x[6:8])[0])) # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
    # print("LogFile Seq Number: " + str(struct.unpack("<d", x[8:16])[0])) # LogFile Seq Number; "<": little endian, "d": double (8 bytes)
    # print("Seq Number: " + str(struct.unpack("<H", x[16:18])[0])) # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
    # print("Reference Count: " + str(struct.unpack("<H", x[18:20])[0])) # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
    # print("Attribute offset: " + str(struct.unpack("<H", x[20:22])[0])) # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
    # print("Entry Flags: " + str(struct.unpack("<H", x[22:24])[0])) # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
    # print("used entry size: " + str(struct.unpack("<I", x[24:28])[0])) # used entry size; "<": little endian, "I": unsigned int (4 bytes)
    # print("Total entry size: " + str(struct.unpack("<I", x[28:32])[0])) # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
    # print("Base record file reference: " + str(struct.unpack("<Ixx", x[32:38])[0])) # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
    # print("Base record file seq: " + str(struct.unpack("<H", x[38:40])[0])) # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
    # print("Next attribute identifier: " + str(struct.unpack("<H", x[40:42])[0])) # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
    # print("MFT Entry record number: " + str(struct.unpack("<I", x[44:48])[0])) # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)
    # x = file.read(struct.unpack("<I", x[28:32])[0]-48)


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

