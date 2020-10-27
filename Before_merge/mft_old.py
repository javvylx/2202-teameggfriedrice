#!/usr/bin/env python

import binascii, json, ctypes, struct, os, sys, getopt, datetime

# TEMPORARILY HERE CAUSE IDK HOW WANT READ FRM TXT OR WHAT HALP
record = {}
TIMEZONE = datetime.datetime.now().astimezone().tzinfo


def get_mft_data(raw_file):
    read_ptr = record['attr_offset']
    print(read_ptr)
    while read_ptr < 1024:
        attr_record = get_attr_header(raw_file[read_ptr:])
        if attr_record['type'] == 0xffffffff:  # End of attributes
            print("End of attributes")

        if attr_record['name_len'] > 0:
            file_bytes = raw_file[
                           read_ptr + attr_record['name_off']: read_ptr + attr_record['name_off'] + attr_record[
                               'name_len'] * 2]
            attr_record['name'] = file_bytes.decode('utf-16').encode('utf-8')
        else:
            attr_record['name'] = ''
        if attr_record['type'] == 0x10:  # Standard Information
            si_record = get_si_attribute(raw_file[read_ptr + attr_record['soff']:], TIMEZONE)
            record['si'] = si_record
            print(si_record)
        if attr_record['len'] > 0:
            read_ptr = read_ptr + attr_record['len']
        else:
            break

    return record


# GET STANDARD INFORMATION ATTRIBUTES
def get_si_attribute(s, localtz):
    si_attr = {
        'crtime': get_time(struct.unpack("<L", s[:4])[0], struct.unpack("<L", s[4:8])[0], localtz), # File create time; "<": little endian, "L": unassigned long (4 bytes)
        'mtime': get_time(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], localtz),  # MFT changed time; "<": little endian, "L": unassigned long (4 bytes)
        'ctime': get_time(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], localtz),  # Entry time; "<": little endian, "L": unassigned long (4 bytes)
        'atime': get_time(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], localtz),  # File alter time; "<": little endian, "L": unassigned long (4 bytes)
        'dos': struct.unpack("<I", s[32:36])[0], 'maxver': struct.unpack("<I", s[36:40])[0],
        'ver': struct.unpack("<I", s[40:44])[0], 'class_id': struct.unpack("<I", s[44:48])[0],
        'own_id': struct.unpack("<I", s[48:52])[0], 'sec_id': struct.unpack("<I", s[52:56])[0],
        'quota': struct.unpack("<d", s[56:64])[0], 'usn': struct.unpack("<d", s[64:72])[0],
    }

    return si_attr


def get_time(low, high, localtz):
    if low == 0 and high == 0:
        dt = 0
        dt_str = 'Undefined'
        unix_time = 0
        return dt, dt_str, unix_time
    unix_time = (float(high) * 2 ** 32 + low) * 1e-7 - 11644473600

    try:

        if localtz:
            dt = datetime.datetime.fromtimestamp(unix_time)
        else:
            dt = datetime.datetime.utcfromtimestamp(unix_time)

        # Edit timestamp delimiter
        dt_str = dt.isoformat(' ')
    except:
        dt = 0
        dt_str = 'Invalid timestamp'
        unix_time = 0
    return dt, dt_str, unix_time


def get_attr_header(pointer):
    d = {'type': struct.unpack("<L", pointer[:4])[0]} # Attribute Type; "<": little endian, "L": unassigned long (4 bytes)
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L", pointer[4:8])[0] # Length; "<": little endian, "L": unassigned long (4 bytes)
    d['res_flag'] = struct.unpack("B", pointer[8:9])[0] # Non-resident flag; "B": byte (1 byte)
    d['name_len'] = struct.unpack("B", pointer[9:10])[0] # Name length; "B": byte (1 byte)
    d['name_off'] = struct.unpack("<H", pointer[10:12])[0] # Offset to the name; "H": unsigned short (2 byte)
    d['flags'] = struct.unpack("<H", pointer[12:14])[0] # Flags; "H": unsigned short (2 byte)
    d['attr_id'] = struct.unpack("<H", pointer[14:16])[0] # Attribute ID; "H": unsigned short (2 byte)
    if d['res_flag'] == 0:
        d['ssize'] = struct.unpack("<L", pointer[16:20])[0]  # dwLength
        d['soff'] = struct.unpack("<H", pointer[20:22])[0]  # wAttrOffset
        d['idxflag'] = struct.unpack("B", pointer[22:23])[0]  # uchIndexedTag
    else:
        d['start_vcn'] = struct.unpack("<Q", pointer[16:24])[0]  # n64StartVCN
        d['last_vcn'] = struct.unpack("<Q", pointer[24:32])[0]  # n64EndVCN
        d['run_off'] = struct.unpack("<H", pointer[32:34])[0]  # wDataRunOffset (in clusters, from start of partition?)
        d['compsize'] = struct.unpack("<H", pointer[34:36])[0]  # wCompressionSize
        d['allocsize'] = struct.unpack("<Lxxxx", pointer[40:48])[0]  # n64AllocSize
        d['realsize'] = struct.unpack("<Lxxxx", pointer[48:56])[0]  # n64RealSize
        d['streamsize'] = struct.unpack("<Lxxxx", pointer[56:64])[0]  # n64StreamSize
        (d['ndataruns'], d['dataruns'], d['drunerror']) = unpack_dataruns(pointer[64:])
    return d

# Dataruns - http://inform.pucp.edu.pe/~inf232/Ntfs/ntfs_doc_v0.5/concepts/data_runs.html
def unpack_dataruns(datarun_str):
    dataruns = []
    numruns = 0
    pos = 0
    prevoffset = 0
    error = ''

    c_uint8 = ctypes.c_uint8

    class LengthBits(ctypes.LittleEndianStructure):
        _fields_ = [
            ("lenlen", c_uint8, 4),
            ("offlen", c_uint8, 4),
        ]

    class Lengths(ctypes.Union):
        _fields_ = [("b", LengthBits),
                    ("asbyte", c_uint8)]

    lengths = Lengths()

    # mftutils.hexdump(str,':',16)
    lengths.asbyte = struct.unpack("B", datarun_str[pos:1])[0]
    while True:
        lengths.asbyte = struct.unpack("B", datarun_str[pos+1:pos+2])[0]
        pos += 1
        if lengths.asbyte == 0x00:
            break

        if lengths.b.lenlen > 6 or lengths.b.lenlen == 0:
            error = "Datarun oddity."
            break
        bit_len = struct.unpack("<B", datarun_str[pos:pos + lengths.b.lenlen])[0]

        # print lengths.b.lenlen, lengths.b.offlen, bit_len
        pos += lengths.b.lenlen

        if lengths.b.offlen > 0:
            offset = struct.unpack("<B", datarun_str[pos:pos + lengths.b.offlen])[0]
            offset = offset + prevoffset
            prevoffset = offset
            pos += lengths.b.offlen
        else:  # Sparse
            offset = 0
            pos += 1

        dataruns.append([bit_len, offset])
        numruns += 1

        # print "Lenlen: %d Offlen: %d Len: %d Offset: %d" % (lengths.b.lenlen, lengths.b.offlen, bit_len, offset)
    print(numruns, dataruns, error, "\n-------------------------------------------------------------")
    return numruns, dataruns, error

# Get MFT
def get_mft_eh_val(file):
    # Currently only first header
    result = open("r.txt", "w")
    count = 0
    file.seek(0)
    while True:
        count += 1
        header = file.read(1024)
        if header[:4] == b'\x00\x00\x00\x00':
            #file.read(1024-48)
            continue
        if header[:4] == b'':
            result.close()
            break
        if header != "":
            record['signature'] = struct.unpack("<I", header[:4])[0] # Signature; "<": little endian, "I": unsigned int (4 bytes)
            record['fixup_offset'] = struct.unpack("<H", header[4:6])[0] # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
            record['fixup_values'] = struct.unpack("<H", header[6:8])[0] # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
            record['log_seq_num'] = struct.unpack("<d", header[8:16])[0] # LogFile Seq Number; "<": little endian, "d": double (8 bytes)
            record['seq_num'] = struct.unpack("<H", header[16:18])[0] # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
            record['ref_count'] = struct.unpack("<H", header[18:20])[0] # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
            record['attr_offset'] = struct.unpack("<H", header[20:22])[0] # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
            record['entry_flags'] = struct.unpack("<H", header[22:24])[0] # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
            record['used_entry_size'] = struct.unpack("<I", header[24:28])[0] # used entry size; "<": little endian, "I": unsigned int (4 bytes)
            record['total_entry_size'] = struct.unpack("<I", header[28:32])[0] # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
            record['base_rec_file_ref'] = struct.unpack("<Lxx", header[32:38])[0] # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
            record['base_rec_file_seq'] = struct.unpack("<H", header[38:40])[0] # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
            record['next_attr_id'] = struct.unpack("<H", header[40:42])[0] # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
            record['record_num'] = struct.unpack("<I", header[44:48])[0]  # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)
            result.write("Signature: " + str(record['signature']) + "\r\n")
            result.write("Fix-up offset: " + str(record['fixup_offset']) + "\r\n")
            result.write("Fix-up values: " + str(record['fixup_values']) + "\r\n")
            result.write("LogFile Seq Number: " + str(record['log_seq_num']) + "\r\n")
            result.write("Seq Number: " + str(record['seq_num']) + "\r\n")
            result.write("Reference Count: " + str(record['ref_count']) + "\r\n")
            result.write("Attribute offset: " + str(record['attr_offset']) + "\r\n")
            result.write("Entry Flags: " + str(record['entry_flags']) + "\r\n")
            result.write("used entry size: " + str(record['used_entry_size']) + "\r\n")
            result.write("Total entry size: " + str(record['total_entry_size']) + "\r\n")
            result.write("Base record file reference: " + str(record['base_rec_file_ref']) + "\r\n")
            result.write("Base record file seq: " + str(record['base_rec_file_seq']) + "\r\n")
            result.write("Next attribute identifier: " + str(record['next_attr_id']) + "\r\n")
            result.write("MFT Entry record number: " + str(record['record_num']) + "\r\n")
            result.write("-"*300 + "\r\n")
            print(count)

            get_mft_data(header)

        else:
            result.close()
            break


# MAIN FUNCTION
def main(args):
    try:
        opts, args = getopt.getopt(args, "hf:")
    except getopt.GetoptError:
        print("ICT2202_Tool.py -f <raw MFT filename>")
    for opt, arg in opts:
        if opt == "-h":
            print("ICT2202_Tool.py -f <raw MFT filename>")
            sys.exit(2) # exit with a syntax error
        elif opt == "-f":
            f = open(arg, "rb")

            get_mft_eh_val(f)


if __name__ == "__main__":
    main(sys.argv[1:])