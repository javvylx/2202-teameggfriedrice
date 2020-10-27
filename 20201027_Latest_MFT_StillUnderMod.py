import binascii, json, ctypes, struct, os, sys, getopt, datetime

#* Timezone of his script follows host's Timezone
TIMEZONE = datetime.datetime.now().astimezone().tzinfo

#* GET MFT ATTRIBUTE DATA
def get_mft_data(raw_file, mft_record, read_ptr):

    # Generally each file MFT is 1024 btyes
    while read_ptr < 1024:

        attr_record = get_attr_header(raw_file[read_ptr:])
        if attr_record['type'] == 0xffffffff:  # End of attributes
            return mft_record

        if attr_record['name_len'] > 0:
            file_bytes = raw_file[
                        read_ptr + attr_record['name_off']: read_ptr + attr_record['name_off'] + attr_record[
                            'name_len'] * 2]
            attr_record['name'] = file_bytes.decode('utf-16').encode('utf-8')
        else:
            attr_record['name'] = ''

        if attr_record['type'] == 0x10:  # Standard Information
            si_record = get_si_attribute(raw_file[read_ptr + attr_record['soff']:], TIMEZONE)
            mft_record['si'] = si_record

        if attr_record['type'] == 0x30:  #! File Name
            fn_record = get_fn_attribute(raw_file[read_ptr + attr_record['soff']:], TIMEZONE)
            mft_record['fncount'] += 1
            mft_record['fn', mft_record['fncount']] = fn_record

        if attr_record['len'] > 0:
                read_ptr = read_ptr + attr_record['len']
        else:
            return mft_record
    


#* GET STANDARD INFORMATION ATTRIBUTES
def get_si_attribute(s, localtz):
    si_attr = {
        'crtime': get_time(struct.unpack("<L", s[:4])[0], struct.unpack("<L", s[4:8])[0], localtz), # File create time; "<": little endian, "L": unassigned long (4 bytes)
        'mtime': get_time(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], localtz),  # MFT changed time; "<": little endian, "L": unassigned long (4 bytes)
        'ctime': get_time(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], localtz),  # Entry time; "<": little endian, "L": unassigned long (4 bytes)
        'atime': get_time(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], localtz),  # File alter time; "<": little endian, "L": unassigned long (4 bytes)
        'dos': struct.unpack("<I", s[32:36])[0], 'maxver': struct.unpack("<I", s[36:40])[0],
        'ver': struct.unpack("<I", s[40:44])[0], 'class_id': struct.unpack("<I", s[44:48])[0],
        'own_id': struct.unpack("<I", s[48:52])[0], 'sec_id': struct.unpack("<I", s[52:56])[0],
        'quota': struct.unpack("<d", s[56:64])[0], 'usn': struct.unpack("<q", s[64:72])[0],
    }

    return si_attr

#! GET FILE NAME ATTRIBUTES
def get_fn_attribute(s, localtz):
    fn_attr = {
        'par_ref': struct.unpack("<Lxx", s[:6])[0], 'par_seq': struct.unpack("<H", s[6:8])[0],
        'crtime': get_time(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], localtz),
        'mtime': get_time(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], localtz),
        'ctime': get_time(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], localtz),
        'atime': get_time(struct.unpack("<L", s[32:36])[0], struct.unpack("<L", s[36:40])[0], localtz),
        'alloc_fsize': struct.unpack("<q", s[40:48])[0],
        'real_fsize': struct.unpack("<q", s[48:56])[0],
        'flags': struct.unpack("<q", s[56:64])[0],
        'nlen': struct.unpack("B", bytes([s[64]]))[0],
        'nspace': struct.unpack("B", bytes([s[65]]))[0],
    }

    attr_bytes = s[66:66 + fn_attr['nlen'] * 2]
    try:
        fn_attr['name'] = attr_bytes.decode('utf-16').encode('utf-8')
    except:
        fn_attr['name'] = 'UnableToDecodeFilename'

    return fn_attr

#* CONVERT FILETIME TO UNIX TIME
def get_time(low, high, localtz):
    if low == 0 and high == 0:
        dt = 0
        dt_str = 'Undefined'
        unix_time = 0
        return
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

#! CHECK FOR MFT RECORD ANOMALIES
def anomaly_mftrecord_check(mft_record):
    if mft_record['end_seq_1'] != mft_record['fixup_data'] or mft_record['end_seq_2'] != mft_record['fixup_data']:
        return 1
    return 0


#! CHECK FOR TIMESTAMP ANOMALIES
def anomaly_timestamp_check(mft_record,fn_count):
    '''
    Flags
    0: Okay
    1: 0s in $SI
    2: 0s in $FN
    3: Invalid Timestamp
    4: $SI (crtime) after $FN (crtime)
    5. $SI (crtime) millisec = 0
    6. $SI (crtime) after $SI (mtime)
    7. $SI (atime) after $SI (mtime) and $SI (atime) after $SI (crtime)
    8: $SI after Current Time
    9: $FN after Current TIme
    '''
    check = 1
    while check <= fn_count:

        # Check for any only 0s in $SI
        if mft_record['si']['crtime'] is None or mft_record['si']['mtime'] is None or mft_record['si']['ctime'] is None or mft_record['si']['atime'] is None:
            return 1

        # Check for any only 0s in $FN
        elif mft_record['fn', check]['crtime'] is None or mft_record['fn', check]['mtime'] is None or mft_record['fn', check]['ctime'] is None or mft_record['fn', check]['atime'] is None:
            return 2

        # Check for any invalid timestamp in $SI and $FN
        elif mft_record['si']['crtime'][0] == 0 or mft_record['si']['mtime'][0] == 0 or mft_record['si']['ctime'][0] == 0 or mft_record['si']['atime'][0] == 0 \
        or mft_record['fn', check]['crtime'][0] == 0 or mft_record['fn', check]['mtime'][0] == 0 or mft_record['fn', check]['ctime'][0] == 0 or mft_record['fn', check]['atime'][0] == 0:
            return 3

        else:
            # Check for $SI Create Time is before $FN Create Time
            if mft_record['si']['crtime'][1] < mft_record['fn', check]['crtime'][1]:
                return 4

            # Check for $SI Create Time with a nanosecond value of '0'     
            if mft_record['si']['crtime'][2] != 0:
                if str(mft_record['si']['crtime'][2]).split('.')[1] == str(0):
                    return 5

            # Check for $SI Create Time after the $SI Modify Time
            if mft_record['si']['crtime'][1] > mft_record['si']['mtime'][1]:
                return 6

            # Check for #SI Access Time after the $SI Modify and $SI Create Time
            if mft_record['si']['atime'][1] > mft_record['si']['mtime'][1] and mft_record['si']['atime'][1] > mft_record['si']['crtime'][1]:
                return 7
            
            # Check for $SI Time after Current Time
            if mft_record['si']['crtime'][1] > str(datetime.datetime.now()) or mft_record['si']['mtime'][1] > str(datetime.datetime.now()) or mft_record['si']['ctime'][1] > str(datetime.datetime.now()) or mft_record['si']['atime'][1] > str(datetime.datetime.now()):
                return 8

            # Check for $FN Time after Current Time
            if mft_record['fn', check]['crtime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['mtime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['ctime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['atime'][1] > str(datetime.datetime.now()):
                return 9
        
        check += 1

    # Return Flag 0 for no anomalies
    return 0


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
        #(d['ndataruns'], d['dataruns'], d['drunerror']) = unpack_dataruns(pointer[64:])
    # print(d)
    return d

def get_mft_entry_header(raw_data):
    mft_record = {
        'signature' : struct.unpack("<I", raw_data[:4])[0], # Signature; "<": little endian, "I": unsigned int (4 bytes)
        'fixup_offset' : struct.unpack("<H", raw_data[4:6])[0], # Fix-up offset; "<": little endian, "H": unsigned short (2 bytes)
        'fixup_arraysize' : struct.unpack("<H", raw_data[6:8])[0], # Fix-up values; "<": little endian, "H": unsigned short (2 bytes)
        'log_seq_num' : struct.unpack("<q", raw_data[8:16])[0], # LogFile Seq Number; "<": little endian, "q": long long (8 bytes)
        'seq_num' : struct.unpack("<H", raw_data[16:18])[0], # Seq Number; "<": little endian, "H": unsigned short (2 bytes)
        'ref_count' : struct.unpack("<H", raw_data[18:20])[0], # Reference Count; "<": little endian, "H": unsigned short (2 bytes)
        'attr_offset' : struct.unpack("<H", raw_data[20:22])[0], # Attribute offset; "<": little endian, "H": unsigned short (2 bytes)
        'entry_flags' : struct.unpack("<H", raw_data[22:24])[0], # Entry Flags; "<": little endian, "H": unsigned short (2 bytes)
        'used_entry_size' : struct.unpack("<I", raw_data[24:28])[0], # used entry size; "<": little endian, "I": unsigned int (4 bytes)
        'total_entry_size' : struct.unpack("<I", raw_data[28:32])[0], # Total entry size (possible > 1024 bytes); "<": little endian, "I": unsigned int (4 bytes)
        'base_rec_file_ref' : struct.unpack("<Lxx", raw_data[32:38])[0], # Base record file reference; "<": little endian, "I": unsigned int (4 bytes), "x": just padding only (1 byte per x)
        'base_rec_file_seq' : struct.unpack("<H", raw_data[38:40])[0], # Base record file seq; "<": little endian, "H": unsigned short (2 bytes)
        'next_attr_id' : struct.unpack("<H", raw_data[40:42])[0], # Next attribute identifier; "<": little endian, "H": unsigned short (2 bytes)
        'record_num' : struct.unpack("<I", raw_data[44:48])[0], # MFT Entry record number; "<": little endian, "I": unsigned int (4 bytes)
        'fixup_data' : raw_data[struct.unpack("<H", raw_data[6:8])[0]:struct.unpack("<H", raw_data[6:8])[0]+2],
        'end_seq_1' : raw_data[510:512],
        'end_seq_2' : raw_data[1022:],
        'fncount' : 0 # Number of $FN
    }
    return mft_record

#! Main function
def get_mft_eh_val(file):
    result = open("log.txt", "w")  #! <-- txt file dir to be changed
    count = 0
    file.seek(0)
    anomaly_1, anomaly_2, anomaly_3, anomaly_4, anomaly_5, anomaly_6, anomaly_7, anomaly_8, anomaly_9 = 0, 0, 0, 0, 0, 0, 0, 0, 0
    while (True):
        count += 1
        hexdata = file.read(1024)
        if hexdata[:4] == b'\x00\x00\x00\x00':
            continue
        if hexdata[:4] == b'':
            result.close()
            break
        if hexdata != "":
            #? Get MFT entry header
            mft_record = get_mft_entry_header(hexdata)
            result.write("Signature: " + str(mft_record['signature']) + "\r\n")
            result.write("Fix-up offset: " + str(mft_record['fixup_offset']) + "\r\n")
            result.write("Fix-up values: " + str(mft_record['fixup_arraysize']) + "\r\n")
            result.write("LogFile Seq Number: " + str(mft_record['log_seq_num']) + "\r\n")
            result.write("Seq Number: " + str(mft_record['seq_num']) + "\r\n")
            result.write("Reference Count: " + str(mft_record['ref_count']) + "\r\n")
            result.write("Attribute offset: " + str(mft_record['attr_offset']) + "\r\n")
            result.write("Entry Flags: " + str(mft_record['entry_flags']) + "\r\n")
            result.write("used entry size: " + str(mft_record['used_entry_size']) + "\r\n")
            result.write("Total entry size: " + str(mft_record['total_entry_size']) + "\r\n")
            result.write("Base mft_record file reference: " + str(mft_record['base_rec_file_ref']) + "\r\n")
            result.write("Base record file seq: " + str(mft_record['base_rec_file_seq']) + "\r\n")
            result.write("Next attribute identifier: " + str(mft_record['next_attr_id']) + "\r\n")
            result.write("MFT Entry record number: " + str(mft_record['record_num']) + "\r\n")
            result.write("-"*300 + "\r\n")
            # print(count)
            # print(str(record['record_num']))

            mft_record = get_mft_data(hexdata, mft_record, mft_record['attr_offset'])
            print("----------------------------------------------------" + str(count) + "----------------------------------------------------")
            print(mft_record)

            bool_mftrecord_check = anomaly_mftrecord_check(mft_record)

            print(mft_record)
            if(count == 30):
                break

            #! Do the check only if both $SI and $FN is available
            if mft_record['fncount'] > 0 and mft_record['fn', 1] and mft_record['si']:
                flag = anomaly_timestamp_check(mft_record,mft_record['fncount'])
                if flag != 0:
                    if flag == 1:
                        anomaly_1 += 1
                    if flag == 2:
                        anomaly_2 += 1
                    if flag == 3:
                        anomaly_3 += 1
                    if flag == 4:
                        anomaly_4 += 1
                    if flag == 5:
                        anomaly_5 += 1
                    if flag == 6:
                        anomaly_6 += 1
                    if flag == 7:
                        anomaly_7 += 1
                    if flag == 8:
                        anomaly_8 += 1
                    if flag == 9:
                        anomaly_9 += 1

        else:
            result.close()
            break

    print(anomaly_1, anomaly_2, anomaly_3, anomaly_4, anomaly_5, anomaly_6, anomaly_7, anomaly_8, anomaly_9)

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