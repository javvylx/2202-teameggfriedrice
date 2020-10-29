import binascii, json, ctypes, struct, os, sys, getopt, datetime, csv
#from py_to_docx import FileMetaExtractor

#fileme = FileMetaExtractor()

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

        if attr_record['type'] == 0x30:  # File Name
            fn_record = get_fn_attribute(raw_file[read_ptr + attr_record['soff']:], TIMEZONE)
            mft_record['fncount'] += 1
            mft_record['fn', mft_record['fncount']] = fn_record

        if attr_record['len'] > 0:
                read_ptr = read_ptr + attr_record['len']
        else:
            return mft_record

    return mft_record
    


#* GET STANDARD INFORMATION ATTRIBUTES
def get_si_attribute(s, tz):
    si_attr = {
        'crtime': get_time(struct.unpack("<L", s[:4])[0], struct.unpack("<L", s[4:8])[0], tz), # File create time; "<": little endian, "L": unassigned long (4 bytes)
        'mtime': get_time(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], tz),  # MFT changed time; "<": little endian, "L": unassigned long (4 bytes)
        'ctime': get_time(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], tz),  # Entry time; "<": little endian, "L": unassigned long (4 bytes)
        'atime': get_time(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], tz),  # File alter time; "<": little endian, "L": unassigned long (4 bytes)
        'dos': struct.unpack("<I", s[32:36])[0], 'maxver': struct.unpack("<I", s[36:40])[0],
        'ver': struct.unpack("<I", s[40:44])[0], 'class_id': struct.unpack("<I", s[44:48])[0],
        'own_id': struct.unpack("<I", s[48:52])[0], 'sec_id': struct.unpack("<I", s[52:56])[0],
        'quota': struct.unpack("<d", s[56:64])[0], 'usn': struct.unpack("<q", s[64:72])[0],
    }

    return si_attr

#* GET FILE NAME ATTRIBUTES
def get_fn_attribute(s, tz):
    fn_attr = {
        'par_ref': struct.unpack("<Lxx", s[:6])[0], 'par_seq': struct.unpack("<H", s[6:8])[0],
        'crtime': get_time(struct.unpack("<L", s[8:12])[0], struct.unpack("<L", s[12:16])[0], tz),
        'mtime': get_time(struct.unpack("<L", s[16:20])[0], struct.unpack("<L", s[20:24])[0], tz),
        'ctime': get_time(struct.unpack("<L", s[24:28])[0], struct.unpack("<L", s[28:32])[0], tz),
        'atime': get_time(struct.unpack("<L", s[32:36])[0], struct.unpack("<L", s[36:40])[0], tz),
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
def get_time(low, high, tz):
    if low == 0 and high == 0:
        dt = 0
        dt_str = 'Undefined'
        unix_time = 0
        return
    unix_time = (float(high) * 2 ** 32 + low) * 1e-7 - 11644473600

    try:

        if tz:
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

    # if mft_record['end_seq_1'] is None or mft_record['end_seq_2'] is None:
    #     return 1
    # elif mft_record['fixup_data'] is None:
    #     return 2
    if mft_record['end_seq_1'] != mft_record['fixup_data'] or mft_record['end_seq_2'] != mft_record['fixup_data']:
        return 1

    return 0

#* CHECK FOR $SI TIMESTAMP ANOMALIES
def anomaly_timestamp_check_SI(mft_record):
    '''
    Flags for $SI Checks
    0: Okay
    1. 0s in $SI
    2: Invalid $SI Timestamp
    3. $SI nanosec = 0
    4. $SI (crtime) after $SI (mtime)
    5. $SI (atime) after $SI (mtime) and $SI (atime) after $SI (crtime)
    6. $SI after Current Time
    '''

    # Check for any only 0s in $SI
    if mft_record['si']['crtime'] is None or mft_record['si']['mtime'] is None or mft_record['si']['ctime'] is None or mft_record['si']['atime'] is None:
        return 1

    # Check for any invalid timestamp in $SI
    elif mft_record['si']['crtime'][0] == 0 or mft_record['si']['mtime'][0] == 0 or mft_record['si']['ctime'][0] == 0 or mft_record['si']['atime'][0] == 0:
        return 2

    # Check for $SI with a nanosecond value of '0'
    else:
        if mft_record['si']['crtime'][2] != 0:
            if str(mft_record['si']['crtime'][2]).split('.')[1] == str(0):
                return 3
        elif mft_record['si']['mtime'][2] != 0:
            if str(mft_record['si']['mtime'][2]).split('.')[1] == str(0):
                return 3
        elif mft_record['si']['ctime'][2] != 0:
            if str(mft_record['si']['ctime'][2]).split('.')[1] == str(0):
                return 3
        elif mft_record['si']['atime'][2] != 0:
            if str(mft_record['si']['atime'][2]).split('.')[1] == str(0):
                return 3

        # Check for $SI Create Time after the $SI Modify Time
        if mft_record['si']['crtime'][1] > mft_record['si']['mtime'][1]:
            return 4

        # Check for #SI Access Time after the $SI Modify and $SI Create Time
        if mft_record['si']['atime'][1] > mft_record['si']['mtime'][1] and mft_record['si']['atime'][1] > mft_record['si']['crtime'][1]:
            return 5

        # Check for $SI Time after Current Time
        if mft_record['si']['crtime'][1] > str(datetime.datetime.now()) or mft_record['si']['mtime'][1] > str(datetime.datetime.now()) or mft_record['si']['ctime'][1] > str(datetime.datetime.now()) or mft_record['si']['atime'][1] > str(datetime.datetime.now()):
            return 6

    # Return Flag 0 for no anomalies    
    return 0

#* CHECK FOR $FN & $SI TIMESTAMP ANOMALIES
def anomaly_timestamp_check_SI_FN(mft_record,fn_count):
    '''
    Flags for both $SI and $FN
    0: Okay
    1: 0s in $FN
    2: Invalid $FN Timestamp
    3. $FN nanosec = 0
    4: $SI (crtime) before $FN (crtime)
    5: $FN after Current Time
    '''
    check = 1
    while check <= fn_count:
            
        # Check for any only 0s in $FN
        if mft_record['fn', check]['crtime'] is None or mft_record['fn', check]['mtime'] is None or mft_record['fn', check]['ctime'] is None or mft_record['fn', check]['atime'] is None:
            return 1

        # Check for any invalid timestamp in $FN
        elif mft_record['fn', check]['crtime'][0] == 0 or mft_record['fn', check]['mtime'][0] == 0 or mft_record['fn', check]['ctime'][0] == 0 or mft_record['fn', check]['atime'][0] == 0:
            return 2

        else:
            if mft_record['fn', check]['crtime'][2] != 0:
                if str(mft_record['fn', check]['crtime'][2]).split('.')[1] == str(0):
                    return 3
            elif mft_record['fn', check]['mtime'][2] != 0:
                if str(mft_record['fn', check]['mtime'][2]).split('.')[1] == str(0):
                    return 3
            elif mft_record['fn', check]['ctime'][2] != 0:
                if str(mft_record['fn', check]['ctime'][2]).split('.')[1] == str(0):
                    return 3
            elif mft_record['fn', check]['atime'][2] != 0:
                if str(mft_record['fn', check]['atime'][2]).split('.')[1] == str(0):
                    return 3

            # Check for $SI Create Time is before $FN Create Time
            if mft_record['si']['crtime'][1] < mft_record['fn', check]['crtime'][1]:
                return 4

            # Check for $FN Time after Current Time
            if mft_record['fn', check]['crtime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['mtime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['ctime'][1] > str(datetime.datetime.now()) or mft_record['fn', check]['atime'][1] > str(datetime.datetime.now()):
                return 5
        
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
        'fixup_data' : raw_data[struct.unpack("<H", raw_data[4:6])[0]:struct.unpack("<H", raw_data[4:6])[0]+2],
        'end_seq_1' : raw_data[510:512],
        'end_seq_2' : raw_data[1022:],
        'fncount' : 0 # Number of $FN
    }
    return mft_record

def csvheader():
    listheader = ["Data Number", "Signature", "Fix-up Data Offset", "Fix-up Data Array Size", "Log Sequence Number",
    "Sequence Number", "Reference Count", "Attribute Offset", "Entry Flags", "MFT Record Actual Size", "MFT Record Allocated",
    "Base Record File Reference", "Next Attribute ID", "MFT Data Number",
    "$SI Creation Time", "$SI Modified Time", "$SI Change Time", "$SI Access Time", "DOS File Permission", "Owner ID",
    "$FN_1 Creation Time", "$FN_1 Modified Time", "$FN_1 Change Time", "$FN_1 Access Time", "$FN_1 Flag", "$FN_1 Filename Length", "$FN_1 Name Space Length", "$FN_1 Filename", 
    "$FN_2 Creation Time", "$FN_2 Modified Time", "$FN_2 Change Time", "$FN_2 Access Time", "$FN_2 Flag", "$FN_2 Filename Length", "$FN_2 Name Space Length", "$FN_2 Filename", 
    "$FN_3 Creation Time", "$FN_3 Modified Time", "$FN_3 Change Time", "$FN_3 Access Time", "$FN_3 Flag", "$FN_3 Filename Length", "$FN_3 Name Space Length", "$FN_3 Filename"]
    return listheader

def excel_date(date1):
    return '="{}"'.format(date1)

#! Main function
def get_mft_eh_val(file):
    result = open("log.csv", "w")  #! <-- txt file dir to be changed
    count = 0
    overalldata, wd=[],[]
    listcsvcolumns = csvheader()
    writer = csv.writer(result, delimiter=',')
    writer.writerow(listcsvcolumns)
    file.seek(0)
    anomaly_SI_1, anomaly_SI_2, anomaly_SI_3, anomaly_SI_4, anomaly_SI_5, anomaly_SI_6 = 0, 0, 0, 0, 0, 0
    anomaly_SI_FN_1, anomaly_SI_FN_2, anomaly_SI_FN_3, anomaly_SI_FN_4, anomaly_SI_FN_5= 0, 0, 0, 0, 0
    anonamlymftrecord = 0
    test = 0
    a1, a2 = True, True
    while (True):
        count += 1
        hexdata = file.read(1024)
        if hexdata[:4] == b'\x00\x00\x00\x00':
            test += 1
            continue
        if hexdata[:4] == b'':
            result.close()
            break
        if hexdata != "":
            #? Get MFT entry header
            mft_record = {}
            mft_record = get_mft_entry_header(hexdata)
            # print("----------------------------------------------------" + str(count) + "----------------------------------------------------")

            mft_record = get_mft_data(hexdata, mft_record, mft_record['attr_offset'])
            mft_record['datanumber'] = count
            #print("-"*200)
            # print(mft_record)
            # print("-"*200)
            x = writecsv(mft_record)
            writer.writerow(x)
            bool_mftrecord_check = anomaly_mftrecord_check(mft_record)
            if bool_mftrecord_check == 1:
                wd.append((count, "anonamlymftrecord"))
                anonamlymftrecord += 1

            #print(bool_mftrecord_check)
            #print("-"*200)
            #print(mft_record)
            # if(count == 30):
            #     break
            
            #* Do Anomaly Check on $SI only
            if 'si' in mft_record:
                flag_SI = anomaly_timestamp_check_SI(mft_record)
                if flag_SI != 0:
                    if flag_SI == 1:
                        wd.append((count, "anomaly_SI_1"))
                        anomaly_SI_1 += 1
                        a1 = False
                    if flag_SI == 2:
                        wd.append((count, "anomaly_SI_2"))
                        anomaly_SI_2 += 1
                        a2 = False
                    if flag_SI == 3:
                        wd.append((count, "anomaly_SI_3"))
                        anomaly_SI_3 += 1
                    if flag_SI == 4:
                        wd.append((count, "anomaly_SI_4"))
                        anomaly_SI_4 += 1
                    if flag_SI == 5:
                        wd.append((count, "anomaly_SI_5"))
                        anomaly_SI_5 += 1
                    if flag_SI == 6:
                        wd.append((count, "anomaly_SI_6"))
                        anomaly_SI_6 += 1
            
            #* Do Anomaly check only if both $SI and $FN is available
            if mft_record['fncount'] > 0 and mft_record['fn', 1] and 'si' in mft_record and a1 and a2:
                flag_SI_FN = anomaly_timestamp_check_SI_FN(mft_record,mft_record['fncount'])
                if flag_SI_FN != 0:
                    if flag_SI_FN == 1:
                        wd.append((count, "anomaly_SI_FN_1"))
                        anomaly_SI_FN_1 += 1
                    if flag_SI_FN == 2:
                        wd.append((count, "anomaly_SI_FN_2"))
                        anomaly_SI_FN_2 += 1
                    if flag_SI_FN == 3:
                        wd.append((count, "anomaly_SI_FN_3"))
                        anomaly_SI_FN_3 += 1
                    if flag_SI_FN == 4:
                        wd.append((count, "anomaly_SI_FN_4"))
                        anomaly_SI_FN_4 += 1
                    if flag_SI_FN == 5:
                        wd.append((count, "anomaly_SI_FN_5"))
                        anomaly_SI_FN_5 += 1
            
            a1, a2 = True, True

        else:
            result.close()
            break
    #******************************************************************************************************************************************#
    '''
    Data passing to Jav [overalldata]
    anonamlymftrecord : MFT record might be tampered/damaged
    anomaly_SI_1 : 0s in $SI
    anomaly_SI_2 : Invalid $SI Timestamp
    anomaly_SI_3 : $SI nanosec = 0
    anomaly_SI_4 : $SI (crtime) after $SI (mtime)
    anomaly_SI_5 : $SI (atime) after $SI (mtime) and $SI (atime) after $SI (crtime)
    anomaly_SI_6 : $SI after Current Time
    anomaly_SI_FN_1 : 0s in $FN
    anomaly_SI_FN_2 : Invalid $FN Timestamp
    anomaly_SI_FN_3 : $FN nanosec = 0
    anomaly_SI_FN_4 : $SI (crtime) after $FN (crtime)
    anomaly_SI_FN_5 : $FN after Current Time
    '''
    #******************************************************************************************************************************************#
    overalldata.extend([count,anonamlymftrecord,anomaly_SI_1,anomaly_SI_2,anomaly_SI_3,anomaly_SI_4,anomaly_SI_5,anomaly_SI_6,anomaly_SI_FN_1,anomaly_SI_FN_2,anomaly_SI_FN_3,anomaly_SI_FN_4,anomaly_SI_FN_5])
    #******************************************************************************************************************************************#
    '''
    Data passing to Jav [wd]
    - List
    -- Tuple
    '''
    #! JAVIER
    #! JAVIER
    #! JAVIER
    #******************************************************************************************************************************************#
    #fileme.createReport(overalldata,wd,fileme.fileHash(file))
    #******************************************************************************************************************************************#
    print(test)
    print("anomalymftrecord: " + str(anonamlymftrecord))
    print("Anomaly $SI: ", anomaly_SI_1, anomaly_SI_2, anomaly_SI_3, anomaly_SI_4, anomaly_SI_5, anomaly_SI_6)
    print("Anomaly $SI + $FN: ", anomaly_SI_FN_1, anomaly_SI_FN_2, anomaly_SI_FN_3, anomaly_SI_FN_4, anomaly_SI_FN_5)

def signaturechk(n):
    if n == 1162627398:
        return "Good MFT Signature"
    else:
        return "Bad MFT Signature"

def padding(n):
    t = []
    for x in range(n):
        t.append('')
    return t

def writecsv(mft_record):
    csvcontent = [mft_record['datanumber'], signaturechk(mft_record['signature']), 
                    mft_record['fixup_offset'],mft_record['fixup_arraysize'],
                    mft_record['log_seq_num'],mft_record['seq_num'],
                    mft_record['ref_count'],mft_record['attr_offset'],
                    mft_record['entry_flags'],mft_record['used_entry_size'],
                    mft_record['total_entry_size'],mft_record['base_rec_file_ref'],
                    mft_record['next_attr_id'],mft_record['record_num']]
    #print(mft_record['si']['crtime'])
    if 'si' not in mft_record:
        csvcontent.extend(padding(6))
    elif 'si' in mft_record:
        if mft_record['si']['crtime'] is not None:
            csvcontent.extend([excel_date(mft_record['si']['crtime'][1])])
        else:
            csvcontent.extend(padding(1))
        if mft_record['si']['mtime'] is not None:
            csvcontent.extend([excel_date(mft_record['si']['mtime'][1])])
        else:
            csvcontent.extend(padding(1))
        if mft_record['si']['ctime'] is not None:
            csvcontent.extend([excel_date(mft_record['si']['ctime'][1])])
        else:
            csvcontent.extend(padding(1))
        if mft_record['si']['atime'] is not None:
            csvcontent.extend([excel_date(mft_record['si']['atime'][1])])
        else:
            csvcontent.extend(padding(1))
        csvcontent.extend([mft_record['si']['dos'], mft_record['si']["own_id"]])
    if mft_record['fncount'] == 0:
        csvcontent.extend(padding(21))
    elif mft_record['fncount'] > 0:
        for i in range(3):
            if (i) == mft_record['fncount']-1:
                break
            check = i + 1
            if mft_record['fn', check]['crtime'] is not None:
                csvcontent.extend([excel_date(mft_record['fn', check]['crtime'][1])])
            else:
                csvcontent.extend(padding(1))
            if mft_record['fn', check]['mtime'] is not None:
                csvcontent.extend([excel_date(mft_record['fn', check]['mtime'][1])])
            else:
                csvcontent.extend(padding(1))
            if mft_record['fn', check]['ctime'] is not None:
                csvcontent.extend([excel_date(mft_record['fn', check]['ctime'][1])])
            else:
                csvcontent.extend(padding(1))
            if mft_record['fn', check]['atime'] is not None:
                csvcontent.extend([excel_date(mft_record['fn', check]['atime'][1])])
            else:
                csvcontent.extend(padding(1))
            csvcontent.extend([mft_record['fn', check]['flags'], mft_record['fn',check]['nlen'],mft_record['fn',check]['nspace'], str(mft_record['fn',check]['name'])[2:-1]])
    if mft_record['fncount'] < 3:
        csvcontent.extend(padding((3-mft_record['fncount'])*7))
    return csvcontent

    
    


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