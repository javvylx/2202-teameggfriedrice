import shutil
import os
import argparse
import pytz #timezone
from datetime import datetime as dt
import pywintypes #Module which supposrts common windows type
import filetype #Determine original file extension
import hashlib #Generate MD5
import PyPDF2 # Read PDF Metadata

##Run this on command prompt. If you are unsure, do this - python file_extract.py -h

__description__ = "Gather filesystem metadata of provided file"

def file_import():
    parser = argparse.ArgumentParser(description=__description__)

    parser.add_argument("source", help="Source file")

    args = parser.parse_args()

    source = os.path.abspath(args.source)

    if os.sep in args.source:
        src_file_name = args.source.split(os.sep, 1)[1]
    else:
        src_file_name = args.source

    tz = pytz.timezone("Asia/Singapore")

    return source, tz, src_file_name


def file_extension(file):
    ext = filetype.guess(file)
    print("Extension: {}\nMultipurpose Internet Mail Extensions: {}\n".format(ext.extension, ext.MIME))

def file_timestamp(source,tz):
    created = dt.fromtimestamp(os.path.getctime(source))
    created = pywintypes.Time(tz.localize(created))
    modified = dt.fromtimestamp(os.path.getmtime(source))
    modified = pywintypes.Time(tz.localize(modified))
    accessed = dt.fromtimestamp(os.path.getatime(source))
    accessed = pywintypes.Time(tz.localize(accessed))
    print("Created: {}\nModified: {}\nAccessed: {}\n".format(created, modified, accessed))

def file_abspath(file):
    print ("File absolute path: {}\n".format(os.path.abspath(file)))

def file_checksum(file):
    md5_hash = hashlib.md5()
    file_open = open(file,"rb")
    content = file_open.read()
    md5_hash.update(content)
    digest = md5_hash.hexdigest()
    print("MD5: {}\n".format(digest))

def file_pdf(file,filename):
    pdfFile = PyPDF2.PdfFileReader(file)
    data = pdfFile.getDocumentInfo()
    print ("======Meta data for the file======")
    count = 1
    for metadata in data:
        print ("{}) {}: {}".format(count, metadata[1:], data[metadata]))
        count+=1

source, tz, src_file_name = file_import()
file_extension(source)
file_timestamp(source, tz)
file_checksum(source)
file_abspath(source)
file_pdf(source, src_file_name)






