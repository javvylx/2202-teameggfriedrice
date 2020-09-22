import shutil
import os
import argparse
import pytz
from datetime import datetime as dt
import pywintypes
import filetype

__description__ = "Gather filesystem metadata of provided file"


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

def file_import():
    parser = argparse.ArgumentParser(description=__description__)

    parser.add_argument("source", help="Source file")

    args = parser.parse_args()

    source = os.path.abspath(args.source)

    tz = pytz.timezone("Asia/Singapore")

    return source, tz

source, tz = file_import()
file_extension(source)
file_timestamp(source, tz)






