# function to identify file type based on file header and magic number
# pip install python-magic-bin
# pip install pillow

# IMPORT MODULES
import sys
import os
import magic
from PIL import Image, ExifTags

# Directory to process the file types. Can be changed later
directory = str(sys.argv[1])

# For all files in the directory
for filename in os.listdir(directory):
    # File path
    f_path = '%s/%s' % (directory, filename)
    # Check the file type based on the file headers and magic number
    # Return MIME type
    file_type = magic.from_file(f_path, mime=True)
    ft = file_type.split("/")

    print('File Name: %s' % filename)
    print('File Type: %s\n' % ft[1].upper())

    # If the file is an image type
    # Perform Exiftool to extract and print any metadata
    if ft[0] == 'image':
        print('File Metadata:\n')
        try:
            img = Image.open(f_path)
            if ft[1] == 'png':
                print('%s' % f_path.info)
            else:
                exif = {ExifTags.TAGS[k]: v for k, v in img._getexif().items() if k in ExifTags.TAGS}
                for metadata, value in exif.items():
                    print('%s:\t\t%s' % (metadata, value))
        except AttributeError:
            print('No metadata found.\n')
        print('--------------------------------------------------------------------------------------')

    # Else, print the file type only.
    else:
        print('--------------------------------------------------------------------------------------')
