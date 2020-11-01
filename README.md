# SIT ICT 2202 AY20/21 Digital Forensic Project
This is a Year 2 Trimester 1 ICT 2202 - Digital Forensic Project. This project's objective is to design and develop a technical solution for a problem in digital forensics.

The tool identifies timestamp and Master File Table (MFT) record anomalies automatically and return the user with a consolidated digital forensic summary report of all the findings of potential areas of forensic investigation. The MFT records, including the MFT entry header, Standard Information attribute table and File Name attribute table, will be examined to extract and analyse its offset values.

<a href="http://www.youtube.com/watch?feature=player_embedded&v=2RpdTD4ShGE" target="_blank"><img src="https://img.youtube.com/vi/2RpdTD4ShGE/maxresdefault.jpg" 
alt="ICT2202 MFT Analyser - TeamEggFriedRice" width="240" height="180" border="10" /></a>

## Getting Started
Download the project into a folder of your choice using the following [link](https://github.com/javvylx/2202-teameggfriedrice)
> **_NOTE:_** The tool is only compatible with Windows OS

## Dependencies

To install the tools, run `pip install` in python console/terminal:
> Example: `pip install python-docx`

| Dependency | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| Python 3   | High-level and general-purpose coding language.                             |
| struct     | A Python library to format, pack and unpack strings to the required format. |
| os         | A Python library to use Operating System dependent functionalities.         |
| datetime   | A Python library to manipulate date and time.                               |
| csv        | A Python library to read or write to csv file.                              |
| hashlib    | A Python library with different hash functions.                             |
| python-docx| A Python library to handle word document                                    |
| docx2pdf   | A Python library to convert word document files to PDF.                     |
| argparse   | A Python library to write user-friendly command-line interfaces.            |
| time       | A Python library to provide access to time-related functions.               |

## Prerequisite
Below is a method to extract the raw MFT file for analysis by the tool. There may be other alternatives to extracting the raw file.
1. Using a linux terminal, find the correct offset using [mmls](http://www.sleuthkit.org/sleuthkit/man/mmls.html):

	```sh
	mmls <dd image>
	```

2. Extract raw MFT file:

	```sh
	icat -o <offset> <dd image> 0 > mft.raw
	```
## Usage
With the raw MFT file, parse it to the tool for analysis.

1. Navigate to project folder in command prompt or pycharm terminal.

2. Run the MFT Analyser with the raw MFT file (in Windows OS): 

	```sh
	python 2202_teameggfriedrice_mft_final.py -f <raw MFT file>
	``` 

## Authors
- Javier Lim [@javvylx](https://github.com/javvylx)
- Tay Kai Keng [@TayKK](https://github.com/TayKK)
- Jerry Tan Fu Wei [@Jerry19968](https://github.com/Jerry19968)
- Chin Bing Hong [@CB-Hong](https://github.com/CB-Hong)
- Claudia Chan [@x3Kuro](https://github.com/x3Kuro)
