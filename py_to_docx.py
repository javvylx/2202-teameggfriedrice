# First criteria, is to enter pip install python-docx

# Python-docx guide: https://python-docx.readthedocs.io/en/latest/

from docx import Document
from docx.shared import Inches, Pt
from docx.section import _Header
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
document = Document()

header = document.sections[0].header

# document.add_picture('./images/SIT_logo.png', width=Inches(1.2))

htable=header.add_table(1, 2, Inches(6))
htab_cells=htable.rows[0].cells
ht0=htab_cells[0].add_paragraph()
kh=ht0.add_run()
kh.add_picture('./images/SIT_logo.png', width=Inches(0.8))
ht1=htab_cells[1].add_paragraph('Singapore Institute of Technology')
ht1.alignment = WD_PARAGRAPH_ALIGNMENT.RIGHT

penis = document.add_heading('Digital Forensic Report', 0)
penis.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

p = document.add_paragraph('This is a Forensic Report')
# p.add_run('bold').bold = True
# p.add_run(' and some ')
# p.add_run('italic.').italic = True

document.add_heading('Company Name', level=1)
document.add_paragraph('Company Address', style='Intense Quote')

# document.add_paragraph(
#     'first item in unordered list', style='List Bullet'
# )
# document.add_paragraph(
#     'first item in ordered list', style='List Number'
# )


# Table Records 1 row, 5 columns
records = (
    (1, '2202', 'DF'),
    (2, '2204', 'EH'),
    (3, '2201', 'SE'),
    (4, '2203', 'NS'),
    (5, '2901', 'CPD1'),
)

table = document.add_table(rows=1, cols=5)
hdr_cells = table.rows[0].cells
hdr_cells[0].text = 'Num'
hdr_cells[1].text = 'Module Code'
hdr_cells[2].text = 'Module Name'


for num, modC, modN in records:
    row_cells = table.add_row().cells
    row_cells[0].text = str(num)
    row_cells[1].text = modC
    row_cells[2].text = modN

document.add_page_break() # Add New Page

document.save('./output/poc.docx')