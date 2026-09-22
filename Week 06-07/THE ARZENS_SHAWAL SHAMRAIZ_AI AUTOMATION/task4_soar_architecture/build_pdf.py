# -*- coding: utf-8 -*-
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)

import content as c

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleCustom", fontSize=18, leading=22, spaceAfter=6,
                           fontName="Helvetica-Bold", textColor=colors.HexColor("#1a2b4c")))
styles.add(ParagraphStyle(name="Subtitle", fontSize=10, leading=13, spaceAfter=18,
                           textColor=colors.HexColor("#555555")))
styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16, spaceBefore=14, spaceAfter=6,
                           fontName="Helvetica-Bold", textColor=colors.HexColor("#1a2b4c")))
styles.add(ParagraphStyle(name="Body", fontSize=10.2, leading=15, spaceAfter=8, alignment=4))
styles.add(ParagraphStyle(name="Caption", fontSize=9, leading=12, alignment=1,
                           textColor=colors.HexColor("#555555"), spaceAfter=10))
styles.add(ParagraphStyle(name="TableCell", fontSize=8.8, leading=12))
styles.add(ParagraphStyle(name="TableHeader", fontSize=9.2, leading=12, textColor=colors.white,
                           fontName="Helvetica-Bold"))

story = []
story.append(Paragraph(c.TITLE, styles["TitleCustom"]))
story.append(Paragraph(c.SUBTITLE, styles["Subtitle"]))
story.append(Paragraph(c.OVERVIEW, styles["Body"]))

for heading, text in c.SECTIONS:
    story.append(Paragraph(heading, styles["H2"]))
    story.append(Paragraph(text, styles["Body"]))

story.append(PageBreak())
story.append(Image("workflow_diagram.png", width=6.6*inch, height=6.6*inch*1478/2188))
story.append(Paragraph(c.DIAGRAM_CAPTION, styles["Caption"]))

story.append(Paragraph(c.SAFETY_HEADER, styles["H2"]))
table_data = [[Paragraph("<b>Control</b>", styles["TableHeader"]),
               Paragraph("<b>Description</b>", styles["TableHeader"])]]
for label, desc in c.SAFETY_ROWS:
    table_data.append([Paragraph(f"<b>{label}</b>", styles["TableCell"]),
                        Paragraph(desc, styles["TableCell"])])
tbl = Table(table_data, colWidths=[1.3*inch, 5.2*inch], repeatRows=1)
tbl.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2b4c")),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f8")]),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
]))
story.append(tbl)

story.append(Paragraph(c.AUDIT_HEADER, styles["H2"]))
story.append(Paragraph(c.AUDIT_TEXT, styles["Body"]))

doc = SimpleDocTemplate(
    "Task4_SOAR_Architecture_Design.pdf",
    pagesize=letter,
    topMargin=0.75*inch, bottomMargin=0.75*inch,
    leftMargin=0.75*inch, rightMargin=0.75*inch,
    title="SOAR Architecture Design - Task 4",
)
doc.build(story)
print("PDF built.")
