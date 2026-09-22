# -*- coding: utf-8 -*-
"""
Builds Task1_AI_ML_Concept_Analysis.pdf from content.py
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
)

import content as c

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleCustom", fontSize=18, leading=22, spaceAfter=6,
                           fontName="Helvetica-Bold", textColor=colors.HexColor("#1a2b4c")))
styles.add(ParagraphStyle(name="Subtitle", fontSize=10, leading=13, spaceAfter=18,
                           textColor=colors.HexColor("#555555")))
styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16, spaceBefore=14, spaceAfter=6,
                           fontName="Helvetica-Bold", textColor=colors.HexColor("#1a2b4c")))
styles.add(ParagraphStyle(name="Body", fontSize=10.2, leading=15, spaceAfter=8,
                           alignment=4))  # justify
styles.add(ParagraphStyle(name="BulletBody", fontSize=10.2, leading=14, spaceAfter=4))
styles.add(ParagraphStyle(name="RefBody", fontSize=9, leading=12, spaceAfter=4,
                           textColor=colors.HexColor("#333333")))
styles.add(ParagraphStyle(name="TableCell", fontSize=8.6, leading=11))
styles.add(ParagraphStyle(name="TableHeader", fontSize=9, leading=11, textColor=colors.white,
                           fontName="Helvetica-Bold"))

story = []
story.append(Paragraph(c.TITLE, styles["TitleCustom"]))
story.append(Paragraph(c.SUBTITLE, styles["Subtitle"]))

story.append(Paragraph(c.INTRO, styles["Body"]))

story.append(Paragraph("1. Log Analysis", styles["H2"]))
story.append(Paragraph(c.USE_CASE_LOG_ANALYSIS, styles["Body"]))

story.append(Paragraph("2. Threat Intelligence Summarization", styles["H2"]))
story.append(Paragraph(c.USE_CASE_THREAT_INTEL, styles["Body"]))

story.append(Paragraph("3. Alert Triage", styles["H2"]))
story.append(Paragraph(c.USE_CASE_ALERT_TRIAGE, styles["Body"]))

story.append(Paragraph("Comparison Table", styles["H2"]))
table_data = [[Paragraph(f"<b>{h}</b>", styles["TableHeader"]) for h in c.COMPARISON_TABLE_HEADER]]
for row in c.COMPARISON_TABLE_ROWS:
    table_data.append([Paragraph(cell.replace("\n", "<br/>"), styles["TableCell"]) for cell in row])

col_widths = [1.05*inch, 1.75*inch, 1.85*inch, 1.85*inch]
tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
tbl.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2b4c")),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f8")]),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
]))
story.append(tbl)

story.append(Paragraph(c.SAFE_AI_HEADER, styles["H2"]))
story.append(Paragraph(c.SAFE_AI_INTRO, styles["Body"]))
bullet_items = []
for label, text in c.SAFE_AI_BULLETS:
    bullet_items.append(ListItem(Paragraph(f"<b>{label}:</b> {text}", styles["BulletBody"]),
                                  bulletColor=colors.HexColor("#1a2b4c")))
story.append(ListFlowable(bullet_items, bulletType="bullet", leftIndent=16, spaceAfter=8))

story.append(Paragraph("Conclusion", styles["H2"]))
story.append(Paragraph(c.CONCLUSION, styles["Body"]))

story.append(Paragraph(c.REFERENCES_HEADER, styles["H2"]))
for i, ref in enumerate(c.REFERENCES, start=1):
    story.append(Paragraph(f"[{i}] {ref}", styles["RefBody"]))

doc = SimpleDocTemplate(
    "Task1_AI_ML_Concept_Analysis.pdf",
    pagesize=letter,
    topMargin=0.75*inch, bottomMargin=0.75*inch,
    leftMargin=0.75*inch, rightMargin=0.75*inch,
    title="AI/ML Concept Analysis - Task 1",
)
doc.build(story)
print("PDF built.")

# Word count check (body text only, excludes table/refs/title)
body_text = " ".join([
    c.INTRO, c.USE_CASE_LOG_ANALYSIS, c.USE_CASE_THREAT_INTEL, c.USE_CASE_ALERT_TRIAGE,
    c.SAFE_AI_INTRO, " ".join(f"{l} {t}" for l, t in c.SAFE_AI_BULLETS), c.CONCLUSION
])
print("Word count:", len(body_text.split()))
