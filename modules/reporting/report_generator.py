from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(filename, title, findings):
    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = [
        Paragraph(title, styles["Title"]),
        Spacer(1, 12)
    ]

    for finding in findings:
        content.append(
            Paragraph(f"• {finding}", styles["BodyText"])
        )

    doc.build(content)

    return filename