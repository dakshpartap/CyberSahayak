# modules/evidence/pdf_report.py — Generate a PDF investigation report
import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Color palette matching CYBER_PALETTE
COL_BG = HexColor('#0A0E1A')
COL_ACCENT = HexColor('#2563EB')
COL_RED = HexColor('#EF4444')
COL_AMBER = HexColor('#F59E0B')
COL_GREEN = HexColor('#10B981')
COL_TEXT = HexColor('#F1F5F9')
COL_MUTED = HexColor('#94A3B8')
COL_CARD = HexColor('#131D35')


def _risk_color(score: int) -> HexColor:
    if score >= 75:
        return COL_RED
    elif score >= 45:
        return COL_AMBER
    elif score >= 20:
        return HexColor('#F97316')
    return COL_GREEN


def generate_pdf_report(session_data: dict) -> bytes:
    """
    Generate a formatted A4 PDF investigation report from session data.
    Returns PDF bytes suitable for st.download_button.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"CyberSahayak Report — {session_data.get('case_id', 'Unknown')}"
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Styles ────────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        'Title', parent=styles['Title'],
        fontSize=22, textColor=COL_ACCENT, spaceAfter=6, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', parent=styles['Normal'],
        fontSize=11, textColor=COL_MUTED, spaceAfter=20, alignment=TA_CENTER
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Heading2'],
        fontSize=13, textColor=COL_ACCENT, spaceBefore=16, spaceAfter=6
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontSize=10, textColor=black, spaceAfter=4
    )
    mono_style = ParagraphStyle(
        'Mono', parent=styles['Code'],
        fontSize=8, textColor=black, spaceAfter=4
    )

    # ── Header ────────────────────────────────────────────────────────
    story.append(Paragraph("🛡️ CyberSahayak Investigation Report", title_style))
    story.append(Paragraph("AI-Powered Cybercrime Analysis Platform", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=COL_ACCENT))
    story.append(Spacer(1, 0.4 * cm))

    # ── Case Summary Table ────────────────────────────────────────────
    case_id = session_data.get('case_id', 'N/A')
    created = session_data.get('created_at', datetime.now(timezone.utc).isoformat())
    crime_type = session_data.get('crime_type', 'Not specified')
    overall_risk = session_data.get('overall_risk', 0)
    conclusion = session_data.get('conclusion', 'Investigation ongoing')

    story.append(Paragraph("Case Summary", h2_style))

    summary_data = [
        ['Case ID', case_id],
        ['Date / Time', created[:19].replace('T', ' ') + ' UTC'],
        ['Crime Type', crime_type],
        ['Overall Risk Score', f"{overall_risk}/100"],
        ['Conclusion', conclusion or 'Investigation ongoing'],
    ]

    summary_table = Table(summary_data, colWidths=[5 * cm, 12 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#E8F0FE')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [white, HexColor('#F8FAFC')]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (1, 3), (1, 3), _risk_color(overall_risk)),
        ('FONTNAME', (1, 3), (1, 3), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── URL Scans ─────────────────────────────────────────────────────
    url_scans = session_data.get('scanned_urls', [])
    if url_scans:
        story.append(Paragraph(f"URL Scan Results ({len(url_scans)} URLs)", h2_style))
        for entry in url_scans[:20]:
            url = entry.get('url', 'N/A')
            res = entry.get('result', {})
            score = res.get('risk_score', 0)
            verdict = res.get('verdict', 'Unknown')
            findings = res.get('findings', [])

            url_data = [
                ['URL', url[:80] + ('...' if len(url) > 80 else '')],
                ['Risk Score', f"{score}/100"],
                ['Verdict', verdict],
            ]
            if findings:
                url_data.append(['Findings', '\n'.join(f'• {f}' for f in findings[:5])])

            t = Table(url_data, colWidths=[4 * cm, 13 * cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#E8F0FE')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [white, HexColor('#F8FAFC')]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('TEXTCOLOR', (1, 1), (1, 1), _risk_color(score)),
                ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
            ]))
            story.append(KeepTogether([t, Spacer(1, 0.2 * cm)]))

    # ── SMS Scans ─────────────────────────────────────────────────────
    sms_scans = session_data.get('scanned_messages', [])
    if sms_scans:
        story.append(Paragraph(f"Message Scan Results ({len(sms_scans)} messages)", h2_style))
        for entry in sms_scans[:20]:
            msg = entry.get('message', 'N/A')
            res = entry.get('result', {})
            score = res.get('risk_score', 0)

            msg_data = [
                ['Message', (msg[:120] + '...') if len(msg) > 120 else msg],
                ['Risk Score', f"{score}/100"],
                ['Flags', ', '.join(res.get('flags', res.get('matched_categories', ['None'])))],
            ]
            t = Table(msg_data, colWidths=[4 * cm, 13 * cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#E8F0FE')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [white, HexColor('#F8FAFC')]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('TEXTCOLOR', (1, 1), (1, 1), _risk_color(score)),
                ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
            ]))
            story.append(KeepTogether([t, Spacer(1, 0.2 * cm)]))

    # ── Recommended Actions ───────────────────────────────────────────
    actions = session_data.get('recommended_actions', [])
    if actions:
        story.append(Paragraph("Recommended Actions", h2_style))
        for action in actions:
            story.append(Paragraph(f"• {action}", body_style))

    # ── Legal Footer ──────────────────────────────────────────────────
    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=COL_MUTED))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Emergency: Call <b>1930</b> (National Cyber Crime Helpline) | "
        "Report: <b>cybercrime.gov.in</b>",
        ParagraphStyle('Footer', parent=styles['Normal'],
                       fontSize=9, textColor=COL_MUTED, alignment=TA_CENTER)
    ))
    story.append(Paragraph(
        "Generated by CyberSahayak v2.0 — For official use, attach original evidence screenshots.",
        ParagraphStyle('Footer2', parent=styles['Normal'],
                       fontSize=8, textColor=COL_MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()