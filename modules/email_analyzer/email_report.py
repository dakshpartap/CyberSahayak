# modules/email_analyzer/email_report.py
# Generate JSON reports, PDF reports, and evidence export packages
# for email intelligence analysis results.

import io
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── PDF generation (reportlab) ──────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    _REPORTLAB_OK = True
except ImportError:
    _REPORTLAB_OK = False

# Color palette matching CyberSahayak design system
COL_ACCENT = HexColor('#2563EB') if _REPORTLAB_OK else None
COL_RED = HexColor('#EF4444') if _REPORTLAB_OK else None
COL_AMBER = HexColor('#F59E0B') if _REPORTLAB_OK else None
COL_ORANGE = HexColor('#F97316') if _REPORTLAB_OK else None
COL_GREEN = HexColor('#10B981') if _REPORTLAB_OK else None
COL_MUTED = HexColor('#94A3B8') if _REPORTLAB_OK else None


def _risk_color(score: int):
    if not _REPORTLAB_OK:
        return None
    if score >= 75:
        return COL_RED
    elif score >= 50:
        return COL_ORANGE
    elif score >= 25:
        return COL_AMBER
    return COL_GREEN


def build_json_report(analysis: dict, source_info: dict = None) -> str:
    """
    Build a clean, serializable JSON report from analysis results.
    Returns a JSON string ready for download.
    """
    source_info = source_info or {}

    report = {
        "report_type": "CyberSahayak Email Intelligence Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_info,
        "summary": {
            "verdict": analysis.get("verdict", "Unknown"),
            "risk_score": analysis.get("final_score", 0),
            "total_findings": analysis.get("total_findings", 0),
            "critical_findings": analysis.get("critical_count", 0),
            "high_findings": analysis.get("high_count", 0),
            "medium_findings": analysis.get("medium_count", 0),
        },
        "sender": {
            "from_address": analysis.get("from", {}).get("email", ""),
            "display_name": analysis.get("from", {}).get("display_name", ""),
            "domain": analysis.get("from", {}).get("domain", ""),
        },
        "authentication": {
            "spf": analysis.get("spf_label", "Unknown"),
            "dkim": analysis.get("dkim_label", "Unknown"),
            "dmarc": analysis.get("dmarc_label", "Unknown"),
        },
        "metadata": analysis.get("metadata", {}),
        "indicators": {
            "urls_found": analysis.get("urls", []),
            "url_count": analysis.get("url_count", 0),
            "attachments": [
                {
                    "filename": a.get("filename", ""),
                    "content_type": a.get("content_type", ""),
                    "size_bytes": a.get("size_bytes", 0),
                }
                for a in analysis.get("attachments", [])
            ],
            "attachment_count": analysis.get("attachment_count", 0),
        },
        "findings": [
            {
                "category": f.get("category", ""),
                "severity": f.get("severity", ""),
                "description": f.get("description", ""),
            }
            for f in analysis.get("all_findings", [])
        ],
        "base64_analysis": _summarize_base64(
            analysis.get("component_results", {}).get("base64", {})
        ),
        "recommendations": analysis.get("recommendations", []),
        "errors": analysis.get("errors", []),
        "disclaimer": (
            "This automated analysis is provided for preliminary risk assessment only. "
            "It does not constitute legal or forensic certification. For active fraud, "
            "call the National Cyber Crime Helpline 1930 or visit cybercrime.gov.in."
        ),
    }

    return json.dumps(report, indent=2, default=str, ensure_ascii=False)


def _summarize_base64(base64_component: dict) -> dict:
    """Compact summary of base64 findings for the JSON report."""
    items = base64_component.get("decoded_items", [])
    return {
        "candidates_found": base64_component.get("candidates_found", 0),
        "successfully_decoded": base64_component.get("successfully_decoded", 0),
        "has_hidden_payload": base64_component.get("has_hidden_payload", False),
        "decoded_summaries": [
            {
                "detected_type": item.get("detected_type", ""),
                "contains_url": item.get("contains_url", False),
                "contains_script": item.get("contains_script", False),
                "contains_html": item.get("contains_html", False),
                "is_executable": item.get("is_executable", False),
                "risk_score": item.get("item_risk_score", 0),
            }
            for item in items[:10]
        ],
    }


def generate_pdf_report(analysis: dict, source_info: dict = None, case_id: str = "") -> bytes:
    """
    Generate a formatted A4 PDF report for an email intelligence analysis.
    Returns PDF bytes suitable for st.download_button.
    Raises RuntimeError if reportlab is unavailable.
    """
    if not _REPORTLAB_OK:
        raise RuntimeError("reportlab is not installed — PDF generation unavailable")

    source_info = source_info or {}
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"CyberSahayak Email Intelligence Report — {case_id or 'Unknown'}",
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'Title', parent=styles['Title'],
        fontSize=20, textColor=COL_ACCENT, spaceAfter=6, alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', parent=styles['Normal'],
        fontSize=10, textColor=COL_MUTED, spaceAfter=16, alignment=TA_CENTER,
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Heading2'],
        fontSize=13, textColor=COL_ACCENT, spaceBefore=14, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontSize=9.5, textColor=black, spaceAfter=4,
    )
    footer_style = ParagraphStyle(
        'Footer', parent=styles['Normal'],
        fontSize=8.5, textColor=COL_MUTED, alignment=TA_CENTER,
    )

    score = analysis.get("final_score", 0)
    verdict = analysis.get("verdict", "Unknown")

    # ── Header ───────────────────────────────────────────────────────────
    story.append(Paragraph("🛡️ CyberSahayak Email Intelligence Report", title_style))
    story.append(Paragraph("Automated Phishing & Authentication Analysis", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=COL_ACCENT))
    story.append(Spacer(1, 0.4 * cm))

    # ── Summary Table ────────────────────────────────────────────────────
    story.append(Paragraph("Analysis Summary", h2_style))
    summary_data = [
        ['Case ID', case_id or 'N/A'],
        ['Generated', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')],
        ['Sender Email', analysis.get("from", {}).get("email", "Unknown")],
        ['Sender Domain', analysis.get("from", {}).get("domain", "Unknown")],
        ['Risk Score', f"{score}/100"],
        ['Verdict', verdict],
        ['Total Findings', str(analysis.get("total_findings", 0))],
    ]
    t = Table(summary_data, colWidths=[5 * cm, 12 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#E8F0FE')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [white, HexColor('#F8FAFC')]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (1, 5), (1, 5), _risk_color(score)),
        ('FONTNAME', (1, 5), (1, 5), 'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # ── Authentication Results ──────────────────────────────────────────
    story.append(Paragraph("Authentication Checks (SPF / DKIM / DMARC)", h2_style))
    auth_data = [
        ['Check', 'Result'],
        ['SPF', analysis.get("spf_label", "Unknown")],
        ['DKIM', analysis.get("dkim_label", "Unknown")],
        ['DMARC', analysis.get("dmarc_label", "Unknown")],
    ]
    t2 = Table(auth_data, colWidths=[5 * cm, 12 * cm])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F8FAFC')]),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t2)
    story.append(Spacer(1, 0.4 * cm))

    # ── Findings ─────────────────────────────────────────────────────────
    findings = analysis.get("all_findings", [])
    if findings:
        story.append(Paragraph(f"Detailed Findings ({len(findings)})", h2_style))
        for f in findings[:30]:
            sev = f.get("severity", "INFO")
            color = {
                "CRITICAL": COL_RED, "HIGH": COL_ORANGE,
                "MEDIUM": COL_AMBER, "LOW": COL_GREEN,
            }.get(sev, COL_MUTED)
            color_hex = color.hexval() if color else "#666666"
            finding_style = ParagraphStyle(
                'Finding', parent=body_style, textColor=black,
            )
            category_text = f.get('category', '')
            description_text = f.get('description', '')
            story.append(Paragraph(
                f"<b><font color='{color_hex}'>[{sev}]</font></b> "
                f"<b>{category_text}:</b> {description_text}",
                finding_style,
            ))
        story.append(Spacer(1, 0.3 * cm))

    # ── URLs ─────────────────────────────────────────────────────────────
    urls = analysis.get("urls", [])
    if urls:
        story.append(Paragraph(f"URLs Found ({len(urls)})", h2_style))
        for url in urls[:20]:
            story.append(Paragraph(f"• {url[:120]}", body_style))
        story.append(Spacer(1, 0.3 * cm))

    # ── Attachments ──────────────────────────────────────────────────────
    attachments = analysis.get("attachments", [])
    if attachments:
        story.append(Paragraph(f"Attachments ({len(attachments)})", h2_style))
        att_data = [['Filename', 'Type', 'Size']]
        for a in attachments[:15]:
            att_data.append([
                str(a.get("filename", ""))[:50],
                str(a.get("content_type", ""))[:30],
                f"{a.get('size_bytes', 0):,} bytes",
            ])
        t3 = Table(att_data, colWidths=[7 * cm, 6 * cm, 4 * cm])
        t3.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1E293B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#F8FAFC')]),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t3)
        story.append(Spacer(1, 0.3 * cm))

    # ── Recommendations ──────────────────────────────────────────────────
    recs = analysis.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommendations", h2_style))
        for r in recs:
            story.append(Paragraph(f"• {r}", body_style))

    # ── Footer ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=COL_MUTED))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Emergency: Call <b>1930</b> (National Cyber Crime Helpline) | Report: <b>cybercrime.gov.in</b>",
        footer_style,
    ))
    story.append(Paragraph(
        "Generated by CyberSahayak v2.0 Email Intelligence Module. "
        "This is an automated preliminary assessment, not a forensic certification.",
        footer_style,
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def build_evidence_package(analysis: dict, raw_email_text: str, source_info: dict = None) -> dict:
    """
    Build a complete evidence package combining the JSON report and raw
    original content — suitable for attaching to a cybercrime.gov.in complaint
    or for the Evidence Builder module.
    """
    return {
        "evidence_type": "email_intelligence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_report": json.loads(build_json_report(analysis, source_info)),
        "raw_content_preview": (raw_email_text or "")[:5000],
        "raw_content_length": len(raw_email_text or ""),
    }


def pdf_available() -> bool:
    """Check if PDF generation is available."""
    return _REPORTLAB_OK
