# core/audit_logger.py — SQLite-backed audit log for all scans
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from config import settings

DB_PATH = str(settings.AUDIT_DB)

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT,
            type       TEXT NOT NULL,
            target     TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            verdict    TEXT NOT NULL DEFAULT 'Unknown',
            details    TEXT,
            timestamp  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_case ON scans(case_id)
    """)
    conn.commit()
    conn.close()

def log_scan(
    scan_type: str,
    target: str,
    risk_score: int,
    verdict: str,
    details: dict = None,
    case_id: str = None
):
    """
    Persist a scan result to the audit log.

    Args:
        scan_type: 'url', 'sms', 'image', 'document', 'upi', 'whatsapp', 'digital_arrest'
        target: The scanned item (URL, truncated SMS, filename, etc.)
        risk_score: 0–100
        verdict: Human-readable verdict string
        details: Full result dict (stored as JSON)
        case_id: Optional investigation case ID
    """
    init_db()
    conn = _get_conn()
    conn.execute(
        """INSERT INTO scans (case_id, type, target, risk_score, verdict, details, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            scan_type,
            target[:500],
            int(risk_score),
            verdict,
            json.dumps(details or {}, default=str),
            datetime.now(timezone.utc).isoformat()
        )
    )
    conn.commit()
    conn.close()

def get_recent_scans(limit: int = 20, scan_type: str = None, case_id: str = None) -> list[dict]:
    """Return the most recent scans, optionally filtered by type or case."""
    init_db()
    conn = _get_conn()
    query = "SELECT * FROM scans"
    params = []
    conditions = []

    if scan_type:
        conditions.append("type = ?")
        params.append(scan_type)
    if case_id:
        conditions.append("case_id = ?")
        params.append(case_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats() -> dict:
    """Aggregate statistics for the SOC dashboard."""
    init_db()
    conn = _get_conn()

    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()

    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    today = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE timestamp >= ?", (today_start,)
    ).fetchone()[0]
    threats = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_score >= ?", (settings.HIGH_RISK_THRESHOLD,)
    ).fetchone()[0]
    urls = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE type = 'url'"
    ).fetchone()[0]
    sms = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE type IN ('sms', 'whatsapp')"
    ).fetchone()[0]
    cases = conn.execute(
        "SELECT COUNT(DISTINCT case_id) FROM scans WHERE case_id IS NOT NULL"
    ).fetchone()[0]

    conn.close()
    return {
        'total_scans': total,
        'scans_today': today,
        'threats_detected': threats,
        'urls_scanned': urls,
        'sms_scanned': sms,
        'cases_opened': cases,
    }

def get_timeline_data(hours: int = 24) -> list[dict]:
    """Return hourly scan counts and avg risk for charting."""
    init_db()
    conn = _get_conn()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    rows = conn.execute("""
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
            COUNT(*) AS scan_count,
            AVG(risk_score) AS avg_risk,
            SUM(CASE WHEN risk_score >= 75 THEN 1 ELSE 0 END) AS high_risk_count
        FROM scans
        WHERE timestamp >= ?
        GROUP BY hour
        ORDER BY hour ASC
    """, (since,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_threat_category_breakdown() -> dict:
    """Return counts per scan type for the donut chart."""
    init_db()
    conn = _get_conn()
    rows = conn.execute("""
        SELECT type, COUNT(*) as cnt
        FROM scans
        WHERE risk_score >= 45
        GROUP BY type
        ORDER BY cnt DESC
    """).fetchall()
    conn.close()
    return {r['type']: r['cnt'] for r in rows}

def get_scans_for_case(case_id: str) -> list[dict]:
    """All scans belonging to a specific investigation case."""
    return get_recent_scans(limit=500, case_id=case_id)