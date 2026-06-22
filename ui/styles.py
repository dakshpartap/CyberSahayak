# ui/styles.py — Global CSS for CyberSahayak 2.0
# ── CyberSahayak Color Palette ──────────────────────────────

CYBER_PALETTE = {
    # Backgrounds
    "bg_primary": "#060D1A",
    "bg_secondary": "#0A1428",
    "bg_card": "#0F1629",

    # Borders
    "border": "#1E293B",

    # Text
    "text_primary": "#F1F5F9",
    "text_secondary": "#CBD5E1",
    "text_muted": "#94A3B8",

    # Brand
    "primary": "#2563EB",
    "secondary": "#3B82F6",

    # Accent colors used by charts.py
    "accent_blue": "#2563EB",
    "accent_red": "#EF4444",
    "accent_amber": "#F59E0B",
    "accent_cyan": "#06B6D4",
    "accent_green": "#22C55E",

    # Risk colors
    "safe": "#22C55E",
    "low": "#10B981",
    "medium": "#EAB308",
    "warning": "#F59E0B",
    "high": "#F97316",
    "danger": "#EF4444",
    "critical": "#DC2626",

    # Compatibility aliases
    "surface": "#0F1629",
    "background": "#060D1A",
    "sidebar": "#0A1428",
    "text": "#F1F5F9",
    "muted": "#94A3B8",
}
GLOBAL_CSS = """
<style>
/* ── Reset & Base ──────────────────────────────────────────── */
[data-testid="stAppViewContainer"] {
    background: #060D1A;
    color: #F1F5F9;
}
[data-testid="stSidebar"] {
    background: #0A1428 !important;
    border-right: 1px solid #1E293B;
}
[data-testid="stHeader"] {
    background: transparent;
}

/* ── Typography ─────────────────────────────────────────────── */
h1, h2, h3, h4 {
    color: #F1F5F9 !important;
    font-family: 'Inter', 'Segoe UI', sans-serif;
    font-weight: 700;
}
p, span, label, div {
    color: #CBD5E1;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}

/* ── Section Header ─────────────────────────────────────────── */
.section-header {
    font-size: 1.4rem;
    font-weight: 700;
    color: #F1F5F9;
    padding: 0.6rem 0 1rem 0;
    border-bottom: 2px solid #2563EB;
    margin-bottom: 1.2rem;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}

/* ── Metric Cards ───────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #0F1629 !important;
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
    padding: 16px !important;
}
[data-testid="stMetricValue"] {
    color: #2563EB !important;
    font-size: 1.8rem !important;
    font-weight: 800 !important;
}
[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
    font-size: 0.8rem !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
[data-testid="stMetricDelta"] {
    font-size: 0.8rem !important;
}

/* ── Buttons ────────────────────────────────────────────────── */
.stButton > button {
    background: #1E3A8A !important;
    color: #F1F5F9 !important;
    border: 1px solid #2563EB !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-family: 'Inter', sans-serif !important;
    transition: all 0.2s ease;
    padding: 0.5rem 1rem !important;
}
.stButton > button:hover {
    background: #2563EB !important;
    border-color: #3B82F6 !important;
    box-shadow: 0 0 12px rgba(37, 99, 235, 0.4) !important;
    transform: translateY(-1px);
}
.stButton > button:active {
    transform: translateY(0);
}

/* ── Primary action button ──────────────────────────────────── */
.stButton > button[kind="primary"] {
    background: #2563EB !important;
    color: #FFFFFF !important;
}

/* ── Input Fields ───────────────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #0F1629 !important;
    border: 1px solid #334155 !important;
    color: #F1F5F9 !important;
    border-radius: 8px !important;
    font-family: 'Inter', sans-serif !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #2563EB !important;
    box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2) !important;
}

/* ── Select boxes ───────────────────────────────────────────── */
.stSelectbox > div > div {
    background: #0F1629 !important;
    border: 1px solid #334155 !important;
    color: #F1F5F9 !important;
    border-radius: 8px !important;
}

/* ── File uploader ──────────────────────────────────────────── */
[data-testid="stFileUploader"] {
    background: #0F1629 !important;
    border: 2px dashed #334155 !important;
    border-radius: 12px !important;
    padding: 1rem !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: #2563EB !important;
}

/* ── Expander ───────────────────────────────────────────────── */
.streamlit-expanderHeader {
    background: #0F1629 !important;
    border: 1px solid #1E293B !important;
    border-radius: 8px !important;
    color: #F1F5F9 !important;
    font-weight: 600 !important;
}
.streamlit-expanderContent {
    background: #060D1A !important;
    border: 1px solid #1E293B !important;
    border-top: none !important;
}

/* ── Alerts / Messages ──────────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 8px !important;
    border-left-width: 4px !important;
}

/* ── Tabs ───────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: #0A1428 !important;
    border-bottom: 1px solid #1E293B !important;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #94A3B8 !important;
    border-radius: 6px 6px 0 0 !important;
    padding: 8px 16px !important;
    font-weight: 500 !important;
}
.stTabs [aria-selected="true"] {
    background: #1E3A8A !important;
    color: #F1F5F9 !important;
    border-bottom: 2px solid #2563EB !important;
}

/* ── DataFrames ─────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    background: #0F1629 !important;
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
}
.stDataFrame table {
    background: #0F1629 !important;
    color: #F1F5F9 !important;
}
.stDataFrame th {
    background: #1E293B !important;
    color: #94A3B8 !important;
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.stDataFrame td {
    border-color: #1E293B !important;
    font-size: 0.85rem !important;
}

/* ── Progress bar ───────────────────────────────────────────── */
.stProgress > div > div {
    background: #1E293B !important;
    border-radius: 999px !important;
}
.stProgress > div > div > div {
    background: linear-gradient(90deg, #2563EB, #3B82F6) !important;
    border-radius: 999px !important;
}

/* ── Divider ────────────────────────────────────────────────── */
hr {
    border-color: #1E293B !important;
    margin: 1.5rem 0 !important;
}

/* ── Sidebar elements ───────────────────────────────────────── */
[data-testid="stSidebar"] .stButton > button {
    background: #1E293B !important;
    border-color: #334155 !important;
    width: 100% !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background: #2563EB !important;
    border-color: #2563EB !important;
}

/* ── Chat messages ──────────────────────────────────────────── */
[data-testid="stChatMessage"] {
    background: #0F1629 !important;
    border: 1px solid #1E293B !important;
    border-radius: 12px !important;
    padding: 12px 16px !important;
    margin: 6px 0 !important;
}
[data-testid="stChatInput"] > div {
    background: #0F1629 !important;
    border: 1px solid #334155 !important;
    border-radius: 12px !important;
}
[data-testid="stChatInput"] textarea {
    color: #F1F5F9 !important;
}

/* ── Risk score badges ──────────────────────────────────────── */
.risk-critical { color: #EF4444; font-weight: 800; }
.risk-high     { color: #F97316; font-weight: 700; }
.risk-medium   { color: #EAB308; font-weight: 700; }
.risk-low      { color: #22C55E; font-weight: 600; }
.risk-safe     { color: #10B981; font-weight: 600; }

/* ── Verdict badges ─────────────────────────────────────────── */
.verdict-box {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.9rem;
    letter-spacing: 0.03em;
}
.verdict-danger  { background: rgba(239,68,68,0.15); color: #EF4444; border: 1px solid #EF4444; }
.verdict-warning { background: rgba(234,179,8,0.15);  color: #EAB308; border: 1px solid #EAB308; }
.verdict-safe    { background: rgba(16,185,129,0.15); color: #10B981; border: 1px solid #10B981; }

/* ── Scrollbar ──────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #060D1A; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #2563EB; }

/* ── Spinner ────────────────────────────────────────────────── */
.stSpinner > div {
    border-color: #2563EB transparent transparent transparent !important;
}

/* ── Code blocks ────────────────────────────────────────────── */
code, pre {
    background: #0F1629 !important;
    color: #7DD3FC !important;
    border: 1px solid #1E293B !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
}

/* ── Tooltip ────────────────────────────────────────────────── */
[data-baseweb="tooltip"] {
    background: #1E293B !important;
    color: #F1F5F9 !important;
    border: 1px solid #334155 !important;
    border-radius: 6px !important;
}

/* ── Checkbox / Radio ───────────────────────────────────────── */
.stCheckbox label, .stRadio label {
    color: #CBD5E1 !important;
}

/* ── Hide Streamlit branding ────────────────────────────────── */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
[data-testid="stDecoration"] { display: none; }
</style>
"""