# ui/charts.py — Plotly chart builders for the SOC dashboard
import plotly.graph_objects as go
import plotly.express as px
from ui.styles import CYBER_PALETTE

BG = CYBER_PALETTE['bg_primary']
CARD_BG = CYBER_PALETTE['bg_card']
GRID_COLOR = CYBER_PALETTE['border']
TEXT_COLOR = CYBER_PALETTE['text_secondary']

BASE_LAYOUT = dict(
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(0,0,0,0)',
    font=dict(color=TEXT_COLOR, family='Inter, sans-serif'),
    margin=dict(l=20, r=20, t=30, b=20),
    xaxis=dict(gridcolor=GRID_COLOR, showgrid=True, zeroline=False),
    yaxis=dict(gridcolor=GRID_COLOR, showgrid=True, zeroline=False),
)


def threat_timeline_chart(timeline_data: list[dict]) -> go.Figure:
    """
    Line/area chart showing scan volume and threat count over time.
    timeline_data: list of {hour, scan_count, avg_risk, high_risk_count}
    """
    if not timeline_data:
        fig = go.Figure()
        fig.update_layout(**BASE_LAYOUT, title='No data yet')
        return fig

    hours = [row['hour'] for row in timeline_data]
    scans = [row['scan_count'] for row in timeline_data]
    high_risk = [row['high_risk_count'] for row in timeline_data]
    avg_risk = [round(row['avg_risk'] or 0, 1) for row in timeline_data]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=hours, y=scans,
        mode='lines+markers',
        name='Total Scans',
        line=dict(color=CYBER_PALETTE['accent_blue'], width=2),
        fill='tozeroy',
        fillcolor='rgba(37, 99, 235, 0.08)',
        hovertemplate='%{x}<br>Scans: %{y}<extra></extra>'
    ))

    fig.add_trace(go.Scatter(
        x=hours, y=high_risk,
        mode='lines+markers',
        name='High Risk',
        line=dict(color=CYBER_PALETTE['accent_red'], width=2),
        fill='tozeroy',
        fillcolor='rgba(239, 68, 68, 0.08)',
        hovertemplate='%{x}<br>High Risk: %{y}<extra></extra>'
    ))

    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text='Threat Activity (Last 24h)', font=dict(color=TEXT_COLOR, size=13)),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1,
                    bgcolor='rgba(0,0,0,0)', bordercolor='rgba(0,0,0,0)'),
        hovermode='x unified'
    )
    return fig


def threat_category_donut(category_data: dict) -> go.Figure:
    """
    Donut chart of threat categories.
    category_data: {scan_type: count}
    """
    if not category_data:
        fig = go.Figure()
        fig.add_annotation(text='No threats detected yet',
                           xref='paper', yref='paper', x=0.5, y=0.5,
                           showarrow=False, font=dict(color=TEXT_COLOR))
        fig.update_layout(**BASE_LAYOUT)
        return fig

    LABEL_MAP = {
        'url': 'URL Phishing',
        'sms': 'SMS Scam',
        'whatsapp': 'WhatsApp Fraud',
        'image': 'Image Fraud',
        'document': 'Doc Malware',
        'upi': 'UPI Fraud',
        'digital_arrest': 'Digital Arrest',
    }
    COLORS = [
        CYBER_PALETTE['accent_red'],
        CYBER_PALETTE['accent_amber'],
        CYBER_PALETTE['accent_blue'],
        CYBER_PALETTE['accent_cyan'],
        CYBER_PALETTE['accent_green'],
        '#8B5CF6', '#EC4899'
    ]

    labels = [LABEL_MAP.get(k, k.title()) for k in category_data.keys()]
    values = list(category_data.values())

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=COLORS[:len(labels)],
                    line=dict(color=BG, width=2)),
        textinfo='label+percent',
        textfont=dict(size=10, color='white'),
        hovertemplate='%{label}<br>Count: %{value}<br>Share: %{percent}<extra></extra>'
    )])

    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text='Threat Categories', font=dict(color=TEXT_COLOR, size=13)),
        showlegend=False
    )
    return fig


def risk_score_histogram(scan_data: list[dict]) -> go.Figure:
    """Bar chart of risk score distribution."""
    if not scan_data:
        fig = go.Figure()
        fig.update_layout(**BASE_LAYOUT)
        return fig

    scores = [s.get('risk_score', 0) for s in scan_data]
    bins = [0, 20, 45, 75, 100]
    labels = ['Safe (0-20)', 'Caution (21-44)', 'Suspicious (45-74)', 'High Risk (75-100)']
    colors = [CYBER_PALETTE['accent_green'], '#F97316',
              CYBER_PALETTE['accent_amber'], CYBER_PALETTE['accent_red']]

    counts = [0, 0, 0, 0]
    for s in scores:
        if s <= 20:
            counts[0] += 1
        elif s <= 44:
            counts[1] += 1
        elif s <= 74:
            counts[2] += 1
        else:
            counts[3] += 1

    fig = go.Figure(data=[go.Bar(
        x=labels, y=counts,
        marker_color=colors,
        text=counts, textposition='auto',
        hovertemplate='%{x}<br>Count: %{y}<extra></extra>'
    )])

    fig.update_layout(
        **BASE_LAYOUT,
        title=dict(text='Risk Score Distribution', font=dict(color=TEXT_COLOR, size=13)),
        showlegend=False
    )
    return fig


def risk_gauge_plotly(score: int) -> go.Figure:
    """Plotly gauge chart for a single risk score."""
    if score >= 75:
        color = CYBER_PALETTE['accent_red']
        label = 'HIGH RISK'
    elif score >= 45:
        color = CYBER_PALETTE['accent_amber']
        label = 'SUSPICIOUS'
    elif score >= 20:
        color = '#F97316'
        label = 'CAUTION'
    else:
        color = CYBER_PALETTE['accent_green']
        label = 'LIKELY SAFE'

    fig = go.Figure(go.Indicator(
        mode='gauge+number',
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': label, 'font': {'color': color, 'size': 16}},
        number={'font': {'color': color, 'size': 40}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': TEXT_COLOR,
                     'tickfont': {'color': TEXT_COLOR}},
            'bar': {'color': color},
            'bgcolor': CARD_BG,
            'borderwidth': 0,
            'steps': [
                {'range': [0, 20], 'color': 'rgba(16,185,129,0.15)'},
                {'range': [20, 45], 'color': 'rgba(249,115,22,0.15)'},
                {'range': [45, 75], 'color': 'rgba(245,158,11,0.15)'},
                {'range': [75, 100], 'color': 'rgba(239,68,68,0.15)'},
            ],
            'threshold': {
                'line': {'color': color, 'width': 3},
                'thickness': 0.8,
                'value': score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color=TEXT_COLOR),
        height=220,
        margin=dict(l=20, r=20, t=40, b=10)
    )
    return fig