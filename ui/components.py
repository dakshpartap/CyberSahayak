# ui/components.py — Reusable UI components

def render_risk_gauge(score: int) -> str:
    """Returns HTML for an animated risk gauge."""
    if score >= 75:
        color, label = '#EF4444', 'HIGH RISK'
    elif score >= 45:
        color, label = '#F59E0B', 'SUSPICIOUS'
    elif score >= 20:
        color, label = '#F97316', 'CAUTION'
    else:
        color, label = '#10B981', 'LIKELY SAFE'
    
    return f"""
    <div style="text-align:center; padding: 20px; background: #0F1629; 
                border-radius: 12px; border: 1px solid #1E293B;">
        <svg width="160" height="80" viewBox="0 0 160 80">
            <path d="M 20 70 A 60 60 0 0 1 140 70" stroke="#1E293B" 
                  stroke-width="12" fill="none" stroke-linecap="round"/>
            <path d="M 20 70 A 60 60 0 0 1 140 70" stroke="{color}"
                  stroke-width="12" fill="none" stroke-linecap="round"
                  stroke-dasharray="{int(188 * score / 100)} 188"/>
        </svg>
        <div style="color: {color}; font-size: 2.5rem; font-weight: 800; 
                    margin-top: -30px;">{score}</div>
        <div style="color: #94A3B8; font-size: 0.8rem;">/100</div>
        <div style="color: {color}; font-weight: 600; margin-top: 4px; 
                    font-size: 0.9rem;">{label}</div>
    </div>
    """

def render_finding_card(finding: str, is_critical: bool = False) -> str:
    bg = 'rgba(239,68,68,0.08)' if is_critical else 'rgba(37,99,235,0.08)'
    border = '#EF4444' if is_critical else '#2563EB'
    icon = '🚨' if is_critical else '⚠️'
    return f"""
    <div style="background:{bg}; border-left: 3px solid {border}; 
                padding: 10px 14px; border-radius: 0 8px 8px 0; 
                margin-bottom: 8px; color: #F1F5F9; font-size: 0.9rem;">
        {icon} {finding}
    </div>
    """