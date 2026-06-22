# core/session_manager.py
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import json
import sqlite3

@dataclass
class InvestigationSession:
    """Represents a single cybercrime investigation case."""
    case_id: str = field(default_factory=lambda: f"CS-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}")
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    crime_type: str = ""
    victim_description: str = ""
    
    # Evidence collected
    scanned_urls: list[dict] = field(default_factory=list)
    scanned_messages: list[dict] = field(default_factory=list)
    scanned_images: list[dict] = field(default_factory=list)
    scanned_documents: list[dict] = field(default_factory=list)
    
    # Intelligence gathered
    threat_intel: dict = field(default_factory=dict)
    
    # Final assessment
    overall_risk: int = 0
    conclusion: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    
    def add_url_result(self, url: str, result: dict):
        self.scanned_urls.append({'url': url, 'result': result,
                                  'timestamp': datetime.now().isoformat()})
        self._update_risk()
    
    def add_message_result(self, message: str, result: dict):
        self.scanned_messages.append({'message': message[:200], 'result': result,
                                      'timestamp': datetime.now().isoformat()})
        self._update_risk()
    
    def _update_risk(self):
        """Recalculate overall risk from all evidence."""
        all_scores = (
            [r['result'].get('risk_score', 0) for r in self.scanned_urls] +
            [r['result'].get('risk_score', 0) for r in self.scanned_messages] +
            [r['result'].get('risk_score', 0) for r in self.scanned_images]
        )
        self.overall_risk = max(all_scores) if all_scores else 0
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)