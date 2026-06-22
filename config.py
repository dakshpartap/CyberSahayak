# config.py — CyberSahayak v2.0 Configuration
import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    # API Keys
    VIRUSTOTAL_API_KEY: str = field(default_factory=lambda: os.getenv('VIRUSTOTAL_API_KEY', ''))
    ABUSEIPDB_API_KEY: str = field(default_factory=lambda: os.getenv('ABUSEIPDB_API_KEY', ''))
    GEMINI_API_KEY: str = field(default_factory=lambda: os.getenv('GEMINI_API_KEY', ''))

    # Paths
    MODELS_DIR: Path = Path('models')
    DATASETS_DIR: Path = Path('datasets')
    KB_DIR: Path = Path('modules/chatbot/knowledge_base')
    FAISS_INDEX_DIR: Path = Path('modules/chatbot/knowledge_base/faiss_index')
    AUDIT_DB: Path = Path('cybersahayak_audit.db')
    GEOIP_DB: Path = Path('models/GeoLite2-Country.mmdb')

    # Thresholds
    HIGH_RISK_THRESHOLD: int = 75
    SUSPICIOUS_THRESHOLD: int = 45
    CAUTION_THRESHOLD: int = 20

    # Ollama config
    OLLAMA_BASE_URL: str = field(default_factory=lambda: os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'))
    OLLAMA_DEFAULT_MODEL: str = field(default_factory=lambda: os.getenv('OLLAMA_MODEL', 'qwen2.5:3b'))

    # App config
    APP_VERSION: str = '2.0.0'
    MAX_FILE_SIZE_MB: int = 10
    SCAN_TIMEOUT_SECONDS: int = 30

settings = Settings()