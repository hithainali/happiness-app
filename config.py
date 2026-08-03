import os
from pathlib import Path

# Load .env first
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

BASE_DIR = Path(__file__).parent

DB_PATH = os.environ.get("HAPPINESS_DB", str(BASE_DIR / "happiness_pro.db"))
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")