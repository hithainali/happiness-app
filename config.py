import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = os.environ.get("HAPPINESS_DB", str(BASE_DIR / "happiness_pro.db"))
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Optional: load from a .env file in development
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
