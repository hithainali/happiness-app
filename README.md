# Happiness & Wellbeing Platform

A small Streamlit app to track moods and get AI wellbeing coaching.

## Quickstart

1. Create a virtualenv and install deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Set environment variables (example):

```bash
export GROQ_API_KEY="your_api_key_here"
export ADMIN_PASSWORD="choose-a-strong-admin-password"
```

3. Run the app:

```bash
streamlit run app.py
```

Notes:
- ADMIN_PASSWORD: set this before first run to create the `admin` account. If not set, the app will not create a default admin and will print an instruction.
- Passwords are stored hashed using bcrypt (passlib).
