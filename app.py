import os
import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import hashlib
import requests
import json


# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="Happiness & Wellbeing Platform",
    page_icon="🧠",
    layout="wide"
)

# -------------------- AI CONFIG --------------------
HF_TOKEN = os.getenv("HF_TOKEN")

def generate_ai_response(prompt):
    if not HF_TOKEN:
        return "HF_TOKEN is not set in Streamlit Secrets."

    API_URL = "https://router.huggingface.co/hf-inference/models/mistralai/Mistral-7B-Instruct-v0.2"
    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": f"""
You are a warm and empathetic emotional wellbeing coach.
Respond kindly and practically. Do NOT give medical diagnosis.

User message:
{prompt}
""",
        "parameters": {
            "max_new_tokens": 200,
            "temperature": 0.7
        }
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload)

        if response.status_code != 200:
            return f"API Error {response.status_code}: {response.text}"

        result = response.json()

        if isinstance(result, list):
            return result[0].get("generated_text", "No response generated.")
        else:
            return str(result)

    except Exception as e:
        return f"Error: {str(e)}"

# -------------------- DATABASE --------------------
conn = sqlite3.connect("happiness_pro.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    created_at TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS moods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    mood INTEGER,
    note TEXT,
    date TEXT
)
""")

conn.commit()

c.execute("""
CREATE TABLE IF NOT EXISTS ai_chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    user_message TEXT,
    ai_response TEXT,
    date TEXT
)
""")

conn.commit()

# -------------------- UTILITIES --------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    return hash_password(password) == password_hash

# -------------------- ADMIN INIT --------------------
def init_admin():
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", hash_password("admin123"), datetime.now().isoformat())
        )
        conn.commit()

init_admin()

# -------------------- SESSION --------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

# -------------------- AUTH --------------------
def authenticate(username, password):
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if row and verify_password(password, row[0]):
        return True
    return False

def register_user(username, password):
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hash_password(password), datetime.now().isoformat())
        )
        conn.commit()
        return True, "Account created successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"

# -------------------- LOGIN UI --------------------
def show_auth():
    st.title("Happiness & Wellbeing Platform")

    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid username or password")

    with tab2:
        new_user = st.text_input("Choose Username")
        new_pass = st.text_input("Choose Password", type="password")
        if st.button("Create Account"):
            if len(new_user) < 3 or len(new_pass) < 5:
                st.warning("Username must be 3+ chars and password 5+ chars")
            else:
                success, msg = register_user(new_user, new_pass)
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

# -------------------- SIDEBAR --------------------
def show_sidebar():
    with st.sidebar:
        page = st.radio(
            "Navigation",
            ["Dashboard", "Mood Tracker", "AI Coach", "Insights", "Survey Results", "Profile"]
        )

        st.markdown("---")
        st.write(f"Logged in as: **{st.session_state.username}**")

        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()

    return page

# -------------------- DASHBOARD --------------------
def show_dashboard():
    st.title("Dashboard")
    c.execute("SELECT mood FROM moods WHERE username=?", (st.session_state.username,))
    moods = [r[0] for r in c.fetchall()]

    avg_mood = round(sum(moods) / len(moods), 2) if moods else 0
    total = len(moods)

    col1, col2 = st.columns(2)
    col1.metric("Average Mood", avg_mood)
    col2.metric("Total Check-ins", total)

    if moods:
        df = pd.DataFrame({"Mood": moods})
        st.line_chart(df)


# -------------------- MOOD TRACKER --------------------
def show_mood_tracker():
    st.title("Mood Tracker")

    mood = st.slider("How do you feel today?", 1, 10, 5)
    note = st.text_area("Reflection / Notes")

    if st.button("Save Entry"):
        c.execute(
            "INSERT INTO moods (username, mood, note, date) VALUES (?, ?, ?, ?)",
            (st.session_state.username, mood, note, datetime.now().isoformat())
        )
        conn.commit()
        st.success("Mood saved successfully")
        st.rerun()

# -------------------- AI COACH --------------------
def show_ai_coach():
    st.title("AI Wellbeing Coach")

    user_input = st.text_area("Share what you're feeling")

    if st.button("Get Coaching"):
        if user_input.strip() == "":
            st.warning("Please enter something first.")
            return

        # Fetch last 5 mood entries for memory
        c.execute(
            "SELECT mood, note, date FROM moods WHERE username=? ORDER BY date DESC LIMIT 5",
            (st.session_state.username,)
        )
        past_entries = c.fetchall()

        memory_text = ""

        if past_entries:
            memory_text += "Recent mood history:\n"
            for mood, note, date in past_entries:
                memory_text += f"- Date: {date}, Mood: {mood}/10, Note: {note}\n"
        else:
            memory_text += "No previous mood history available.\n"
        prompt = f"""
You are a warm, empathetic emotional wellbeing coach.

Use the user's past mood history to give personalized advice.
If mood trend is low, encourage gently.
If improving, acknowledge progress.
Keep response supportive and practical.
Do NOT give medical diagnosis.

{memory_text}

User currently says:
{user_input}
"""

        response = generate_ai_response(prompt)

        st.subheader("Coach Response")
        st.info(response)
        c.execute(
            "INSERT INTO ai_chats (username, user_message, ai_response, date) VALUES (?, ?, ?, ?)",
            (st.session_state.username, user_input, response, datetime.now().isoformat())
        )
        conn.commit()


# -------------------- INSIGHTS --------------------
def show_insights():
    st.title("Insights")

    c.execute("SELECT mood, date FROM moods WHERE username=?", (st.session_state.username,))
    rows = c.fetchall()

    if rows:
        df = pd.DataFrame(rows, columns=["Mood", "Date"])
        df["Date"] = pd.to_datetime(df["Date"])
        df["Day"] = df["Date"].dt.date
        daily_avg = df.groupby("Day")["Mood"].mean()
        st.line_chart(daily_avg)
    else:
        st.info("Not enough data yet.")

# -------------------- SURVEY RESULT --------------------
def show_survey_results():
    st.title("Survey Results - All Users")

    # Fetch all moods
    df = pd.read_sql_query("SELECT mood, date FROM moods", conn)

    if df.empty:
        st.info("No survey responses yet.")
        return

    # Convert date
    df["date"] = pd.to_datetime(df["date"])
    df["day"] = df["date"].dt.date

    # Overall stats
    overall_avg = round(df["mood"].mean(), 2)
    total_responses = len(df)

    col1, col2 = st.columns(2)
    col1.metric("Overall Average Mood", overall_avg)
    col2.metric("Total Responses", total_responses)

    st.markdown("---")

    # Daily average across ALL users
    daily_avg = df.groupby("day")["mood"].mean()

    st.subheader("Average Mood Per Day (All Users)")
    st.line_chart(daily_avg)

# -------------------- PROFILE --------------------
def show_profile():
    st.title("Profile")

    c.execute(
        "SELECT mood, note, date FROM moods WHERE username=? ORDER BY date DESC",
        (st.session_state.username,)
    )
    rows = c.fetchall()

    df = pd.DataFrame(rows, columns=["Mood", "Note", "Date"])
    st.dataframe(df, width=True)

# -------------------- ADMIN DATA VIEW --------------------
    if st.session_state.username == "admin":
        st.markdown("---")
        st.subheader("Admin Panel - All Users Data")

        if st.button("View All Mood Entries"):
            all_moods = pd.read_sql_query("SELECT * FROM moods", conn)
            st.dataframe(all_moods)

        if st.button("View All AI Chats"):
            all_chats = pd.read_sql_query("SELECT * FROM ai_chats", conn)
            st.dataframe(all_chats)

        if st.button("Download Full Database"):
            all_data = pd.read_sql_query("SELECT * FROM moods", conn)
            all_data.to_csv("exported_data.csv", index=False)
            with open("exported_data.csv", "rb") as f:
                st.download_button(
                    label="Download CSV",
                    data=f,
                    file_name="happiness_data.csv",
                    mime="text/csv"
                )

# -------------------- MAIN --------------------
if not st.session_state.logged_in:
    show_auth()
else:
    page = show_sidebar()

    if page == "Dashboard":
        show_dashboard()
    elif page == "Mood Tracker":
        show_mood_tracker()
    elif page == "AI Coach":
        show_ai_coach()
    elif page == "Insights":
        show_insights()
    elif page == "Survey Results":
        show_survey_results()
    elif page == "Profile":
        show_profile()



