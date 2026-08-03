import streamlit as st
import pandas as pd

from db import init_db, get_moods_by_user, save_mood, get_recent_moods, save_ai_chat, get_all_moods, get_all_chats
from auth import authenticate, register_user, init_admin
from ai_client import generate_ai_response


def _init_session():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = None


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
            success, msg = register_user(new_user, new_pass)
            if success:
                st.success(msg)
            else:
                st.error(msg)


def show_sidebar():
    with st.sidebar:
        menu_options = ["Dashboard", "Mood Tracker", "AI Coach", "Insights", "Profile"]

        if st.session_state.username == "admin":
            menu_options.insert(4, "Survey Results")

        page = st.radio("Navigation", menu_options)

        st.markdown("---")
        st.write(f"Logged in as: **{st.session_state.username}**")

        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()

        st.markdown("---")
        st.markdown("### Connect with Me")
        st.markdown(
            """
            <div style="display:flex; gap:15px; align-items:center;">
            <a href="https://www.linkedin.com/in/hithain-ali" target="_blank">
            <img src="https://cdn-icons-png.flaticon.com/512/174/174857.png" 
                 width="30" title="LinkedIn">
            </a>
            <a href="https://www.instagram.com/hithain_4li" target="_blank">
            <img src="https://cdn-icons-png.flaticon.com/512/2111/2111463.png" 
                 width="30" title="Instagram">
            </a>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return page


def show_dashboard():
    st.title("Dashboard")
    rows = get_moods_by_user(st.session_state.username)
    moods = [r["mood"] for r in rows]

    avg_mood = round(sum(moods) / len(moods), 2) if moods else 0
    total = len(moods)

    col1, col2 = st.columns(2)
    col1.metric("Average Mood", avg_mood)
    col2.metric("Total Check-ins", total)

    if moods:
        df = pd.DataFrame({"Mood": moods})
        st.line_chart(df)


def show_mood_tracker():
    st.title("Mood Tracker")

    if "mood_saved" in st.session_state and st.session_state.mood_saved:
        st.success("✅ Your mood has been saved successfully!")
        st.session_state.mood_saved = False

    mood = st.slider("How do you feel today?", 1, 10, 5)
    note = st.text_area("Reflection / Notes")

    if st.button("Save Entry"):
        save_mood(st.session_state.username, mood, note)
        st.session_state.mood_saved = True
        st.rerun()


def show_ai_coach():
    st.title("AI Wellbeing Coach")

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # Load last 10 chats from DB for this user (optional enhancement)
    for chat in st.session_state.chat_history:
        with st.chat_message(chat["role"]):
            st.markdown(chat["content"]) 

    user_input = st.chat_input("Share what you're feeling...")

    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})

        with st.chat_message("user"):
            st.markdown(user_input)

        past_entries = get_recent_moods(st.session_state.username, limit=5)

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

User says:
{user_input}
"""

        response = generate_ai_response(prompt)

        st.session_state.chat_history.append({"role": "assistant", "content": response})

        with st.chat_message("assistant"):
            st.markdown(response)

        save_ai_chat(st.session_state.username, user_input, response)


def show_insights():
    st.title("Insights")

    rows = get_moods_by_user(st.session_state.username)

    if rows:
        df = pd.DataFrame(rows, columns=["Mood", "Note", "Date"]) if False else None
        # convert rows to dataframe properly
        df = pd.DataFrame([{"Mood": r["mood"], "Date": r["date"]} for r in rows])
        df["Date"] = pd.to_datetime(df["Date"])
        df["Day"] = df["Date"].dt.date
        daily_avg = df.groupby("Day")["Mood"].mean()
        st.line_chart(daily_avg)
    else:
        st.info("Not enough data yet.")


def show_survey_results():
    if st.session_state.username != "admin":
        st.error("Access denied.")
        return
    st.title("Survey Results - All Users")

    df = get_all_moods()

    if df.empty:
        st.info("No survey responses yet.")
        return

    df["date"] = pd.to_datetime(df["date"])
    df["day"] = df["date"].dt.date

    overall_avg = round(df["mood"].mean(), 2)
    total_responses = len(df)

    col1, col2 = st.columns(2)
    col1.metric("Overall Average Mood", overall_avg)
    col2.metric("Total Responses", total_responses)

    st.markdown("---")

    daily_avg = df.groupby("day")["mood"].mean()

    st.subheader("Average Mood Per Day (All Users)")
    st.line_chart(daily_avg)


def show_profile():
    st.title("Profile")

    rows = get_moods_by_user(st.session_state.username)

    df = pd.DataFrame([{"Mood": r["mood"], "Note": r["note"], "Date": r["date"]} for r in rows])
    st.dataframe(df, width=True)

    if st.session_state.username == "admin":
        st.markdown("---")
        st.subheader("Admin Panel - All Users Data")

        if st.button("View All Mood Entries"):
            all_moods = get_all_moods()
            st.dataframe(all_moods)

        if st.button("View All AI Chats"):
            all_chats = get_all_chats()
            st.dataframe(all_chats)

        if st.button("Download Full Database"):
            all_data = get_all_moods()
            all_data.to_csv("exported_data.csv", index=False)
            with open("exported_data.csv", "rb") as f:
                st.download_button(
                    label="Download CSV",
                    data=f,
                    file_name="happiness_data.csv",
                    mime="text/csv",
                )


def run_app():
    st.set_page_config(page_title="Happiness & Wellbeing Platform", page_icon="🥰", layout="wide")
    init_db()
    init_admin()
    _init_session()

    if not st.session_state.logged_in:
        show_auth()
        return

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
