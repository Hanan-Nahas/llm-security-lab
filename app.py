"""Streamlit MVP for llm-security-lab."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

import requests
import streamlit as st
from dotenv import load_dotenv

from challenges import get_challenges_for_difficulty, get_difficulties

load_dotenv()

PROGRESS_PATH = Path("progress.json")
BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/chat")


def load_progress() -> Dict[str, Dict[str, object]]:
    if not PROGRESS_PATH.exists():
        return {}

    try:
        with PROGRESS_PATH.open("r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                return data
    except (json.JSONDecodeError, OSError):
        pass

    return {}


def save_progress(progress: Dict[str, Dict[str, object]]) -> None:
    with PROGRESS_PATH.open("w", encoding="utf-8") as file:
        json.dump(progress, file, indent=2)


def init_session_state() -> None:
    defaults = {
        "chat_history": [],
        "active_challenge_id": None,
        "progress": load_progress(),
        "last_risk_report": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_challenge_by_selection(difficulty: str, challenge_title: str):
    for challenge in get_challenges_for_difficulty(difficulty):
        if challenge.title == challenge_title:
            return challenge
    return None


def ensure_progress_record(challenge_id: str) -> None:
    if challenge_id not in st.session_state.progress:
        st.session_state.progress[challenge_id] = {
            "attempts": 0,
            "solved": False,
        }


def call_chat_api(challenge_id: str, user_message: str) -> Dict[str, object]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"challenge_id": challenge_id, "message": user_message}

    try:
        response = requests.post(BACKEND_API_URL, headers=headers, json=payload, timeout=45)
        if response.status_code != 200:
            return {
                "reply": f"Backend returned {response.status_code}: {response.text}",
                "risk_report": {
                    "risk_score": 0.0,
                    "detected_tags": [],
                    "attack_style": "backend_error",
                    "mitigation_tips": ["Verify backend server and request payload."],
                },
                "attempts": 0,
                "solved": False,
            }
        return response.json()
    except requests.RequestException as exc:
        return {
            "reply": f"API call failed. Is backend running at {BACKEND_API_URL}? Error: {exc}",
            "risk_report": {
                "risk_score": 0.0,
                "detected_tags": [],
                "attack_style": "backend_unreachable",
                "mitigation_tips": ["Start backend via: uvicorn backend:app --reload"],
            },
            "attempts": 0,
            "solved": False,
        }


def render_sidebar(challenge):
    ensure_progress_record(challenge.id)
    record = st.session_state.progress[challenge.id]

    st.sidebar.subheader("Challenge")
    st.sidebar.write(f"**Difficulty:** {challenge.difficulty}")
    st.sidebar.write(f"**Description:** {challenge.description}")

    st.sidebar.subheader("Progress")
    st.sidebar.metric("Attempts", record["attempts"])
    st.sidebar.metric("Solved", "✅ Yes" if record["solved"] else "❌ No")

    st.sidebar.subheader("Backend")
    st.sidebar.code(BACKEND_API_URL)


def main() -> None:
    st.set_page_config(page_title="LLM Security Lab", page_icon="🛡️", layout="wide")
    st.title("🛡️ LLM Security Lab")
    st.caption("Practice prompt injection attacks and learn defenses with instant risk analysis.")

    init_session_state()

    difficulty = st.selectbox("Select difficulty", options=get_difficulties(), index=0)
    challenge_options = get_challenges_for_difficulty(difficulty)
    challenge_title = st.selectbox(
        "Select challenge",
        options=[c.title for c in challenge_options],
        index=0,
    )
    challenge = get_challenge_by_selection(difficulty, challenge_title)

    if challenge is None:
        st.error("Challenge not found. Please reselect.")
        return

    if st.session_state.active_challenge_id != challenge.id:
        st.session_state.active_challenge_id = challenge.id
        st.session_state.chat_history = []
        st.session_state.last_risk_report = None

    render_sidebar(challenge)

    st.subheader("Chat")
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    user_input = st.chat_input("Try a prompt injection attack...")
    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})

        api_result = call_chat_api(challenge.id, user_input)
        st.session_state.last_risk_report = api_result["risk_report"]

        ensure_progress_record(challenge.id)
        st.session_state.progress[challenge.id]["attempts"] = api_result.get("attempts", 0)
        st.session_state.progress[challenge.id]["solved"] = api_result.get("solved", False)
        save_progress(st.session_state.progress)

        st.session_state.chat_history.append({"role": "assistant", "content": api_result["reply"]})
        st.rerun()

    st.subheader("Risk Report")
    if st.session_state.last_risk_report:
        report = st.session_state.last_risk_report
        st.write(f"**Risk Score:** `{report['risk_score']}`")
        st.write(f"**Attack Style:** `{report['attack_style']}`")
        st.write(f"**Detected Tags:** `{', '.join(report['detected_tags']) or 'None'}`")
        st.write("**Mitigation Tips:**")
        for tip in report["mitigation_tips"]:
            st.write(f"- {tip}")
    else:
        st.info("Send a message to generate a risk report.")

    st.subheader("Flag Submission")
    submitted_flag = st.text_input("Submit extracted flag", placeholder="FLAG{...}")
    if st.button("Validate Flag", type="primary"):
        ensure_progress_record(challenge.id)

        if submitted_flag.strip() == challenge.hidden_flag:
            st.session_state.progress[challenge.id]["solved"] = True
            st.success("Correct flag! Challenge solved.")
        else:
            st.error("Incorrect flag. Keep testing prompt strategies.")

        save_progress(st.session_state.progress)
        st.rerun()


if __name__ == "__main__":
    main()
