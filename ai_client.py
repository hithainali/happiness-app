import requests
import logging
from typing import Optional
from config import GROQ_API_KEY


def generate_ai_response(prompt: str, timeout: int = 10) -> str:
    if not GROQ_API_KEY:
        return "GROQ_API_KEY not configured. Set it in your environment."

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": "You are a warm, empathetic emotional wellbeing coach. Be supportive and practical."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.7,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        j = resp.json()
        return j["choices"][0]["message"]["content"]
    except Exception as exc:
        logging.exception("AI request failed")
        return "Sorry — the AI service is currently unavailable. Please try again later."
