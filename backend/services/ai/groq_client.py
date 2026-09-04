"""
Thin Groq client. Uses `requests` directly against Groq's OpenAI-compatible
Chat Completions endpoint, so we don't need the `groq` package as an extra
dependency -- `requests` is already in requirements.txt.

Env vars (add to .env, see .env.example):
    GROQ_API_KEY   -- required to actually call the LLM
    GROQ_MODEL     -- defaults to "llama-3.3-70b-versatile"

If GROQ_API_KEY isn't set, `call_groq_json` returns None and ai_engine.py
falls back to a deterministic template -- so the pipeline (and demo) never
hard-fails just because a key isn't configured yet.
"""

import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


class GroqError(Exception):
    pass


def is_configured() -> bool:
    return bool(os.getenv("GROQ_API_KEY"))


def call_groq_json(system_prompt: str, user_prompt: str, temperature: float = 0.2,
                    max_tokens: int = 700, model: str | None = None) -> dict | None:
    """Call Groq's chat completions API in JSON mode and parse the result.

    Returns the parsed dict, or None if no API key is configured or the
    call fails -- callers must handle the None case (see ai_engine.py's
    template fallback), never raise up into the request handler.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    payload = {
        "model": model or DEFAULT_MODEL,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=20)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return json.loads(content)
    except (requests.RequestException, KeyError, json.JSONDecodeError, IndexError):
        return None
