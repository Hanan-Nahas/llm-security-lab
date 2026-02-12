"""FastAPI backend for API security testing and traffic inspection."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from litellm import completion

from challenges import build_system_prompt, get_challenge_by_id
from risk import analyze_risk

load_dotenv()

MODEL = os.getenv("LITELLM_MODEL", "gpt-4o-mini")
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() in {"1", "true", "yes", "on"}
PROGRESS_PATH = Path("progress.json")
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)
ATTACK_LOG_PATH = LOGS_DIR / "attacks.log"

logger = logging.getLogger("attack_logger")
if not logger.handlers:
    handler = logging.FileHandler(ATTACK_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

app = FastAPI(title="LLM Security Lab API", version="1.0.0")


class ChatRequest(BaseModel):
    challenge_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    reply: str
    risk_report: Dict[str, Any]
    attempts: int
    solved: bool
    debug: Dict[str, Any] | None = None


def _load_progress() -> Dict[str, Dict[str, Any]]:
    if not PROGRESS_PATH.exists():
        return {}
    try:
        return json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_progress(progress: Dict[str, Dict[str, Any]]) -> None:
    PROGRESS_PATH.write_text(json.dumps(progress, indent=2), encoding="utf-8")


def _llm_reply(system_prompt: str, user_message: str) -> str:
    try:
        response = completion(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content or "(No response content returned by model.)"
    except Exception as exc:
        return f"Model call failed. Check API key/model configuration. Error: {exc}"


def _append_attack_log(challenge_id: str, message: str, risk_report: Dict[str, Any]) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "challenge_id": challenge_id,
        "message": message,
        "risk_score": risk_report.get("risk_score"),
        "detected_tags": risk_report.get("detected_tags", []),
    }
    logger.info(json.dumps(entry, ensure_ascii=False))


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/chat", response_model=ChatResponse)
def api_chat(payload: ChatRequest) -> ChatResponse:
    challenge = get_challenge_by_id(payload.challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Unknown challenge_id")

    risk_report = analyze_risk(payload.message)
    reply = _llm_reply(build_system_prompt(challenge), payload.message)

    progress = _load_progress()
    record = progress.setdefault(challenge.id, {"attempts": 0, "solved": False})
    record["attempts"] = int(record.get("attempts", 0)) + 1
    record["solved"] = bool(record.get("solved", False))
    _save_progress(progress)

    _append_attack_log(challenge.id, payload.message, risk_report)

    debug = None
    if DEBUG_MODE:
        debug = {
            "challenge_title": challenge.title,
            "attack_style": risk_report.get("attack_style"),
            "sanitized_prompt_preview": build_system_prompt(challenge).splitlines()[0],
            "model": MODEL,
        }

    return ChatResponse(
        reply=reply,
        risk_report=risk_report,
        attempts=record["attempts"],
        solved=record["solved"],
        debug=debug,
    )
