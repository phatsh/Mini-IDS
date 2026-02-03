import json
import os
from datetime import datetime, timezone
from typing import Optional, Any, Dict

"""
Lightweight logging helpers for the CLI IDS.

We intentionally avoid Python's full logging configuration to keep things
simple and to ensure logs are always appended in JSONL-friendly form.

Files (relative to project root by default):
- actions.log        : high‑level actions / state transitions
- results.log        : final alerts (IDS decisions)
- errors.log         : errors / exceptions
- captured_events.jsonl : raw capture/bin events
- ml_log.log         : detailed ML scores / flags
- formatpacket.jsonl : per‑packet feature extraction

Paths can be overridden at runtime via `init_logging()`, which the CLI
entrypoint should call once based on global CLI options.
"""


_ACTION_LOG = "logs/actions.log"
_RESULT_LOG = "logs/results.log"
_ERROR_LOG = "logs/errors.log"
_EVENT_LOG = "logs/captured_events.jsonl"
_ML_LOG = "logs/ml_log.log"
_FORMATTED_LOG = "logs/formatpacket.jsonl"


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def init_logging(
    *,
    action_log: Optional[str] = None,
    result_log: Optional[str] = None,
    error_log: Optional[str] = None,
    event_log: Optional[str] = None,
    ml_log: Optional[str] = None,
    formatted_log: Optional[str] = None,
) -> None:
    """
    Configure log file locations. Any parameter left as None keeps default.

    This function is safe to call multiple times; it simply updates the
    module‑level paths.
    """
    global _ACTION_LOG, _RESULT_LOG, _ERROR_LOG, _EVENT_LOG, _ML_LOG, _FORMATTED_LOG

    if action_log:
        _ACTION_LOG = action_log
    if result_log:
        _RESULT_LOG = result_log
    if error_log:
        _ERROR_LOG = error_log
    if event_log:
        _EVENT_LOG = event_log
    if ml_log:
        _ML_LOG = ml_log
    if formatted_log:
        _FORMATTED_LOG = formatted_log


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _append_line(path: str, text: str) -> None:
    _ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def action(msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
    """
    Log a high‑level action step.
    Stored as a JSON line with at least: type, ts, message.
    """
    rec: Dict[str, Any] = {
        "type": "action",
        "ts": _now_iso(),
        "message": msg,
    }
    if extra:
        rec.update(extra)
    _append_line(_ACTION_LOG, json.dumps(rec, ensure_ascii=False))


def result(msg_or_obj: Any) -> None:
    """
    Log a final detection result / alert.
    Accepts either a pre‑encoded string or a Python object.
    """
    if isinstance(msg_or_obj, str):
        line = msg_or_obj
    else:
        line = json.dumps(msg_or_obj, ensure_ascii=False)
    _append_line(_RESULT_LOG, line)


def error(msg: str, *, exc: Optional[BaseException] = None) -> None:
    """
    Log an error. If an exception is provided, include its type and repr().
    """
    rec: Dict[str, Any] = {
        "type": "error",
        "ts": _now_iso(),
        "message": msg,
    }
    if exc is not None:
        rec["exc_type"] = type(exc).__name__
        rec["exc"] = repr(exc)
    _append_line(_ERROR_LOG, json.dumps(rec, ensure_ascii=False))


def event(msg_or_obj: Any) -> None:
    """
    Log a raw capture/bin event to the capture events JSONL stream.
    """
    if isinstance(msg_or_obj, str):
        line = msg_or_obj
    else:
        line = json.dumps(msg_or_obj, ensure_ascii=False)
    _append_line(_EVENT_LOG, line)


def ml(msg_or_obj: Any) -> None:
    """
    Log detailed ML evaluation (scores, windows, thresholds).
    """
    if isinstance(msg_or_obj, str):
        line = msg_or_obj
    else:
        line = json.dumps(msg_or_obj, ensure_ascii=False)
    _append_line(_ML_LOG, line)


def formatted(msg_or_obj: Any) -> None:
    """
    Log per‑packet features in a compact JSON‑friendly format.
    Useful for debugging / retraining datasets.
    """
    if isinstance(msg_or_obj, str):
        line = msg_or_obj
    else:
        line = json.dumps(msg_or_obj, ensure_ascii=False)
    _append_line(_FORMATTED_LOG, line)


