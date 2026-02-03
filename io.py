import json
from typing import Iterator, Dict, Any, Optional, List
import pandas as pd
import os


def read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON at line {line_no} in {path}: {e}")


def read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def write_jsonl(path: str, records: Iterator[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def to_alert(event: Dict[str, Any], kind: str, details: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(event)
    out["_alert_kind"] = kind
    out["_alert_details"] = details
    return out
