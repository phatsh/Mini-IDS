from dataclasses import dataclass
from typing import Any, Dict, List, Iterator, Optional, Tuple
import fnmatch
import os
import yaml


@dataclass
class SigmaRule:
    id: str
    title: str
    detection: Dict[str, Any]
    level: Optional[str] = None

def _value_match(op: str, expected: Any, actual: Any) -> bool:
    if actual is None:
        return False
    # List => OR across items
    if isinstance(expected, list):
        return any(_value_match(op, e, actual) for e in expected)

    # Numeric comparison operators
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a_num = float(actual)
            e_num = float(expected)
        except Exception:
            return False
        if op == "gt":
            return a_num > e_num
        if op == "gte":
            return a_num >= e_num
        if op == "lt":
            return a_num < e_num
        if op == "lte":
            return a_num <= e_num

    # Pattern operators
    if op in ("contains", "startswith", "endswith", "wildcard"):
        actual_s = str(actual)
        expected_s = str(expected)
        if op == "contains":
            return expected_s in actual_s
        if op == "startswith":
            return actual_s.startswith(expected_s)
        if op == "endswith":
            return actual_s.endswith(expected_s)
        if op == "wildcard":
            return fnmatch.fnmatch(actual_s, expected_s)

    # Default equality
    try:
        return actual == expected
    except Exception:
        return str(actual) == str(expected)


def _parse_key_operator(key: str) -> Tuple[str, str]:
    # field|operator -> (field, operator)
    if "|" in key:
        field, op = key.split("|", 1)
        return field, op
    # Wildcard support when value contains *
    return key, "auto"


def _match_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        field, op = _parse_key_operator(raw_key)
        val = event.get(field)
        eff_op = op
        if op == "auto":
            # If expected is str with wildcard, treat as wildcard
            if isinstance(expected, str) and ("*" in expected or "?" in expected):
                eff_op = "wildcard"
            else:
                eff_op = "eq"
        if eff_op == "eq":
            if not _value_match("eq", expected, val):
                return False
        elif eff_op in ("contains", "startswith", "endswith", "wildcard", "gt", "gte", "lt", "lte"):
            if not _value_match(eff_op, expected, val):
                return False
        else:
            # Unsupported operator -> no match
            return False
    return True


class SigmaMatcher:
    def __init__(self) -> None:
        self.rules: List[SigmaRule] = []

    def load_path(self, path: str) -> None:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in files:
                    if name.endswith((".yml", ".yaml")):
                        self._load_file(os.path.join(root, name))
        else:
            self._load_file(path)

    def _load_file(self, file_path: str) -> None:
        with open(file_path, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)
        if isinstance(content, list):
            for item in content:
                self._append_rule(item, file_path)
        else:
            self._append_rule(content, file_path)

    def _append_rule(self, data: Dict[str, Any], origin: str) -> None:
        if not data:
            return
        rid = str(data.get("id") or data.get("ruleid") or os.path.basename(origin))
        title = str(data.get("title") or rid)
        det = data.get("detection") or {}
        level = data.get("level")
        self.rules.append(SigmaRule(id=rid, title=title, detection=det, level=level))

    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            if self._rule_matches(rule, event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                })
        return matches

    def _rule_matches(self, rule: SigmaRule, event: Dict[str, Any]) -> bool:
        detection = rule.detection or {}
        if not detection:
            return False
        # Extract condition, default to simple single selection if only one key
        condition = detection.get("condition")
        selections = {k: v for k, v in detection.items() if k != "condition"}
        if condition is None:
            if len(selections) == 1:
                sel = next(iter(selections.values()))
                return _match_selection(event, sel)
            # If multiple selections without condition, require all
            return all(_match_selection(event, sel) for sel in selections.values())

        cond = str(condition).strip()
        # Support forms: "selection", "1 of selection*", "all of selection*", "selection1 or selection2"
        if cond in selections:
            return _match_selection(event, selections[cond])

        if " of " in cond and cond.endswith("*"):
            # e.g., "1 of selection*" or "all of selection*"
            quant, prefix_star = cond.split(" of ", 1)
            prefix = prefix_star[:-1]  # drop *
            bucket = [name for name in selections.keys() if name.startswith(prefix)]
            if not bucket:
                return False
            if quant == "all":
                return all(_match_selection(event, selections[name]) for name in bucket)
            try:
                needed = int(quant)
            except ValueError:
                return False
            hits = sum(1 for name in bucket if _match_selection(event, selections[name]))
            return hits >= needed

        if " or " in cond:
            parts = [p.strip() for p in cond.split(" or ")]
            good = False
            for p in parts:
                if p in selections and _match_selection(event, selections[p]):
                    good = True
                    break
            return good

        if " and " in cond:
            parts = [p.strip() for p in cond.split(" and ")]
            for p in parts:
                if p not in selections or not _match_selection(event, selections[p]):
                    return False
            return True

        # Fallback: unknown condition -> no match
        return False
