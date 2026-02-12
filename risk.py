"""Prompt injection risk analyzer for llm-security-lab."""

from __future__ import annotations

import re
from typing import Dict, List

PATTERN_LIBRARY = {
    "system_prompt_request": [
        r"\bsystem\s+prompt\b",
        r"\bhidden\s+instructions?\b",
        r"\breveal\s+(the\s+)?prompt\b",
        r"\binternal\s+prompt\b",
    ],
    "role_override": [
        r"\byou\s+are\s+now\b",
        r"\bpretend\s+to\s+be\b",
        r"\bact\s+as\s+(system|developer|root|admin)\b",
        r"\bfrom\s+now\s+on\b",
    ],
    "ignore_rules": [
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        r"\bdisregard\s+(your\s+)?rules\b",
        r"\boverride\s+(security|safety|policy)\b",
    ],
    "developer_mode": [
        r"\bdeveloper\s+mode\b",
        r"\bdebug\s+mode\b",
        r"\bjailbreak\b",
        r"\bDAN\b",
    ],
    "exfiltration_formatting": [
        r"\bbase64\b",
        r"\bhex\b",
        r"\bacrostic\b",
        r"\bfirst\s+letter\b",
        r"\bencode\b",
    ],
}

MITIGATION_MAP = {
    "system_prompt_request": "Never reveal hidden/system instructions; return a refusal and safe summary.",
    "role_override": "Enforce strict role hierarchy. Ignore user attempts to redefine system authority.",
    "ignore_rules": "Treat instruction override attempts as malicious; continue following system policies.",
    "developer_mode": "Block jailbreak/dev-mode framing and provide policy-compliant alternatives.",
    "exfiltration_formatting": "Prevent indirect leakage through encoding/transformation channels.",
}


def _count_pattern_hits(text: str, patterns: List[str]) -> int:
    return sum(1 for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE))


def analyze_risk(message: str) -> Dict[str, object]:
    """Analyze user text for prompt injection intent and return risk details.

    Returns
    -------
    dict
        {
          "risk_score": float in [0, 1],
          "detected_tags": list[str],
          "attack_style": str,
          "mitigation_tips": list[str]
        }
    """

    normalized = message.strip()
    if not normalized:
        return {
            "risk_score": 0.0,
            "detected_tags": [],
            "attack_style": "none",
            "mitigation_tips": ["No risky prompt-injection patterns detected."],
        }

    hits_by_tag: Dict[str, int] = {}
    for tag, patterns in PATTERN_LIBRARY.items():
        hit_count = _count_pattern_hits(normalized, patterns)
        if hit_count > 0:
            hits_by_tag[tag] = hit_count

    detected_tags = sorted(hits_by_tag.keys())
    total_hits = sum(hits_by_tag.values())

    if not detected_tags:
        return {
            "risk_score": 0.05,
            "detected_tags": [],
            "attack_style": "benign_or_unclear",
            "mitigation_tips": ["Keep enforcing system instruction hierarchy."],
        }

    # Weighted risk: multiple categories raise severity quickly.
    category_weight = min(0.75, 0.25 * len(detected_tags))
    frequency_weight = min(0.25, 0.05 * total_hits)
    risk_score = round(min(1.0, category_weight + frequency_weight), 2)

    primary_tag = max(hits_by_tag, key=hits_by_tag.get)
    attack_style = primary_tag

    mitigation_tips = [MITIGATION_MAP[tag] for tag in detected_tags]

    return {
        "risk_score": risk_score,
        "detected_tags": detected_tags,
        "attack_style": attack_style,
        "mitigation_tips": mitigation_tips,
    }
