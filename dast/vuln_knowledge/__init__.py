"""
Vulnerability knowledge base — few-shot examples of what IS and IS NOT a real
vulnerability, keyed by attack_type.

The examples are authored by us (trusted, static YAML) and are consumed by the
Red-Team Validator (dast/ai/red_team.py) to sharpen the "is this a real
vulnerability?" decision: positive examples anchor genuine exploitation, negative
examples anchor the look-alikes that are structurally not exploitable (the false
positives that waste a developer's time).

One YAML file per attack_type under this package. Adding coverage for a new
vulnerability class requires only a new YAML file — no code changes.
"""

from dast.vuln_knowledge.loader import (
    format_examples_block,
    format_positive_examples,
    get_examples,
    known_attack_types,
)

__all__ = [
    "format_examples_block",
    "format_positive_examples",
    "get_examples",
    "known_attack_types",
]
