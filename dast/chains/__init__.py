"""
Attack-chain validation.

A single-request validator cannot confirm a multi-step exploit — one where the
output of request N (a token, a Set-Cookie, an unguessable path leaked by a
GraphQL field) is what makes request N+1 succeed. This package models such a
chain as a data-driven sequence of steps with per-step extractors (bind data
out of a response) and assertions (what must hold), runs it through the proxy
under the same scope + payload-safety gates as every other Frieren request, and
returns a step-by-step verdict.

See ``engine.py`` for the executor and ``models.py`` for the chain spec.
"""

from dast.chains.models import (
    Assertion,
    Chain,
    ChainResult,
    ChainStep,
    Extractor,
    StepResult,
)

__all__ = [
    "Assertion",
    "Chain",
    "ChainResult",
    "ChainStep",
    "Extractor",
    "StepResult",
]
