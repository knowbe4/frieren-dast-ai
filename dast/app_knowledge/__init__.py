"""Local per-host app-knowledge store (notes under ~/.dast-ai/app_knowledge/, never committed)."""

from dast.app_knowledge.store import append_note, knowledge_dir, load_for_host

__all__ = ["append_note", "knowledge_dir", "load_for_host"]
