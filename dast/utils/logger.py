"""
Logging setup for Frieren DAST-AI.

Two outputs:
  1. Console — colored human-readable (structlog dev renderer)
  2. File    — JSON lines, one event per line, written to scan output dir

Every log event includes:
  timestamp, level, logger (module name), event, all kwargs passed by caller.
  Exceptions are captured automatically with full traceback.

Usage:
    logger = get_logger(__name__)
    logger.info("page crawled", url=url, status=200, depth=2)
    logger.error("attack failed", url=url, payload=p, exc_info=True)
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import structlog

_file_handler: Optional[logging.FileHandler] = None
_configured = False


def configure_logging(level: str = "INFO", log_file: Optional[Path] = None) -> None:
    """
    Configure structlog + stdlib logging.

    Call once at startup (CLI entry point). Subsequent calls are no-ops
    unless a new log_file is provided.
    """
    global _file_handler, _configured

    log_level = getattr(logging, level.upper(), logging.INFO)

    # Shared processors applied to every event regardless of renderer
    shared_processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.FUNC_NAME,
            ]
        ),
        structlog.processors.ExceptionRenderer(),
    ]

    # --- stdlib root logger (handles file output) ---
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers.clear()

    # Console handler — pretty colored output
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    root.addHandler(console_handler)

    # File handler — JSON lines
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        _file_handler.setLevel(logging.DEBUG)  # always capture DEBUG to file
        root.addHandler(_file_handler)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Console formatter — human readable
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
        foreign_pre_chain=shared_processors,
    )
    console_handler.setFormatter(console_formatter)

    # File formatter — JSON
    if log_file and _file_handler:
        json_formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=shared_processors,
        )
        _file_handler.setFormatter(json_formatter)

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    if not _configured:
        # Auto-configure with defaults if called before configure_logging()
        configure_logging()
    return structlog.get_logger(name)


def set_log_file(log_file: Path) -> None:
    """Add or replace the file handler after initial configuration."""
    global _file_handler

    root = logging.getLogger()

    if _file_handler and _file_handler in root.handlers:
        root.removeHandler(_file_handler)
        _file_handler.close()

    log_file.parent.mkdir(parents=True, exist_ok=True)
    _file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    _file_handler.setLevel(logging.DEBUG)

    shared_processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]
    json_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    _file_handler.setFormatter(json_formatter)
    root.addHandler(_file_handler)
