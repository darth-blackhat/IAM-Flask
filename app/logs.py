"""Loguru setup. Standard-library logging (uvicorn, httpx, SQLAlchemy) is routed into it.

Log message templates are constant strings; variable data goes in positional args or
bind(), never into the template, so braces in OpenIAM error text can't break formatting.
"""

import inspect
import logging
import re
import sys

from loguru import logger

__all__ = ["logger", "setup_logging"]


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        # Report the caller of the stdlib logger, not this handler or logging internals.
        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame, depth = frame.f_back, depth + 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# International (+...), area code in brackets, or 3-3-4 digit groups; not dates or ids.
_PHONE = re.compile(r"(?<![\w.])(\+\d[\d\s().-]{7,}\d|\(\d{2,4}\)\s?[\d\s.-]{5,}\d"
                    r"|\d{3}[\s.-]\d{3}[\s.-]\d{4})(?![\w.])")


def redact(text: str) -> str:
    """Mask e-mail addresses and phone numbers: a***@corp.example, ***-**12."""
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    return _PHONE.sub(lambda m: "***" + re.sub(r"\D", "", m.group(1))[-2:], text)


def _redact_record(record) -> None:
    record["message"] = redact(record["message"])


def setup_logging(level: str = "INFO", json: bool = False, file: str | None = None,
                  redact_personal_data: bool = True) -> None:
    logger.remove()
    logger.configure(patcher=_redact_record if redact_personal_data else None)
    # diagnose=False: loguru would otherwise print local variable values in tracebacks,
    # which here include client secrets and bearer tokens.
    logger.add(sys.stderr, level=level.upper(), serialize=json, backtrace=False, diagnose=False)
    if file:
        logger.add(file, level=level.upper(), serialize=json, rotation="50 MB", retention=10,
                   enqueue=True, backtrace=False, diagnose=False)

    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        std = logging.getLogger(name)
        std.handlers = [InterceptHandler()]
        std.propagate = False
    # httpx logs every request URL at INFO; SQLAlchemy echoes SQL at INFO.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("alembic").setLevel(logging.WARNING)
