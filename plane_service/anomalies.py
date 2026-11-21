"""Anomaly log. Every record carries an ISO-8601 timestamp and, for failures, the traceback."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger("capability_authority.anomalies")


def log_anomaly(message: str, exc: BaseException | None = None) -> None:
    """Record an anomaly. Pass the caught exception so its traceback is kept."""
    stamp = datetime.now(timezone.utc).isoformat()
    if exc is None:
        logger.error("%s %s", stamp, message)
        return
    logger.error(
        "%s %s",
        stamp,
        message,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
