"""
Audit Logger — records every scan decision to a SQLite database.

Uses SQLAlchemy 2.0 async engine with aiosqlite for non-blocking writes.
**Security**: file contents and matched text are NEVER logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQLAlchemy ORM model
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class AuditEvent(Base):
    """A single scan-decision audit record.

    **Privacy by design**: neither the file content nor the matched text
    are stored — only metadata about the decision.
    """

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    source_ip = Column(String(45), nullable=False)         # IPv4 or IPv6
    destination_host = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False)  # hex digest
    action = Column(String(10), nullable=False)             # ALLOW or BLOCK
    matched_rules = Column(Text, nullable=False, default="[]")  # JSON array of rule IDs
    scan_duration_ms = Column(Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} action={self.action} "
            f"file={self.filename!r} at {self.timestamp}>"
        )


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Async audit logger backed by SQLite.

    Usage::

        audit = AuditLogger("sqlite+aiosqlite:///./audit/dlp_audit.db")
        await audit.initialize()
        await audit.log_event(scan_request, scan_response, file_bytes)
        recent = await audit.get_recent(limit=50)
    """

    def __init__(self, database_url: str) -> None:
        if "sqlite" in database_url and ":///" in database_url:
            path_part = database_url.split(":///", 1)[1]
            if path_part and path_part != ":memory:":
                Path(path_part).resolve().parent.mkdir(parents=True, exist_ok=True)

        self._engine = create_async_engine(database_url, echo=False)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False,
        )
        self._initialized = False

    async def initialize(self) -> None:
        """Create database tables if they don't exist."""
        if self._initialized:
            return
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self._initialized = True
        logger.info("Audit database initialized")

    async def log_event(
        self,
        request: Any,
        response: Any,
        file_bytes: bytes | None = None,
    ) -> None:
        """Record a scan decision.

        Args:
            request:    The ScanRequest (or duck-typed object with
                        ``source_ip``, ``destination_host``, ``filename``).
            response:   The ScanResponse (or duck-typed object with
                        ``action``, ``matched_rules``, ``scan_duration_ms``).
            file_bytes: Raw file content used **only** to compute the
                        SHA-256 hash.  Never stored.
        """
        await self.initialize()

        file_hash = ""
        if file_bytes:
            file_hash = hashlib.sha256(file_bytes).hexdigest()

        matched_rules_json = json.dumps(
            response.matched_rules if hasattr(response, "matched_rules") else []
        )

        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip=getattr(request, "source_ip", "unknown"),
            destination_host=getattr(request, "destination_host", "unknown"),
            filename=getattr(request, "filename", "unknown"),
            file_hash_sha256=file_hash,
            action=getattr(response, "action", "UNKNOWN"),
            matched_rules=matched_rules_json,
            scan_duration_ms=getattr(response, "scan_duration_ms", 0),
        )

        async with self._session_factory() as session:
            async with session.begin():
                session.add(event)

        logger.info(
            "Audit: %s %s -> %s (%s)",
            event.action,
            event.filename,
            event.destination_host,
            event.matched_rules,
        )

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent audit events as dicts.

        Args:
            limit: Maximum number of events to return.
        """
        await self.initialize()

        from sqlalchemy import select

        async with self._session_factory() as session:
            stmt = (
                select(AuditEvent)
                .order_by(AuditEvent.timestamp.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            events = result.scalars().all()

        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source_ip": e.source_ip,
                "destination_host": e.destination_host,
                "filename": e.filename,
                "file_hash_sha256": e.file_hash_sha256,
                "action": e.action,
                "matched_rules": json.loads(e.matched_rules) if e.matched_rules else [],
                "scan_duration_ms": e.scan_duration_ms,
            }
            for e in events
        ]

    async def close(self) -> None:
        """Close the database engine."""
        await self._engine.dispose()


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def create_audit_logger(
    config_path: str | Path = "config/logging_config.yaml",
) -> AuditLogger:
    """Create an AuditLogger from the logging configuration file.

    Args:
        config_path: Path to ``logging_config.yaml``.

    Returns:
        An :class:`AuditLogger` instance (call ``await .initialize()``
        before first use, or it will auto-initialize on first write).
    """
    config_path = Path(config_path)

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as fh:
            config = yaml.safe_load(fh) or {}
        db_url = config.get("audit", {}).get(
            "database", "sqlite+aiosqlite:///./audit/dlp_audit.db"
        )
    else:
        logger.warning("Audit config %s not found — using defaults", config_path)
        db_url = "sqlite+aiosqlite:///./audit/dlp_audit.db"

    # Ensure the URL uses the async driver.
    if db_url.startswith("sqlite:///"):
        db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

    return AuditLogger(database_url=db_url)
