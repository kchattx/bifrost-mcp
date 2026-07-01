from __future__ import annotations

import time
from dataclasses import dataclass

from bifrost_mcp.session import RemoteSessionHandler


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    transport: str
    host: str | None
    canonical_host: str | None
    username: str | None
    port: int | None
    idle_seconds: int

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "transport": self.transport,
            "host": self.host,
            "canonical_host": self.canonical_host,
            "username": self.username,
            "port": self.port,
            "idle_seconds": self.idle_seconds,
        }


class SessionRegistry:
    def __init__(self, *, idle_timeout_seconds: float = 3600, sessions: dict[str, RemoteSessionHandler] | None = None) -> None:
        self.idle_timeout_seconds = idle_timeout_seconds
        self._sessions: dict[str, RemoteSessionHandler] = sessions if sessions is not None else {}

    @property
    def sessions(self) -> dict[str, RemoteSessionHandler]:
        return self._sessions

    def register(self, handler: RemoteSessionHandler) -> str:
        if not handler.session_id:
            raise ValueError("Cannot register remote session handler without an active session_id")
        self._sessions[handler.session_id] = handler
        return handler.session_id

    def get(self, session_id: str) -> RemoteSessionHandler:
        self.cleanup_stale()
        handler = self._sessions.get(session_id)
        if handler is None or handler.session_id != session_id:
            self._sessions.pop(session_id, None)
            raise ValueError(f"Remote session '{session_id}' was not found.")
        return handler

    def remove(self, session_id: str) -> RemoteSessionHandler:
        handler = self.get(session_id)
        self._sessions.pop(session_id, None)
        return handler

    def list_ids(self) -> list[str]:
        self.cleanup_stale()
        return sorted(self._sessions)

    def list_info(self) -> list[SessionInfo]:
        self.cleanup_stale()
        now = time.monotonic()
        infos = []
        for session_id, handler in sorted(self._sessions.items()):
            last_activity = getattr(handler, "last_activity_at", None) or getattr(handler, "created_at", None) or now
            infos.append(
                SessionInfo(
                    session_id=session_id,
                    transport=str(getattr(handler, "transport", "unknown")),
                    host=getattr(handler, "host", None),
                    canonical_host=getattr(handler, "canonical_host", None),
                    username=getattr(handler, "username", None),
                    port=getattr(handler, "port", None),
                    idle_seconds=max(0, int(now - last_activity)),
                )
            )
        return infos

    def cleanup_stale(self) -> list[str]:
        now = time.monotonic()
        removed: list[str] = []
        for session_id, handler in list(self._sessions.items()):
            stale_identity = handler.session_id != session_id
            last_activity = getattr(handler, "last_activity_at", None) or getattr(handler, "created_at", None) or now
            stale_idle = self.idle_timeout_seconds >= 0 and (now - last_activity) > self.idle_timeout_seconds
            if not stale_identity and not stale_idle:
                continue
            try:
                if handler.session_id == session_id:
                    handler.close_session()
            except Exception:
                pass
            finally:
                self._sessions.pop(session_id, None)
                removed.append(session_id)
        return removed

    def cleanup_all(self) -> None:
        for session_id, handler in list(self._sessions.items()):
            try:
                if handler.session_id == session_id:
                    handler.close_session()
            except RuntimeError:
                pass
            finally:
                self._sessions.pop(session_id, None)
