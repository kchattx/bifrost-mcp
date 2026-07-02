from __future__ import annotations

import time
import uuid
from typing import Any

from bifrost_mcp.credentials import CredentialValidationError, canonicalize_host

try:
    import winrm
except ImportError:  # pragma: no cover - exercised via runtime error path when dependency is missing
    class _MissingWinRMModule:
        Session = None

    winrm = _MissingWinRMModule()


def _canonicalize_winrm_host(host: str, port: int, *, use_ssl: bool) -> str:
    if port == (5986 if use_ssl else 5985):
        return canonicalize_host(host)
    try:
        return canonicalize_host(host, port)
    except CredentialValidationError:
        raise


class WinRMHandler:
    transport = "winrm"

    def __init__(self) -> None:
        self.session_id: str | None = None
        self.host: str | None = None
        self.canonical_host: str | None = None
        self.username: str | None = None
        self.port: int | None = None
        self.created_at: float | None = None
        self.last_activity_at: float | None = None
        self._password: str | None = None
        self._use_ssl = False
        self._auth = "ntlm"
        self._is_open = False

    def _touch(self) -> None:
        self.last_activity_at = time.monotonic()

    def open_session(
        self,
        *,
        host: str,
        username: str,
        port: int = 5985,
        password: str,
        use_ssl: bool = False,
        auth: str = "ntlm",
    ) -> str:
        now = time.monotonic()
        self.session_id = uuid.uuid4().hex
        self.host = host
        self.canonical_host = _canonicalize_winrm_host(host, port, use_ssl=use_ssl)
        self.username = username
        self.port = port
        self.created_at = now
        self.last_activity_at = now
        self._password = password
        self._use_ssl = use_ssl
        self._auth = auth
        self._is_open = True
        return self.session_id

    def close_session(self) -> None:
        self._is_open = False
        self._touch()

    def send_input(self, text: str) -> None:
        raise NotImplementedError("WinRM does not support interactive send_input")

    def send_control(self, key: str) -> None:
        raise NotImplementedError("WinRM does not support interactive send_control")

    def resize_session(self, width: int, height: int) -> None:
        raise NotImplementedError("WinRM does not support PTY resize")

    def read_output(self) -> str:
        raise NotImplementedError("WinRM does not provide buffered interactive output")

    def flush_output_buffer(self) -> str:
        raise NotImplementedError("WinRM does not provide buffered interactive output")

    def wait_for_output(self, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, object]:
        raise NotImplementedError("WinRM does not support wait_for_output")

    def _build_endpoint(self) -> str:
        if self.host is None or self.port is None:
            raise RuntimeError("WinRM session is not open")
        scheme = "https" if self._use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/wsman"

    def run_command(self, command: str, timeout: float = 30) -> dict[str, object]:
        if not self._is_open:
            raise RuntimeError("WinRM session is not open")
        if self.username is None or self._password is None:
            raise RuntimeError("WinRM session is missing authentication state")
        if getattr(winrm, "Session", None) is None:
            raise RuntimeError("pywinrm is not installed")
        SessionCls = winrm.Session
        if SessionCls is None:
            raise RuntimeError("pywinrm is not installed")
        read_timeout_sec = max(int(timeout) + 5, 10)
        operation_timeout_sec = max(int(timeout), 5)
        session = SessionCls(
            target=self._build_endpoint(),
            auth=(self.username, self._password),
            transport=self._auth,
            server_cert_validation="ignore",
            read_timeout_sec=read_timeout_sec,
            operation_timeout_sec=operation_timeout_sec,
        )
        # ponytail: pywinrm already wraps this in PowerShell, so callers should pass
        # script text directly instead of nesting `powershell -Command ...`.
        result = session.run_ps(command)
        stdout = result.std_out.decode("utf-8", errors="replace")
        stderr = result.std_err.decode("utf-8", errors="replace")
        self._touch()
        return {
            "status": "completed",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": int(result.status_code),
        }

    def check_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        raise NotImplementedError("WinRM does not support sudo cache operations")

    def warm_sudo_cache(self, sudo_password: str, timeout: float = 10) -> dict[str, object]:
        raise NotImplementedError("WinRM does not support sudo cache operations")

    def clear_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        raise NotImplementedError("WinRM does not support sudo cache operations")

    def upload_file(self, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, object]:
        raise NotImplementedError("WinRM file upload is not implemented")

    def download_file(self, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, object]:
        raise NotImplementedError("WinRM file download is not implemented")
