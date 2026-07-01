from __future__ import annotations

import io
import logging
import os
import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Deque, Literal
from uuid import uuid4

from bifrost_mcp.credentials import canonicalize_host

try:
    import paramiko
except ImportError:
    paramiko = None

if TYPE_CHECKING:
    from paramiko import Channel, PKey, SSHClient


logger = logging.getLogger(__name__)

AuthMode = Literal["password", "inline_key", "key"]

_CONTROL_BYTES = {
    "ctrl-c": "\x03",
    "ctrl-d": "\x04",
    "ctrl-z": "\x1a",
    "enter": "\n",
    "escape": "\x1b",
}


class _PersistingAutoAddPolicy(paramiko.MissingHostKeyPolicy if paramiko is not None else object):
    def __init__(self, known_hosts_path: Path) -> None:
        self._known_hosts_path = known_hosts_path

    def missing_host_key(self, client: SSHClient, hostname: str, key: PKey) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(self._known_hosts_path))


class SSHHandler:
    transport = "ssh"
    _READ_CHUNK_SIZE = 4096
    _CLOSE_TIMEOUT_SECONDS = 5
    _HOST_KEY_POLICY = "accept-new"
    _KNOWN_HOSTS_FILENAME = "bifrost_mcp_known_hosts"

    def __init__(self) -> None:
        self.session_id: str | None = None
        self.host: str | None = None
        self.canonical_host: str | None = None
        self.username: str | None = None
        self.port: int | None = None
        self.created_at: float | None = None
        self.last_activity_at: float | None = None
        self._buffer_chunks: Deque[str] = deque()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._reader_thread: threading.Thread | None = None
        self._client: SSHClient | None = None
        self._channel: Channel | None = None

    @property
    def out_buffer(self) -> str:
        with self._lock:
            return "".join(self._buffer_chunks)

    def open_session(
        self,
        host: str,
        username: str,
        port: int = 22,
        auth_mode: AuthMode = "password",
        password: str | None = None,
        private_key: str | None = None,
        private_key_passphrase: str | None = None,
    ) -> str:
        with self._lock:
            if self._has_active_session_locked():
                raise RuntimeError("An SSH session is already active.")

        canonical_host = canonicalize_host(host, port)
        known_hosts_path = self._ensure_known_hosts_path()
        logger.info("Opening Paramiko SSH session to %s@%s:%s.", username, host, port)

        client = self._create_client(known_hosts_path)
        connect_kwargs: dict[str, object] = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": self._CLOSE_TIMEOUT_SECONDS,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if auth_mode == "password":
            connect_kwargs["password"] = password
        elif auth_mode in ("inline_key", "key"):
            connect_kwargs["pkey"] = self._load_private_key(
                private_key=private_key,
                passphrase=private_key_passphrase,
            )
        else:
            client.close()
            raise ValueError("auth_mode must be 'password' or 'key'")

        try:
            client.connect(**connect_kwargs)
            channel = client.invoke_shell(width=200, height=50)
        except Exception as exc:
            client.close()
            raise RuntimeError(f"Paramiko SSH connection failed: {exc}") from exc

        session_id = str(uuid4())
        reader_thread = threading.Thread(
            target=self._paramiko_reader_loop,
            args=(channel,),
            name=f"ssh-reader-{session_id}",
            daemon=True,
        )
        now = time.monotonic()
        with self._lock:
            self._buffer_chunks.clear()
            self._stop_event.clear()
            self.session_id = session_id
            self.host = host
            self.canonical_host = canonical_host
            self.username = username
            self.port = port
            self.created_at = now
            self.last_activity_at = now
            self._client = client
            self._channel = channel
            self._reader_thread = reader_thread

        reader_thread.start()
        return session_id

    @classmethod
    def validate_runtime_dependencies(cls) -> None:
        if paramiko is None:
            raise RuntimeError("Bifrost MCP requires the 'paramiko' package to be installed.")
        known_hosts_path = cls._ensure_known_hosts_path()
        logger.info("Bifrost MCP Paramiko transport enabled with host-key policy %s at %s.", cls._HOST_KEY_POLICY, known_hosts_path)

    def close_session(self) -> None:
        with self._lock:
            channel = self._channel
            client = self._client
            reader_thread = self._reader_thread
            if channel is None:
                self._reset_process_state_locked(clear_metadata=False)
                raise RuntimeError("No active SSH session is open.")
            if channel.closed:
                self._reset_process_state_locked(clear_metadata=False)
                raise RuntimeError("No active SSH session is open.")
            self._stop_event.set()
            self._touch_locked()

        channel.close()
        if client is not None:
            client.close()
        if reader_thread is not None:
            reader_thread.join(timeout=self._CLOSE_TIMEOUT_SECONDS)

        with self._lock:
            self._reset_process_state_locked(clear_metadata=False)

    def send_input(self, text: str) -> None:
        with self._lock:
            channel = self._get_active_channel_locked()
            self._touch_locked()
        if channel is None:
            raise RuntimeError("The SSH session stdin is not available.")
        try:
            channel.sendall(text.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Failed to send SSH session input: {exc}") from exc

    def read_output(self) -> str:
        with self._lock:
            self._touch_locked()
            return "".join(self._buffer_chunks)

    def flush_output_buffer(self) -> str:
        with self._lock:
            output = "".join(self._buffer_chunks)
            self._buffer_chunks.clear()
            self._touch_locked()
            return output

    def wait_for_output(self, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        compiled = re.compile(pattern) if regex else None
        while True:
            with self._lock:
                output = "".join(self._buffer_chunks)
                matched = bool(compiled.search(output)) if compiled is not None else pattern in output
                if matched:
                    if clear_buffer:
                        self._buffer_chunks.clear()
                    self._touch_locked()
                    return {"status": "matched", "session_id": self.session_id, "pattern": pattern, "output": output}
                if time.monotonic() >= deadline:
                    if clear_buffer:
                        self._buffer_chunks.clear()
                    self._touch_locked()
                    return {"status": "timeout", "session_id": self.session_id, "pattern": pattern, "output": output}
            time.sleep(0.05)

    def run_command(self, command: str, timeout: float = 30) -> dict[str, object]:
        sentinel = f"__BIFROST_MCP_CMD_DONE_{uuid4().hex}__"
        self.flush_output_buffer()
        self.send_input(f"{command}\nprintf '\\n{sentinel}:%s\\n' $?\n")
        result = self.wait_for_output(re.escape(sentinel) + r":(\d+)", timeout=timeout, regex=True, clear_buffer=True)
        output = str(result["output"])
        match = re.search(re.escape(sentinel) + r":(\d+)", output)
        cleaned = re.sub(rf"^.*{re.escape(sentinel)}:\d+\r?\n?", "", output, flags=re.MULTILINE)
        if result["status"] == "timeout" or match is None:
            return {"status": "timeout", "session_id": self.session_id, "output": cleaned}
        return {"status": "completed", "session_id": self.session_id, "exit_code": int(match.group(1)), "output": cleaned}

    def check_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        result = self.run_command("sudo -n -v", timeout=timeout)
        if result["status"] == "timeout":
            return {"status": "timeout", "session_id": self.session_id, "output": result.get("output", "")}
        exit_code = result.get("exit_code")
        output = str(result.get("output", ""))
        if exit_code == 0:
            return {"status": "warm", "session_id": self.session_id}
        lowered = output.lower()
        if "password" in lowered or "a password is required" in lowered or exit_code in (1, 5):
            return {"status": "needs_password", "session_id": self.session_id, "output": output}
        return {"status": "failed", "session_id": self.session_id, "exit_code": exit_code, "output": output}

    def warm_sudo_cache(self, sudo_password: str, timeout: float = 10) -> dict[str, object]:
        self.flush_output_buffer()
        command = "sudo -S -p '[bifrost-mcp sudo password] ' -v && printf '\\n__BIFROST_MCP_SUDO_OK__\\n' || printf '\\n__BIFROST_MCP_SUDO_FAILED__\\n'"
        self.send_input(command + "\n")
        self.send_input(sudo_password + "\n")
        result = self.wait_for_output(r"__BIFROST_MCP_SUDO_(OK|FAILED)__", timeout=timeout, regex=True, clear_buffer=True)
        output = str(result.get("output", "")).replace(sudo_password, "[redacted]")
        if result["status"] == "timeout":
            return {"status": "timeout", "session_id": self.session_id, "output": output}
        if "__BIFROST_MCP_SUDO_OK__" in output:
            return {"status": "warmed", "session_id": self.session_id}
        lowered = output.lower()
        status = "bad_password" if "sorry" in lowered or "incorrect" in lowered or "try again" in lowered else "failed"
        return {"status": status, "session_id": self.session_id, "output": output}

    def clear_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        result = self.run_command("sudo -k", timeout=timeout)
        if result["status"] == "timeout":
            return {"status": "timeout", "session_id": self.session_id, "output": result.get("output", "")}
        if result.get("exit_code") == 0:
            return {"status": "cleared", "session_id": self.session_id}
        return {"status": "failed", "session_id": self.session_id, "exit_code": result.get("exit_code"), "output": result.get("output", "")}

    def send_control(self, key: str) -> None:
        if key not in _CONTROL_BYTES:
            allowed = ", ".join(sorted(_CONTROL_BYTES))
            raise ValueError(f"Unsupported control key '{key}'. Allowed values: {allowed}")
        self.send_input(_CONTROL_BYTES[key])

    def resize_session(self, width: int, height: int) -> None:
        if width < 20 or width > 500 or height < 5 or height > 200:
            raise ValueError("width must be 20-500 columns and height must be 5-200 rows")
        with self._lock:
            channel = self._get_active_channel_locked()
            self._touch_locked()
        if channel is None:
            raise RuntimeError("The SSH session channel is not available.")
        channel.resize_pty(width=width, height=height)

    def upload_file(self, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, object]:
        local = Path(local_path)
        if not local.is_file():
            return {"status": "error", "error": {"code": "local_file_missing", "message": f"Local file does not exist: {local_path}"}}
        sftp = self._open_sftp()
        try:
            if self._remote_exists(sftp, remote_path):
                return {"status": "error", "error": {"code": "file_exists", "message": f"Remote destination already exists: {remote_path}"}}
            parent = os.path.dirname(remote_path)
            if parent:
                if create_parents:
                    self._mkdir_remote_parents(sftp, parent)
                elif not self._remote_exists(sftp, parent):
                    return {"status": "error", "error": {"code": "missing_parent", "message": f"Remote parent directory does not exist: {parent}"}}
            sftp.put(str(local), remote_path)
            return {"status": "uploaded", "session_id": self.session_id, "local_path": str(local), "remote_path": remote_path}
        finally:
            sftp.close()

    def download_file(self, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, object]:
        local = Path(local_path)
        if local.exists() and local.is_dir():
            return {"status": "error", "error": {"code": "local_path_is_directory", "message": "download_file local_path must be a full destination file path"}}
        if local.exists():
            return {"status": "error", "error": {"code": "file_exists", "message": f"Local destination already exists: {local_path}"}}
        if create_parents:
            local.parent.mkdir(parents=True, exist_ok=True)
        elif not local.parent.exists():
            return {"status": "error", "error": {"code": "missing_parent", "message": f"Local parent directory does not exist: {local.parent}"}}
        sftp = self._open_sftp()
        try:
            sftp.get(remote_path, str(local))
            return {"status": "downloaded", "session_id": self.session_id, "remote_path": remote_path, "local_path": str(local)}
        finally:
            sftp.close()

    def _open_sftp(self):
        with self._lock:
            client = self._client
            self._touch_locked()
        if client is None:
            raise RuntimeError("No active SSH client is available for SFTP.")
        return client.open_sftp()

    def _remote_exists(self, sftp, path: str) -> bool:
        try:
            sftp.stat(path)
            return True
        except Exception:
            return False

    def _mkdir_remote_parents(self, sftp, path: str) -> None:
        if not path or path == "/":
            return
        parts = path.strip("/").split("/")
        current = "/" if path.startswith("/") else ""
        for part in parts:
            current = os.path.join(current, part) if current else part
            if not self._remote_exists(sftp, current):
                sftp.mkdir(current)

    def _paramiko_reader_loop(self, channel: Channel) -> None:
        while not self._stop_event.is_set():
            if channel.closed:
                break
            if not channel.recv_ready():
                time.sleep(0.05)
                continue
            try:
                chunk = channel.recv(self._READ_CHUNK_SIZE)
            except Exception:
                break
            if not chunk:
                break
            decoded_chunk = chunk.decode("utf-8", errors="replace")
            with self._lock:
                self._buffer_chunks.append(decoded_chunk)
                self._touch_locked()
        with self._lock:
            if self._channel is channel:
                self._client = None
                self._channel = None
                self._reader_thread = None
                self.session_id = None

    def _get_active_channel_locked(self) -> Channel | None:
        channel = self._channel
        if channel is None:
            return None
        if channel.closed:
            self._reset_process_state_locked(clear_metadata=False)
            raise RuntimeError("No active SSH session is open.")
        return channel

    def _has_active_session_locked(self) -> bool:
        channel = self._channel
        if channel is None:
            return False
        if channel.closed:
            self._reset_process_state_locked(clear_metadata=False)
            return False
        return True

    def _create_client(self, known_hosts_path: Path) -> SSHClient:
        if paramiko is None:
            raise FileNotFoundError("Paramiko SSH support is not installed.")
        client = paramiko.SSHClient()
        client.load_host_keys(str(known_hosts_path))
        client.set_missing_host_key_policy(_PersistingAutoAddPolicy(known_hosts_path))
        return client

    def _load_private_key(self, private_key: str | None, passphrase: str | None) -> PKey:
        if paramiko is None:
            raise FileNotFoundError("Paramiko SSH support is not installed.")
        if private_key is None:
            raise RuntimeError("Key auth requires private key content.")
        key_types = tuple(
            key_type
            for key_type in (
                getattr(paramiko, "Ed25519Key", None),
                getattr(paramiko, "RSAKey", None),
                getattr(paramiko, "ECDSAKey", None),
                getattr(paramiko, "DSSKey", None),
            )
            if key_type is not None
        )
        last_error: Exception | None = None
        for key_type in key_types:
            try:
                return key_type.from_private_key(io.StringIO(private_key), password=passphrase)
            except Exception as exc:
                last_error = exc
        detail = str(last_error) if last_error is not None else "unsupported private key format"
        raise RuntimeError(f"Failed to load private key: {detail}")

    @classmethod
    def _ensure_known_hosts_path(cls) -> Path:
        ssh_dir = Path.home() / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        known_hosts_path = ssh_dir / cls._KNOWN_HOSTS_FILENAME
        known_hosts_path.touch(exist_ok=True)
        return known_hosts_path

    def _touch_locked(self) -> None:
        self.last_activity_at = time.monotonic()

    def _reset_process_state_locked(self, *, clear_metadata: bool = True) -> None:
        self.session_id = None
        self._client = None
        self._channel = None
        self._reader_thread = None
        self._stop_event.clear()
        if clear_metadata:
            self.host = None
            self.canonical_host = None
            self.username = None
            self.port = None
            self.created_at = None
            self.last_activity_at = None
