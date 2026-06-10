import os
import time
from pathlib import Path

import pytest

from bifrost_mcp.ssh_handler import SSHHandler


class FakeChannel:
    def __init__(self):
        self.closed = False
        self.sent = []
        self.resized = None

    def send(self, text):
        self.sent.append(text)

    def close(self):
        self.closed = True

    def recv_ready(self):
        return False

    def resize_pty(self, width, height):
        self.resized = (width, height)


class FakeSFTP:
    def __init__(self, existing=None):
        self.existing = set(existing or [])
        self.puts = []
        self.gets = []
        self.mkdirs = []
        self.closed = False

    def stat(self, path):
        if path not in self.existing:
            raise FileNotFoundError(path)
        return object()

    def mkdir(self, path):
        self.mkdirs.append(path)
        self.existing.add(path)

    def put(self, local, remote):
        self.puts.append((local, remote))
        self.existing.add(remote)

    def get(self, remote, local):
        self.gets.append((remote, local))
        Path(local).write_text("downloaded", encoding="utf-8")

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, sftp):
        self.sftp = sftp

    def open_sftp(self):
        return self.sftp


def active_handler():
    handler = SSHHandler()
    channel = FakeChannel()
    handler.session_id = "sid"
    handler.host = "Example.COM"
    handler.canonical_host = "example.com"
    handler.username = "user"
    handler.port = 22
    handler.created_at = time.monotonic()
    handler.last_activity_at = handler.created_at
    handler._channel = channel
    return handler, channel


def append_output(handler, text):
    with handler._lock:
        handler._buffer_chunks.append(text)


def test_metadata_defaults_and_touch_updates():
    handler, channel = active_handler()
    before = handler.last_activity_at
    time.sleep(0.001)

    handler.send_input("echo hi\n")

    assert handler.canonical_host == "example.com"
    assert channel.sent == ["echo hi\n"]
    assert handler.last_activity_at > before


def test_wait_for_output_regex_literal_and_timeout():
    handler, _ = active_handler()
    append_output(handler, "ready [ok]")

    matched = handler.wait_for_output(r"ready \[ok\]", timeout=0.1)
    assert matched["status"] == "matched"
    assert matched["output"] == "ready [ok]"
    assert handler.read_output() == ""

    append_output(handler, "a.b")
    literal = handler.wait_for_output("a.b", timeout=0.1, regex=False, clear_buffer=False)
    assert literal["status"] == "matched"
    assert handler.read_output() == "a.b"

    timed_out = handler.wait_for_output("missing", timeout=0.01)
    assert timed_out["status"] == "timeout"
    assert timed_out["output"] == "a.b"


def test_run_command_sends_command_sentinel_and_parses_exit(monkeypatch):
    handler, channel = active_handler()
    original_wait = handler.wait_for_output

    def fake_wait(pattern, timeout, regex=True, clear_buffer=True):
        sent = "".join(channel.sent)
        sentinel = sent.split("printf '\\n", 1)[1].split(":%s", 1)[0]
        return {"status": "matched", "session_id": "sid", "pattern": pattern, "output": f"hello\n{sentinel}:7\n"}

    monkeypatch.setattr(handler, "wait_for_output", fake_wait)

    result = handler.run_command("echo hello", timeout=1)

    assert "echo hello" in channel.sent[0]
    assert "__BIFROST_MCP_CMD_DONE_" in channel.sent[0]
    assert result["status"] == "completed"
    assert result["exit_code"] == 7
    assert "__BIFROST_MCP_CMD_DONE_" not in result["output"]


def test_run_command_timeout_leaves_command_running(monkeypatch):
    handler, channel = active_handler()
    monkeypatch.setattr(handler, "wait_for_output", lambda *a, **k: {"status": "timeout", "session_id": "sid", "pattern": "x", "output": "partial"})

    result = handler.run_command("sleep 99", timeout=0.1)

    assert result == {"status": "timeout", "session_id": "sid", "output": "partial"}
    assert "\x03" not in "".join(channel.sent)


def test_sudo_helpers_use_expected_commands(monkeypatch):
    handler, channel = active_handler()
    monkeypatch.setattr(handler, "run_command", lambda command, timeout=10: {"status": "completed", "exit_code": 0, "output": ""})

    assert handler.check_sudo_cache()["status"] == "warm"
    assert handler.clear_sudo_cache()["status"] == "cleared"

    monkeypatch.setattr(handler, "wait_for_output", lambda *a, **k: {"status": "matched", "output": "__BIFROST_MCP_SUDO_OK__"})
    result = handler.warm_sudo_cache("secret")
    assert result == {"status": "warmed", "session_id": "sid"}
    assert any("sudo -S" in item and "sudo -i" not in item for item in channel.sent)
    assert "secret" not in str(result)


def test_send_control_and_resize():
    handler, channel = active_handler()

    handler.send_control("ctrl-c")
    handler.resize_session(120, 40)

    assert channel.sent[-1] == "\x03"
    assert channel.resized == (120, 40)
    with pytest.raises(ValueError, match="Allowed values"):
        handler.send_control("Ctrl+C")
    with pytest.raises(ValueError, match="width"):
        handler.resize_session(1, 1)


def test_upload_file_sftp_no_overwrite_and_closes(tmp_path):
    handler, _ = active_handler()
    sftp = FakeSFTP(existing={"/tmp"})
    handler._client = FakeClient(sftp)
    local = tmp_path / "payload.txt"
    local.write_text("payload", encoding="utf-8")

    result = handler.upload_file(str(local), "/tmp/payload.txt")

    assert result["status"] == "uploaded"
    assert sftp.puts == [(str(local), "/tmp/payload.txt")]
    assert sftp.closed is True

    sftp2 = FakeSFTP(existing={"/tmp/payload.txt"})
    handler._client = FakeClient(sftp2)
    result = handler.upload_file(str(local), "/tmp/payload.txt")
    assert result["error"]["code"] == "file_exists"
    assert sftp2.puts == []


def test_download_file_requires_full_destination_and_can_create_parents(tmp_path):
    handler, _ = active_handler()
    sftp = FakeSFTP(existing={"/remote/file"})
    handler._client = FakeClient(sftp)

    result = handler.download_file("/remote/file", str(tmp_path / "missing" / "file.txt"), create_parents=True)

    assert result["status"] == "downloaded"
    assert sftp.gets == [("/remote/file", str(tmp_path / "missing" / "file.txt"))]
    assert sftp.closed is True

    result = handler.download_file("/remote/file", str(tmp_path), create_parents=True)
    assert result["error"]["code"] == "local_path_is_directory"
