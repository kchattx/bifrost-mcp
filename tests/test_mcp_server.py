import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

import bifrost_mcp.mcp_server as mcp_server
from bifrost_mcp.credentials import CredentialMetadata, CredentialNotFound, StoredSSHAuth


class FakeHandler:
    transport = "ssh"

    def __init__(self, session_id, close_raises=False):
        self.session_id = session_id
        self.host = "example.com"
        self.canonical_host = "example.com"
        self.username = "user"
        self.port = 22
        self.created_at = time.monotonic()
        self.last_activity_at = self.created_at
        self.closed = False
        self.close_raises = close_raises

    def close_session(self):
        self.closed = True
        if self.close_raises:
            raise RuntimeError("already closed")


class FakeStore:
    def __init__(self, auth=None, rows=None, sudo_password="sudo-secret"):
        self.auth = auth
        self.rows = rows or []
        self.sudo_password = sudo_password
        self.stored = []
        self.removed = []

    def resolve_ssh_auth(self, slug):
        if self.auth is None:
            raise CredentialNotFound("No stored SSH credential exists for user@example.com")
        self.resolved_slug = slug
        return self.auth

    def resolve_sudo_password(self, slug):
        self.sudo_slug = slug
        return self.sudo_password

    def list_metadata(self, host=None, user=None, purpose=None):
        rows = self.rows
        if host:
            rows = [row for row in rows if row.canonical_host == host]
        if user:
            rows = [row for row in rows if row.username == user]
        if purpose:
            rows = [row for row in rows if row.purpose == purpose]
        return rows

    def store_record(self, slug, record_type, secret):
        self.stored.append((slug, record_type, secret))
        return CredentialMetadata(slug=slug, purpose=slug.split(":", 1)[0], username="user", canonical_host="example.com", has_password=record_type == "password", has_key=record_type == "key")

    def show_metadata(self, slug):
        return CredentialMetadata(slug=slug, purpose=slug.split(":", 1)[0], username="user", canonical_host="example.com", has_password=True)

    def unlock_record(self, slug, record_type=None):
        self.unlocked = (slug, record_type)
        return {"status": "unlocked", "slug": slug, "record_type": record_type or "password"}

    def remove_record(self, slug, record_type):
        self.removed.append((slug, record_type))
        return CredentialMetadata(slug=slug, purpose=slug.split(":", 1)[0], username="user", canonical_host="example.com")


def teardown_function():
    mcp_server._sessions.clear()


def test_legacy_auth_inputs_are_rejected():
    with pytest.raises(ValueError, match="raw SSH auth inputs"):
        mcp_server._validate_auth_inputs("password", "secret", None, None)


def test_unsupported_operation_error_shape():
    result = mcp_server._unsupported_operation("resize_session", "winrm")

    assert result == {
        "status": "error",
        "error": {
            "code": "unsupported_operation",
            "message": "Operation resize_session is not supported for winrm sessions.",
        },
    }


def test_create_session_inputs_require_username_and_reject_legacy_fields():
    with pytest.raises(ValueError, match="requires username"):
        mcp_server._validate_create_session_inputs("example.com", "", 22)
    with pytest.raises(ValueError, match="password"):
        mcp_server._validate_create_session_inputs("example.com", "user", 22, password="secret")


def test_get_session_returns_active_matching_handler():
    handler = FakeHandler("session-1")
    mcp_server._sessions["session-1"] = handler

    assert mcp_server._get_session("session-1") is handler


def test_get_session_removes_stale_handler_and_raises():
    mcp_server._sessions["session-1"] = FakeHandler("different-session")

    with pytest.raises(ValueError, match="was not found"):
        mcp_server._get_session("session-1")

    assert "session-1" not in mcp_server._sessions


def test_cleanup_sessions_closes_matching_sessions_and_clears_registry():
    active = FakeHandler("active")
    already_closed = FakeHandler("already-closed", close_raises=True)
    stale = FakeHandler("different")
    mcp_server._sessions.update({"active": active, "already-closed": already_closed, "stale": stale})

    mcp_server._cleanup_sessions()

    assert active.closed is True
    assert already_closed.closed is True
    assert stale.closed is False
    assert mcp_server._sessions == {}


def test_list_credentials_groups_by_user_and_guidance():
    rows = [
        CredentialMetadata("ssh://alice@example.com", "ssh", "alice", "example.com", has_key=True),
        CredentialMetadata("sudo://alice@example.com", "sudo", "alice", "example.com", has_password=True),
        CredentialMetadata("ssh://deploy@example.com", "ssh", "deploy", "example.com", has_password=True),
    ]

    result = mcp_server._list_credentials_impl("Example.COM", store=FakeStore(rows=rows))

    assert result["status"] == "ok"
    assert result["host"] == "example.com"
    assert result["guidance"] == "multiple_users_choose_username"
    assert result["users"] == [
        {"username": "alice", "ssh": True, "sudo": True},
        {"username": "deploy", "ssh": True, "sudo": False},
    ]


def test_list_sessions_includes_transport():
    handler = FakeHandler("session-1")
    mcp_server._sessions["session-1"] = handler

    result = mcp_server._list_sessions_impl()

    assert result["sessions"][0]["transport"] == "ssh"


def test_create_ssh_session_derives_slug_and_does_not_expose_auth_type(monkeypatch):
    opened = {}

    class FakeSSHHandler:
        transport = "ssh"

        def open_session(self, **kwargs):
            opened.update(kwargs)
            self.session_id = "sid"
            self.host = kwargs["host"]
            self.canonical_host = "example.com"
            self.username = kwargs["username"]
            self.port = kwargs["port"]
            self.created_at = time.monotonic()
            self.last_activity_at = self.created_at
            return "sid"

    monkeypatch.setattr(mcp_server, "SSHHandler", FakeSSHHandler)
    store = FakeStore(auth=StoredSSHAuth(auth_type="password", secret="ssh-secret"))

    result = mcp_server._create_ssh_session_impl("Example.COM", "user", store=store)

    assert store.resolved_slug == "ssh://user@example.com"
    assert opened["password"] == "ssh-secret"
    assert result == {"status": "created", "session_id": "sid", "transport": "ssh", "host": "example.com", "username": "user", "port": 22}
    assert "password" not in result and "private_key" not in result and "auth_type" not in result


def test_create_ssh_session_missing_credential_returns_structured_error():
    result = mcp_server._create_ssh_session_impl("example.com", "user", store=FakeStore(auth=None))

    assert result["status"] == "error"
    assert result["error"]["code"] == "missing_credential"


def test_credential_cli_add_password_reads_piped_stdin(monkeypatch, capsys):
    args = mcp_server._build_parser().parse_args(["credential", "add", "ssh://user@example.com"])
    store = FakeStore()
    monkeypatch.setattr(sys, "stdin", io.StringIO("secret\n"))

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.stored == [("ssh://user@example.com", "password", "secret")]
    assert "secret" not in capsys.readouterr().out


def test_credential_cli_add_password_prompts_on_tty(monkeypatch, capsys):
    class TTYStdin:
        def isatty(self):
            return True

        def read(self):
            raise AssertionError("TTY password input should use getpass instead of blocking on stdin.read()")

    args = mcp_server._build_parser().parse_args(["credential", "add", "ssh://user@example.com", "--password"])
    store = FakeStore()
    monkeypatch.setattr(sys, "stdin", TTYStdin())
    monkeypatch.setattr(mcp_server.getpass, "getpass", lambda prompt: "typed-secret")

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.stored == [("ssh://user@example.com", "password", "typed-secret")]
    assert "typed-secret" not in capsys.readouterr().out


def test_credential_cli_add_key_reads_file(tmp_path):
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("PRIVATE KEY", encoding="utf-8")
    args = mcp_server._build_parser().parse_args(["credential", "add", "ssh://user@example.com", "--key", str(key_file)])
    store = FakeStore()

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.stored == [("ssh://user@example.com", "key", "PRIVATE KEY")]




def test_credential_cli_unlock_accepts_exact_slug(capsys):
    args = mcp_server._build_parser().parse_args(["credential", "unlock", "ssh://user@example.com"])
    store = FakeStore()

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.unlocked == ("ssh://user@example.com", "password")
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "unlocked"
    assert "secret" not in json.dumps(payload).lower()


def test_credential_cli_unlock_resolves_single_host_user_match(capsys):
    rows = [CredentialMetadata("ssh://deploy@example.com", "ssh", "deploy", "example.com", has_password=True)]
    args = mcp_server._build_parser().parse_args(["credential", "unlock", "--host", "Example.COM", "--user", "deploy"])
    store = FakeStore(rows=rows)

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.unlocked == ("ssh://deploy@example.com", "password")
    payload = json.loads(capsys.readouterr().out)
    assert payload["slug"] == "ssh://deploy@example.com"


def test_create_server_uses_bifrost_name_and_does_not_import_legacy_app_package():
    legacy_module = "app" + ".main"
    sys.modules.pop("app", None)
    sys.modules.pop(legacy_module, None)

    server = mcp_server.create_server()

    assert type(server).__name__ == "FastMCP"
    assert getattr(server, "name", None) == "bifrost"
    assert legacy_module not in sys.modules
