import io
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

import pytest

import bifrost_mcp.mcp_server as mcp_server
from bifrost_mcp.credentials import CredentialDecryptionFailed, CredentialMetadata, CredentialNotFound, CredentialRecord, CredentialStore, StoredSSHAuth
from bifrost_mcp.session import RemoteSessionHandler


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

    def send_input(self, text):
        self.last_sent = text

    def send_control(self, key):
        self.last_control = key

    def resize_session(self, width, height):
        self.last_resize = (width, height)

    def read_output(self):
        return "output"

    def flush_output_buffer(self):
        return "output"

    def wait_for_output(self, pattern, timeout, regex=True, clear_buffer=True):
        return {"status": "matched", "output": "output"}

    def run_command(self, command, timeout=30):
        return {"status": "completed", "stdout": "", "stderr": "", "exit_code": 0}

    def check_sudo_cache(self, timeout=10):
        return {"status": "ok"}

    def warm_sudo_cache(self, sudo_password, timeout=10):
        return {"status": "ok"}

    def clear_sudo_cache(self, timeout=10):
        return {"status": "ok"}

    def upload_file(self, local_path, remote_path, create_parents=False):
        return {"status": "ok"}

    def download_file(self, remote_path, local_path, create_parents=False):
        return {"status": "ok"}


class FakeStore:
    def __init__(self, auth=None, rows=None, sudo_password="sudo-secret", records=None):
        self.auth = auth
        self.rows = rows or []
        self.sudo_password = sudo_password
        self.records = records or {}
        self.stored = []
        self.removed = []
        self.auth_exc: Exception | None = None
        self.record_exc: Exception | None = None
        self.sudo_exc: Exception | None = None

    def resolve_ssh_auth(self, slug):
        if self.auth_exc is not None:
            raise self.auth_exc
        if self.auth is None:
            raise CredentialNotFound("No stored SSH credential exists for user@example.com")
        self.resolved_slug = slug
        return self.auth

    def resolve_sudo_password(self, slug):
        if self.sudo_exc is not None:
            raise self.sudo_exc
        self.sudo_slug = slug
        return self.sudo_password

    def get_record(self, slug, record_type):
        self.record_slug = slug
        self.record_type = record_type
        if self.record_exc is not None:
            raise self.record_exc
        if (slug, record_type) not in self.records:
            raise CredentialNotFound(f"No {record_type} credential record exists for {slug}")
        return self.records[(slug, record_type)]

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

    def record_exists(self, slug, record_type):
        return any(existing_slug == slug and existing_type == record_type for existing_slug, existing_type, _ in self.stored)


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



def test_create_ssh_session_decryption_failure_returns_structured_error():
    store = FakeStore()
    store.auth_exc = CredentialDecryptionFailed("unlock gpg")

    result = mcp_server._create_ssh_session_impl("example.com", "user", store=cast(CredentialStore, store))

    assert result["status"] == "error"
    assert result["error"]["code"] == "credential_decryption_failed"



def test_create_ssh_session_retries_once_after_unlock(monkeypatch):
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

    class RetryStore(FakeStore):
        def __init__(self):
            super().__init__()
            self.resolve_calls = 0

        def resolve_ssh_auth(self, slug):
            self.resolve_calls += 1
            self.resolved_slug = slug
            if self.resolve_calls == 1:
                raise CredentialDecryptionFailed("unlock gpg")
            return StoredSSHAuth(auth_type="password", secret="ssh-secret")

    monkeypatch.setattr(mcp_server, "SSHHandler", FakeSSHHandler)
    store = RetryStore()

    result = mcp_server._create_ssh_session_impl("Example.COM", "user", store=cast(CredentialStore, store))

    assert result["status"] == "created"
    assert store.unlocked == ("ssh://user@example.com", None)
    assert store.resolve_calls == 2
    assert opened["password"] == "ssh-secret"


def test_create_winrm_session_derives_slug_and_uses_password_record(monkeypatch):
    opened = {}

    class FakeWinRMHandler:
        transport = "winrm"

        def open_session(self, **kwargs):
            opened.update(kwargs)
            self.session_id = "winrm-sid"
            self.host = kwargs["host"]
            self.canonical_host = "example.com"
            self.username = kwargs["username"]
            self.port = kwargs["port"]
            self.created_at = time.monotonic()
            self.last_activity_at = self.created_at
            return "winrm-sid"

    monkeypatch.setattr(mcp_server, "WinRMHandler", FakeWinRMHandler)
    store = FakeStore(records={
        ("winrm://EXAMPLE\\user@example.com", "password"): CredentialRecord(
            slug="winrm://EXAMPLE\\user@example.com",
            record_type="password",
            secret="winrm-secret",
        )
    })

    result = mcp_server._create_winrm_session_impl("Example.COM", "EXAMPLE\\user", store=store)

    assert store.record_slug == "winrm://EXAMPLE\\user@example.com"
    assert opened["password"] == "winrm-secret"
    assert opened["auth"] == "ntlm"
    assert opened["use_ssl"] is False
    assert result == {
        "status": "created",
        "session_id": "winrm-sid",
        "transport": "winrm",
        "host": "example.com",
        "username": "EXAMPLE\\user",
        "port": 5985,
    }


def test_create_winrm_session_missing_credential_returns_structured_error():
    result = mcp_server._create_winrm_session_impl("example.com", "EXAMPLE\\user", store=FakeStore(records={}))

    assert result["status"] == "error"
    assert result["error"]["code"] == "missing_credential"


@pytest.mark.parametrize(
    "username",
    [
        "administrator@ad.byu.edu",
        "BYU\\administrator@ad.byu.edu",
        "\\administrator",
        "BYU\\",
        "BYU\\   ",
        "   \\administrator",
        "BYU\\extra\\administrator",
    ],
)
def test_create_winrm_session_rejects_invalid_username_before_credential_lookup(username):
    class LookupMustNotRunStore(FakeStore):
        def get_record(self, slug, record_type):
            raise AssertionError("credential lookup must not run for an invalid username")

    result = mcp_server._create_winrm_session_impl(
        "example.com",
        username,
        store=cast(CredentialStore, LookupMustNotRunStore()),
    )

    assert result["status"] == "error"
    assert result["error"]["code"] == "invalid_username"



def test_create_winrm_session_decryption_failure_returns_structured_error():
    store = FakeStore(records={})
    store.record_exc = CredentialDecryptionFailed("unlock gpg")

    result = mcp_server._create_winrm_session_impl("example.com", "EXAMPLE\\user", store=cast(CredentialStore, store))

    assert result["status"] == "error"
    assert result["error"]["code"] == "credential_decryption_failed"



def test_create_winrm_session_retries_once_after_unlock(monkeypatch):
    opened = {}

    class FakeWinRMHandler:
        transport = "winrm"

        def open_session(self, **kwargs):
            opened.update(kwargs)
            self.session_id = "winrm-sid"
            self.host = kwargs["host"]
            self.canonical_host = "example.com"
            self.username = kwargs["username"]
            self.port = kwargs["port"]
            self.created_at = time.monotonic()
            self.last_activity_at = self.created_at
            return "winrm-sid"

    class RetryStore(FakeStore):
        def __init__(self):
            super().__init__(records={})
            self.record_calls = 0

        def get_record(self, slug, record_type):
            self.record_calls += 1
            self.record_slug = slug
            self.record_type = record_type
            if self.record_calls == 1:
                raise CredentialDecryptionFailed("unlock gpg")
            return CredentialRecord(slug=slug, record_type=record_type, secret="winrm-secret")

    monkeypatch.setattr(mcp_server, "WinRMHandler", FakeWinRMHandler)
    store = RetryStore()

    result = mcp_server._create_winrm_session_impl("Example.COM", "EXAMPLE\\user", store=cast(CredentialStore, store))

    assert result["status"] == "created"
    assert store.unlocked == ("winrm://EXAMPLE\\user@example.com", "password")
    assert store.record_calls == 2
    assert opened["password"] == "winrm-secret"


def test_create_winrm_session_rejects_unsupported_auth_mode():
    result = mcp_server._create_winrm_session_impl(
        "example.com",
        "EXAMPLE\\user",
        auth="kerberos",
        store=FakeStore(records={}),
    )

    assert result["status"] == "error"
    assert result["error"]["code"] == "invalid_auth"


def test_winrm_impl_helpers_return_unsupported_operation_for_interactive_features():
    handler = FakeHandler("winrm-1")
    handler.transport = "winrm"
    mcp_server._sessions["winrm-1"] = handler

    assert mcp_server._send_input_impl("winrm-1", "dir\n")["error"]["code"] == "unsupported_operation"
    assert mcp_server._send_control_impl("winrm-1", "ctrl-c")["error"]["code"] == "unsupported_operation"
    assert mcp_server._resize_session_impl("winrm-1", 120, 40)["error"]["code"] == "unsupported_operation"
    assert mcp_server._read_output_impl("winrm-1")["error"]["code"] == "unsupported_operation"
    assert mcp_server._wait_for_output_impl("winrm-1", "ready", 5)["error"]["code"] == "unsupported_operation"
    assert mcp_server._check_sudo_cache_impl("winrm-1")["error"]["code"] == "unsupported_operation"
    assert mcp_server._warm_sudo_cache_impl("winrm-1")["error"]["code"] == "unsupported_operation"
    assert mcp_server._clear_sudo_cache_impl("winrm-1")["error"]["code"] == "unsupported_operation"
    assert mcp_server._upload_file_impl("winrm-1", "/tmp/a", "/tmp/b")["error"]["code"] == "unsupported_operation"
    assert mcp_server._download_file_impl("winrm-1", "/tmp/a", "/tmp/b")["error"]["code"] == "unsupported_operation"



def test_warm_sudo_cache_decryption_failure_returns_structured_error(monkeypatch):
    handler = FakeHandler("ssh-1")
    mcp_server._sessions["ssh-1"] = cast(RemoteSessionHandler, handler)

    class RaisingStore:
        def resolve_sudo_password(self, slug):
            raise CredentialDecryptionFailed("unlock gpg")

        def unlock_record(self, slug, record_type=None):
            raise CredentialDecryptionFailed("unlock gpg")

    monkeypatch.setattr(mcp_server, "CredentialStore", lambda: RaisingStore())

    result = mcp_server._warm_sudo_cache_impl("ssh-1")

    assert result["status"] == "error"
    assert result["error"]["code"] == "credential_decryption_failed"



def test_warm_sudo_cache_retries_once_after_unlock(monkeypatch):
    handler = FakeHandler("ssh-1")
    mcp_server._sessions["ssh-1"] = cast(RemoteSessionHandler, handler)

    class RetryStore:
        def __init__(self):
            self.calls = 0
            self.unlocked = None

        def resolve_sudo_password(self, slug):
            self.calls += 1
            if self.calls == 1:
                raise CredentialDecryptionFailed("unlock gpg")
            return "sudo-secret"

        def unlock_record(self, slug, record_type=None):
            self.unlocked = (slug, record_type)
            return {"status": "unlocked", "slug": slug, "record_type": record_type or "password"}

    store = RetryStore()
    monkeypatch.setattr(mcp_server, "CredentialStore", lambda: store)

    result = mcp_server._warm_sudo_cache_impl("ssh-1")

    assert result["status"] == "ok"
    assert store.unlocked == ("sudo://user@example.com", "password")
    assert store.calls == 2


def test_credential_cli_add_password_reads_piped_stdin(monkeypatch, capsys):
    args = mcp_server._build_parser().parse_args(["credential", "add", "  ssh://user@example.com  "])
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
    monkeypatch.setattr(mcp_server.getpass, "getpass", lambda prompt: "typed-secret" if prompt == "Credential password: " else "")

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert store.stored == [("ssh://user@example.com", "password", "typed-secret")]
    assert "typed-secret" not in capsys.readouterr().out


def test_credential_cli_add_ssh_password_on_tty_stores_matching_sudo_when_provided(monkeypatch, capsys):
    class TTYStdin:
        def isatty(self):
            return True

        def read(self):
            raise AssertionError("TTY password input should use getpass instead of blocking on stdin.read()")

    prompts = []
    secrets = iter(["typed-secret", "typed-sudo-secret"])
    args = mcp_server._build_parser().parse_args(["credential", "add", "ssh://user@example.com", "--password"])
    store = FakeStore()
    monkeypatch.setattr(sys, "stdin", TTYStdin())
    monkeypatch.setattr(
        mcp_server.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or next(secrets),
    )

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert prompts == ["Credential password: ", "Sudo Password (Leave blank for none): "]
    assert store.stored == [
        ("ssh://user@example.com", "password", "typed-secret"),
        ("sudo://user@example.com", "password", "typed-sudo-secret"),
    ]
    out = capsys.readouterr().out
    assert "typed-secret" not in out
    assert "typed-sudo-secret" not in out


def test_credential_cli_add_ssh_password_on_tty_skips_sudo_when_blank(monkeypatch, capsys):
    class TTYStdin:
        def isatty(self):
            return True

        def read(self):
            raise AssertionError("TTY password input should use getpass instead of blocking on stdin.read()")

    prompts = []
    secrets = iter(["typed-secret", ""])
    args = mcp_server._build_parser().parse_args(["credential", "add", "ssh://user@example.com", "--password"])
    store = FakeStore()
    monkeypatch.setattr(sys, "stdin", TTYStdin())
    monkeypatch.setattr(
        mcp_server.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or next(secrets),
    )

    rc = mcp_server._handle_credential_cli(args, store=store)

    assert rc == 0
    assert prompts == ["Credential password: ", "Sudo Password (Leave blank for none): "]
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



def test_credential_cli_list_defaults_to_table(capsys):
    rows = [
        CredentialMetadata("ssh://deploy@example.com", "ssh", "deploy", "example.com", has_password=True),
        CredentialMetadata("winrm://BYU\\admin@host.example.com", "winrm", "BYU\\admin", "host.example.com", has_password=True),
    ]
    args = mcp_server._build_parser().parse_args(["credential", "list"])
    store = FakeStore(rows=rows)

    rc = mcp_server._handle_credential_cli(args, store=cast(CredentialStore, store))

    assert rc == 0
    out = capsys.readouterr().out
    assert "Bifrost credentials:" in out
    assert "Purpose" in out
    assert "Records" in out
    assert "ssh://deploy@example.com" in out
    assert "winrm://BYU\\admin@host.example.com" in out



def test_credential_cli_list_json_preserves_machine_readable_output(capsys):
    rows = [CredentialMetadata("ssh://deploy@example.com", "ssh", "deploy", "example.com", has_password=True)]
    args = mcp_server._build_parser().parse_args(["credential", "list", "--json"])
    store = FakeStore(rows=rows)

    rc = mcp_server._handle_credential_cli(args, store=cast(CredentialStore, store))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["credentials"][0]["slug"] == "ssh://deploy@example.com"



def test_credential_cli_show_and_remove_strip_slug(capsys):
    show_args = mcp_server._build_parser().parse_args(["credential", "show", "  ssh://user@example.com  "])
    remove_args = mcp_server._build_parser().parse_args(["credential", "remove", "  ssh://user@example.com  ", "--password"])
    store = FakeStore()

    assert mcp_server._handle_credential_cli(show_args, store=cast(CredentialStore, store)) == 0
    assert json.loads(capsys.readouterr().out)["credential"]["slug"] == "ssh://user@example.com"
    assert mcp_server._handle_credential_cli(remove_args, store=cast(CredentialStore, store)) == 0
    assert store.removed == [("ssh://user@example.com", "password")]



def test_credential_cli_unlock_accepts_exact_slug(capsys):
    args = mcp_server._build_parser().parse_args(["credential", "unlock", "  ssh://user@example.com  "])
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



def test_credential_cli_unlock_auto_selects_deterministic_record(capsys):
    rows = [
        CredentialMetadata("winrm://BYU\\deploy@example.com", "winrm", "BYU\\deploy", "example.com", has_password=True),
        CredentialMetadata("ssh://deploy@example.com", "ssh", "deploy", "example.com", has_password=True),
    ]
    args = mcp_server._build_parser().parse_args(["credential", "unlock"])
    store = FakeStore(rows=rows)

    rc = mcp_server._handle_credential_cli(args, store=cast(CredentialStore, store))

    assert rc == 0
    assert store.unlocked == ("ssh://deploy@example.com", "password")
    payload = json.loads(capsys.readouterr().out)
    assert payload["slug"] == "ssh://deploy@example.com"


def test_credential_parser_accepts_winrm_purpose():
    list_args = mcp_server._build_parser().parse_args(["credential", "list", "--purpose", "winrm"])
    unlock_args = mcp_server._build_parser().parse_args(["credential", "unlock", "--purpose", "winrm"])

    assert list_args.purpose == "winrm"
    assert unlock_args.purpose == "winrm"


def test_create_server_uses_bifrost_name_and_does_not_import_legacy_app_package():
    legacy_module = "app" + ".main"
    sys.modules.pop("app", None)
    sys.modules.pop(legacy_module, None)

    server = mcp_server.create_server()

    assert type(server).__name__ == "FastMCP"
    assert getattr(server, "name", None) == "bifrost"
    assert legacy_module not in sys.modules


def test_server_exposes_only_generic_close_session_tool():
    tool_names = {tool.name for tool in mcp_server.create_server()._tool_manager.list_tools()}

    assert "close_session" in tool_names
    assert "close_ssh_session" not in tool_names
