import json
import subprocess
from pathlib import Path

from bifrost_mcp.mcp_server import _build_doctor_report, _build_parser, _handle_doctor_cli


class FakeStore:
    def __init__(self, rows=None):
        self.rows = rows or []

    def list_metadata(self, host=None, user=None, purpose=None):
        rows = self.rows
        if host:
            rows = [row for row in rows if row.canonical_host == host]
        if user:
            rows = [row for row in rows if row.to_dict()["username"] == user]
        if purpose:
            rows = [row for row in rows if row.to_dict()["purpose"] == purpose]
        return rows

    def unlock_record(self, slug, record_type=None):
        self.unlocked = (slug, record_type)
        return {"status": "unlocked", "slug": slug, "record_type": record_type or "password"}


class FakeMetadata:
    def __init__(self, slug="ssh://user@example.com", canonical_host="example.com"):
        self.slug = slug
        self.canonical_host = canonical_host
        self.purpose = "ssh"
        self.username = "user"
        self.has_password = True
        self.has_key = False

    def to_dict(self):
        return {
            "slug": self.slug,
            "purpose": self.purpose,
            "username": self.username,
            "canonical_host": self.canonical_host,
            "has_password": self.has_password,
            "has_key": self.has_key,
        }


def test_doctor_detects_profile_home_mismatch_and_recommends_explicit_env(tmp_path):
    home = tmp_path / ".hermes" / "profiles" / "lseng" / "home"
    real_home = tmp_path / "real-home"
    home.mkdir(parents=True)
    real_home.mkdir()

    report = _build_doctor_report(
        env={"HOME": str(home)},
        store=FakeStore(),
        command_exists=lambda name: name == "gopass",
        run_command=lambda args, **kwargs: subprocess.CompletedProcess(args, 6, "", "password-store is not initialized"),
        real_home_hint=str(real_home),
    )

    assert report["status"] == "needs_attention"
    assert report["checks"]["home"]["profile_scoped"] is True
    assert "mcp_servers.bifrost.env.HOME" in report["recommendations"]
    assert str(real_home) in report["recommendations"]["mcp_servers.bifrost.env.HOME"]
    assert "typed-secret" not in json.dumps(report)
    assert "PRIVATE KEY" not in json.dumps(report)


def test_doctor_reports_gopass_decrypt_failure_without_leaking_secret(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    index = home / ".config" / "bifrost_mcp" / "credentials.json"
    index.parent.mkdir(parents=True)
    index.write_text("{}", encoding="utf-8")

    def run_command(args, **kwargs):
        if args[:2] == ["gopass", "ls"]:
            return subprocess.CompletedProcess(args, 0, "gopass\n", "")
        if args[:2] == ["gopass", "show"]:
            return subprocess.CompletedProcess(args, 11, "", "gpg: decryption failed: No such file or directory\n")
        if args[:2] == ["gpg", "--list-secret-keys"]:
            return subprocess.CompletedProcess(args, 0, "sec rsa2048/ABCDEF\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    report = _build_doctor_report(
        env={"HOME": str(home), "GNUPGHOME": str(home / ".gnupg")},
        store=FakeStore([FakeMetadata()]),
        command_exists=lambda name: name in {"gopass", "gpg", "pinentry-curses"},
        run_command=run_command,
    )

    assert report["status"] == "needs_attention"
    assert report["checks"]["gopass_decrypt"]["ok"] is False
    assert report["checks"]["gopass_decrypt"]["error_code"] == "decrypt_failed"
    assert "unlock_gpg_agent" in report["recommendations"]
    serialized = json.dumps(report)
    assert "PRIVATE KEY" not in serialized
    assert "password" not in report["checks"]["gopass_decrypt"].get("stdout", "")


def test_doctor_cli_outputs_json_without_secret_values(capsys, tmp_path):
    args = _build_parser().parse_args(["doctor"])
    rc = _handle_doctor_cli(
        args,
        env={"HOME": str(tmp_path)},
        store=FakeStore(),
        command_exists=lambda name: False,
        run_command=lambda args, **kwargs: subprocess.CompletedProcess(args, 127, "", "not found"),
    )

    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "needs_attention"
    assert payload["checks"]["gopass"]["found"] is False


def test_doctor_unlock_attempts_safe_unlock_when_requested(capsys, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    rows = [FakeMetadata("ssh://user@example.com", "example.com")]
    store = FakeStore(rows)
    args = _build_parser().parse_args(["doctor", "--unlock"])

    rc = _handle_doctor_cli(
        args,
        env={"HOME": str(home)},
        store=store,
        command_exists=lambda name: name in {"gopass", "gpg"},
        run_command=lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "ok", ""),
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["unlock"]["attempted"] is True
    assert payload["unlock"]["ok"] is True
    assert store.unlocked == ("ssh://user@example.com", "password")
    serialized = json.dumps(payload)
    assert "typed-secret" not in serialized
    assert "PRIVATE KEY" not in serialized
