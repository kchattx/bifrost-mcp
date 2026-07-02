import json
import subprocess

import pytest

from bifrost_mcp.credentials import (
    CredentialDecryptionFailed,
    CredentialNotFound,
    CredentialRecordExists,
    CredentialStore,
    CredentialValidationError,
    build_slug,
    canonicalize_host,
    parse_slug,
)


class FakeRunner:
    def __init__(self):
        self.records = {}
        self.calls = []

    def __call__(self, args, input=None, capture_output=True, text=True):
        self.calls.append((list(args), input))
        command = args[1]
        path = args[-1]
        if command == "show":
            if path not in self.records:
                return subprocess.CompletedProcess(args, 1, "", "not found")
            record = self.records[path]
            if isinstance(record, subprocess.CompletedProcess):
                return record
            return subprocess.CompletedProcess(args, 0, record, "")
        if command == "insert":
            self.records[path] = input
            return subprocess.CompletedProcess(args, 0, "", "")
        if command == "rm":
            if path not in self.records:
                return subprocess.CompletedProcess(args, 1, "", "not found")
            del self.records[path]
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_slug_round_trip_and_canonical_host():
    canonical = canonicalize_host(" Example.COM ", 2222)
    slug = build_slug("ssh", "alice", canonical)
    parsed = parse_slug(slug)

    assert canonical == "example.com:2222"
    assert slug == "ssh://alice@example.com:2222"
    assert parsed.purpose == "ssh"
    assert parsed.username == "alice"
    assert parsed.canonical_host == "example.com:2222"
    assert canonicalize_host("Example.COM") == "example.com"


def test_winrm_slug_round_trip_and_password_storage(tmp_path):
    canonical = canonicalize_host(" Example.COM ")
    slug = build_slug("winrm", "alice", canonical)
    parsed = parse_slug(slug)
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")

    metadata = store.store_record(slug, "password", "winrm-secret")

    assert slug == "winrm://alice@example.com"
    assert parsed.purpose == "winrm"
    assert metadata.purpose == "winrm"
    assert metadata.has_password is True


@pytest.mark.parametrize("slug", ["http://u@example.com", "ssh://@example.com", "ssh://u@", "not-a-slug"])
def test_invalid_slugs_are_rejected(slug):
    with pytest.raises((CredentialValidationError, ValueError)):
        parse_slug(slug)


def test_store_record_uses_gopass_insert_and_refuses_overwrite(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(
        runner=runner,
        index_path=tmp_path / "credentials.json",
        password_store_dir=tmp_path / "password-store",
    )

    metadata = store.store_record("ssh://user@example.com", "password", "secret")

    assert metadata.has_password is True
    assert any(call[0][0:3] == ["gopass", "insert", "-m"] for call in runner.calls)
    record_path = store._record_path("ssh://user@example.com", "password")
    assert (tmp_path / "password-store" / record_path).parent.is_dir()
    assert "secret" not in metadata.to_dict().values()
    with pytest.raises(CredentialRecordExists):
        store.store_record("ssh://user@example.com", "password", "new-secret")


def test_get_record_validates_json_and_exact_lookup(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    store.store_record("ssh://user@example.com", "password", "secret")

    record = store.get_record("ssh://user@example.com", "password")

    assert record.secret == "secret"
    with pytest.raises(CredentialNotFound):
        store.get_record("ssh://other@example.com", "password")



def test_get_record_surfaces_decryption_failures_separately(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    path = store._record_path("ssh://user@example.com", "password")
    runner.records[path] = subprocess.CompletedProcess(["gopass", "show", path], 2, "", "Error: exit status 2.")

    with pytest.raises(CredentialDecryptionFailed, match="Failed to decrypt password credential record"):
        store.get_record("ssh://user@example.com", "password")


def test_malformed_records_fail_clearly(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    path = store._record_path("ssh://user@example.com", "password")
    runner.records[path] = json.dumps({"type": "key", "secret": "secret"})

    with pytest.raises(CredentialValidationError, match="mismatched type"):
        store.get_record("ssh://user@example.com", "password")

    runner.records[path] = json.dumps({"type": "password", "secret": ""})
    with pytest.raises(CredentialValidationError, match="blank secret"):
        store.get_record("ssh://user@example.com", "password")


def test_resolve_ssh_auth_prefers_key_and_falls_back_to_password(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    store.store_record("ssh://user@example.com", "password", "password-secret")

    assert store.resolve_ssh_auth("ssh://user@example.com").auth_type == "password"
    store.store_record("ssh://user@example.com", "key", "key-secret")
    auth = store.resolve_ssh_auth("ssh://user@example.com")

    assert auth.auth_type == "key"
    assert auth.secret == "key-secret"


def test_sudo_rejects_key_and_requires_password(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")

    with pytest.raises(CredentialValidationError, match="password records only"):
        store.store_record("sudo://user@example.com", "key", "KEY")
    with pytest.raises(CredentialNotFound):
        store.resolve_sudo_password("sudo://user@example.com")

    store.store_record("sudo://user@example.com", "password", "sudo-secret")
    assert store.resolve_sudo_password("sudo://user@example.com") == "sudo-secret"


def test_metadata_filters_exclude_secrets(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    store.store_record("ssh://user@example.com", "password", "secret")
    store.store_record("sudo://user@example.com", "password", "sudo-secret")

    rows = store.list_metadata(host="example.com", user="user", purpose="ssh")

    assert len(rows) == 1
    assert rows[0].to_dict() == {
        "slug": "ssh://user@example.com",
        "purpose": "ssh",
        "username": "user",
        "canonical_host": "example.com",
        "has_password": True,
        "has_key": False,
    }
    assert "secret" not in json.dumps([row.to_dict() for row in store.list_metadata()])



def test_list_and_show_prune_stale_index_entries_when_backing_record_is_missing(tmp_path):
    runner = FakeRunner()
    password_store_dir = tmp_path / "password-store"
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json", password_store_dir=password_store_dir)
    slug = "ssh://user@example.com"

    store.store_record(slug, "password", "secret")
    record_file = (password_store_dir / store._record_path(slug, "password")).with_suffix(".gpg")
    record_file.parent.mkdir(parents=True, exist_ok=True)
    record_file.write_text("ciphertext", encoding="utf-8")
    record_file.unlink()
    runner.records.pop(store._record_path(slug, "password"))

    assert store.list_metadata() == []
    with pytest.raises(CredentialNotFound, match="No credential metadata exists"):
        store.show_metadata(slug)
    assert json.loads((tmp_path / "credentials.json").read_text(encoding="utf-8")) == {}



def test_remove_record_prunes_stale_index_entries_when_gopass_record_is_already_gone(tmp_path):
    runner = FakeRunner()
    password_store_dir = tmp_path / "password-store"
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json", password_store_dir=password_store_dir)
    slug = "ssh://user@example.com"

    metadata = store.store_record(slug, "password", "secret")
    record_file = (password_store_dir / store._record_path(slug, "password")).with_suffix(".gpg")
    record_file.parent.mkdir(parents=True, exist_ok=True)
    record_file.write_text("ciphertext", encoding="utf-8")
    record_file.unlink()
    runner.records.pop(store._record_path(slug, "password"))

    removed = store.remove_record(slug, "password")

    assert removed.slug == metadata.slug
    assert removed.has_password is False
    assert removed.has_key is False
    assert store.list_metadata() == []
    assert json.loads((tmp_path / "credentials.json").read_text(encoding="utf-8")) == {}
