import json
import subprocess

import pytest

from bifrost_mcp.credentials import (
    CredentialDecryptionFailed,
    DefaultCredential,
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
        if command == "ls":
            return subprocess.CompletedProcess(args, 0, "\n".join(sorted(self.records)), "")
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


def test_get_record_treats_gopass_missing_entry_error_as_not_found(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    path = store._record_path("ssh://user@example.com", "password")
    runner.records[path] = subprocess.CompletedProcess(
        ["gopass", "show", path],
        11,
        "",
        'Error: failed to retrieve secret "bifrost_mcp/example/password": entry is not in the password store',
    )

    with pytest.raises(CredentialNotFound, match="No password credential record exists"):
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


def test_default_credential_resolves_for_ssh_winrm_and_sudo_without_a_host(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")

    saved = store.set_default_credential("EXAMPLE\\admin", password="password-secret", ssh_key="key-secret")

    assert saved == DefaultCredential(username="EXAMPLE\\admin", has_password=True, has_ssh_key=True)
    assert store.get_default_credential() == saved
    assert store.resolve_default_ssh_auth().auth_type == "key"
    assert store.resolve_default_winrm_password() == "password-secret"
    assert store.resolve_default_sudo_password() == "password-secret"


def test_default_credential_can_be_materialized_once_for_a_successful_host_connection(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    store.set_default_credential("user", password="password-secret", ssh_key=None)

    attached = store.attach_default_credential("ssh", "user", "example.com")

    assert attached.slug == "ssh://user@example.com"
    assert attached.has_password is True
    assert store.resolve_ssh_auth("ssh://user@example.com").secret == "password-secret"
    assert store.attach_default_credential("ssh", "user", "example.com") == attached


def test_unlock_default_credential_prefers_key_without_returning_secret(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    store.set_default_credential("user", password="password-secret", ssh_key="key-secret")

    result = store.unlock_default_credential()

    assert result == {"status": "unlocked", "credential": "default", "record_type": "key"}
    assert "secret" not in str(result)


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


def test_list_metadata_discovers_existing_gopass_records_missing_from_index(tmp_path):
    runner = FakeRunner()
    store = CredentialStore(runner=runner, index_path=tmp_path / "credentials.json")
    slug = "ssh://user@example.com"
    runner.records[store._record_path(slug, "password")] = json.dumps({"type": "password", "secret": "secret"})

    rows = store.list_metadata()

    assert [row.to_dict() for row in rows] == [
        {
            "slug": slug,
            "purpose": "ssh",
            "username": "user",
            "canonical_host": "example.com",
            "has_password": True,
            "has_key": False,
        }
    ]
    assert json.loads((tmp_path / "credentials.json").read_text(encoding="utf-8"))[slug]["has_password"] is True


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
