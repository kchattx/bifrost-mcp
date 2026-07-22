from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Sequence

CredentialPurpose = Literal["ssh", "sudo", "winrm"]
CredentialRecordType = Literal["password", "key"]


class CredentialError(RuntimeError):
    code = "credential_error"


class CredentialBackendUnavailable(CredentialError):
    code = "credential_backend_unavailable"


class CredentialNotFound(CredentialError):
    code = "missing_credential"


class CredentialDecryptionFailed(CredentialError):
    code = "credential_decryption_failed"


class CredentialRecordExists(CredentialError):
    code = "credential_record_exists"


class CredentialValidationError(ValueError):
    code = "invalid_credential"


@dataclass(frozen=True)
class CredentialSlug:
    purpose: CredentialPurpose
    username: str
    canonical_host: str


@dataclass(frozen=True)
class CredentialRecord:
    slug: str
    record_type: CredentialRecordType
    secret: str


@dataclass(frozen=True)
class StoredSSHAuth:
    auth_type: Literal["password", "key"]
    secret: str


@dataclass(frozen=True)
class DefaultCredential:
    """Non-secret metadata for the single cross-transport fallback account."""

    username: str
    has_password: bool = False
    has_ssh_key: bool = False

    def to_dict(self) -> dict[str, object]:
        return {"username": self.username, "has_password": self.has_password, "has_ssh_key": self.has_ssh_key}


@dataclass(frozen=True)
class CredentialMetadata:
    slug: str
    purpose: CredentialPurpose
    username: str
    canonical_host: str
    has_password: bool = False
    has_key: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "slug": self.slug,
            "purpose": self.purpose,
            "username": self.username,
            "canonical_host": self.canonical_host,
            "has_password": self.has_password,
            "has_key": self.has_key,
        }


def canonicalize_host(host: str, port: int = 22) -> str:
    if not isinstance(host, str):
        raise CredentialValidationError("host must be a string")
    cleaned = host.strip().lower()
    if not cleaned:
        raise CredentialValidationError("host must not be blank")
    if port <= 0 or port > 65535:
        raise CredentialValidationError("port must be between 1 and 65535")
    return cleaned if port == 22 else f"{cleaned}:{port}"


def build_slug(purpose: CredentialPurpose, username: str, canonical_host: str) -> str:
    if purpose not in ("ssh", "sudo", "winrm"):
        raise CredentialValidationError("credential purpose must be 'ssh', 'sudo', or 'winrm'")
    user = username.strip() if isinstance(username, str) else ""
    host = canonical_host.strip().lower() if isinstance(canonical_host, str) else ""
    if not user:
        raise CredentialValidationError("credential username must not be blank")
    if not host:
        raise CredentialValidationError("credential canonical host must not be blank")
    return f"{purpose}://{user}@{host}"


def parse_slug(slug: str) -> CredentialSlug:
    if not isinstance(slug, str) or "://" not in slug:
        raise CredentialValidationError("credential slug must be '<purpose>://<username>@<canonical-host>'")
    purpose, rest = slug.split("://", 1)
    if purpose not in ("ssh", "sudo", "winrm"):
        raise CredentialValidationError("credential purpose must be 'ssh', 'sudo', or 'winrm'")
    if "@" not in rest:
        raise CredentialValidationError("credential slug must include username and host")
    username, host = rest.split("@", 1)
    username = username.strip()
    host = host.strip().lower()
    if not username:
        raise CredentialValidationError("credential username must not be blank")
    if not host:
        raise CredentialValidationError("credential canonical host must not be blank")
    if host != host.lower():
        raise CredentialValidationError("credential canonical host must be lowercase")
    return CredentialSlug(purpose=purpose, username=username, canonical_host=host)  # type: ignore[arg-type]


Runner = Callable[..., subprocess.CompletedProcess[str]]


class CredentialStore:
    """Required gopass-backed credential store.

    Secret material lives only in gopass records. A small metadata index is kept
    under ~/.config/bifrost_mcp so list/show operations do not need to read
    every secret record back from gopass.
    """

    def __init__(
        self,
        *,
        runner: Runner | None = None,
        index_path: Path | None = None,
        password_store_dir: Path | None = None,
    ) -> None:
        self._runner = runner or subprocess.run
        self._index_path = index_path or (Path.home() / ".config" / "bifrost_mcp" / "credentials.json")
        self._password_store_dir = password_store_dir

    def validate_backend(self) -> None:
        if shutil.which("gopass") is None:
            raise CredentialBackendUnavailable(
                "gopass is required. Install and initialize gopass, then add Bifrost MCP credentials with 'bifrost-mcp credential add'."
            )
        result = self._run(["gopass", "ls"], input_text=None, check=False)
        if result.returncode != 0:
            raise CredentialBackendUnavailable(
                "gopass is installed but not initialized or not accessible. Run 'gopass init <gpg-key-id-or-email>' or unlock your store."
            )

    def store_record(self, slug: str, record_type: CredentialRecordType, secret: str) -> CredentialMetadata:
        parsed = parse_slug(slug)
        self._validate_record_type(parsed, record_type)
        if not isinstance(secret, str) or secret == "":
            raise CredentialValidationError("credential secret must not be blank")
        if self.record_exists(slug, record_type):
            raise CredentialRecordExists(f"{record_type} record already exists for {slug}")
        payload = json.dumps({"type": record_type, "secret": secret})
        record_path = self._record_path(slug, record_type)
        self._ensure_record_parent(record_path)
        self._run(["gopass", "insert", "-m", record_path], input_text=payload, check=True)
        return self._update_index(slug, record_type, exists=True)

    def get_record(self, slug: str, record_type: CredentialRecordType) -> CredentialRecord:
        parsed = parse_slug(slug)
        self._validate_record_type(parsed, record_type)
        result = self._run(["gopass", "show", self._record_path(slug, record_type)], input_text=None, check=False)
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "gopass show failed").strip()
            lowered = message.lower()
            if (
                "could not find password" in lowered
                or lowered == "not found"
                or "entry is not in the password store" in lowered
            ):
                raise CredentialNotFound(f"No {record_type} credential record exists for {slug}")
            raise CredentialDecryptionFailed(
                f"Failed to decrypt {record_type} credential record for {slug}. Unlock gopass/GPG and retry."
            )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CredentialValidationError(f"Stored credential record for {slug} is not valid JSON") from exc
        if data.get("type") != record_type:
            raise CredentialValidationError(f"Stored credential record for {slug} has mismatched type")
        secret = data.get("secret")
        if not isinstance(secret, str) or secret == "":
            raise CredentialValidationError(f"Stored credential record for {slug} has missing or blank secret")
        return CredentialRecord(slug=slug, record_type=record_type, secret=secret)

    def resolve_ssh_auth(self, slug: str) -> StoredSSHAuth:
        parsed = parse_slug(slug)
        if parsed.purpose != "ssh":
            raise CredentialValidationError("SSH auth resolution requires an ssh:// credential slug")
        try:
            return StoredSSHAuth(auth_type="key", secret=self.get_record(slug, "key").secret)
        except CredentialNotFound:
            pass
        try:
            return StoredSSHAuth(auth_type="password", secret=self.get_record(slug, "password").secret)
        except CredentialNotFound as exc:
            raise CredentialNotFound(f"No stored SSH credential exists for {parsed.username}@{parsed.canonical_host}") from exc

    def resolve_sudo_password(self, slug: str) -> str:
        parsed = parse_slug(slug)
        if parsed.purpose != "sudo":
            raise CredentialValidationError("sudo password resolution requires a sudo:// credential slug")
        return self.get_record(slug, "password").secret

    def get_default_credential(self) -> DefaultCredential:
        if not self._default_index_path.exists():
            raise CredentialNotFound("No default credential is configured. Run 'bifrost-mcp credential set-default'.")
        with self._default_index_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        username = data.get("username")
        if not isinstance(username, str) or not username.strip():
            raise CredentialValidationError("Default credential metadata has a missing or blank username")
        return DefaultCredential(username=username.strip(), has_password=bool(data.get("has_password")), has_ssh_key=bool(data.get("has_ssh_key")))

    def set_default_credential(self, username: str, *, password: str | None = None, ssh_key: str | None = None) -> DefaultCredential:
        """Update the shared fallback account; ``None`` preserves an existing optional secret."""
        user = username.strip() if isinstance(username, str) else ""
        if not user:
            raise CredentialValidationError("default credential username must not be blank")
        try:
            current = self.get_default_credential()
        except CredentialNotFound:
            current = DefaultCredential(username=user)
        if password is not None:
            self._store_default_record("password", password)
        if ssh_key is not None:
            self._store_default_record("key", ssh_key)
        metadata = DefaultCredential(user, current.has_password or password is not None, current.has_ssh_key or ssh_key is not None)
        self._save_default_credential(metadata)
        return metadata

    def resolve_default_ssh_auth(self) -> StoredSSHAuth:
        metadata = self.get_default_credential()
        if metadata.has_ssh_key:
            return StoredSSHAuth(auth_type="key", secret=self._get_default_record("key"))
        if metadata.has_password:
            return StoredSSHAuth(auth_type="password", secret=self._get_default_record("password"))
        raise CredentialNotFound("Default credential has neither an SSH key nor password")

    def resolve_default_winrm_password(self) -> str:
        if not self.get_default_credential().has_password:
            raise CredentialNotFound("Default credential has no password for WinRM")
        return self._get_default_record("password")

    def resolve_default_sudo_password(self) -> str:
        """Return the default account password only for a same-user sudo fallback."""
        if not self.get_default_credential().has_password:
            raise CredentialNotFound("Default credential has no password for sudo")
        return self._get_default_record("password")

    def unlock_default_credential(self, record_type: CredentialRecordType | None = None) -> dict[str, str]:
        metadata = self.get_default_credential()
        selected = record_type or ("key" if metadata.has_ssh_key else "password")
        if selected == "key" and not metadata.has_ssh_key:
            raise CredentialNotFound("Default credential has no SSH key")
        if selected == "password" and not metadata.has_password:
            raise CredentialNotFound("Default credential has no password")
        self._get_default_record(selected)
        return {"status": "unlocked", "credential": "default", "record_type": selected}

    def attach_default_credential(self, purpose: Literal["ssh", "winrm"], username: str, canonical_host: str) -> CredentialMetadata:
        """Materialize defaults only after a successful connection; never overwrite host-specific records."""
        default = self.get_default_credential()
        if username != default.username:
            raise CredentialValidationError("default credential username does not match the requested connection username")
        slug = build_slug(purpose, username, canonical_host)
        record_types: tuple[CredentialRecordType, ...] = ("password",) if purpose == "winrm" else ("password", "key")
        for record_type in record_types:
            available = default.has_password if record_type == "password" else default.has_ssh_key
            if available and not self.record_exists(slug, record_type):
                self.store_record(slug, record_type, self._get_default_record(record_type))
        return self.show_metadata(slug)

    def unlock_record(self, slug: str, record_type: CredentialRecordType | None = None) -> dict[str, str]:
        """Decrypt one record to warm gpg-agent without returning secret material."""
        parsed = parse_slug(slug)
        if record_type is not None:
            self.get_record(slug, record_type)
            return {"status": "unlocked", "slug": slug, "record_type": record_type}
        if parsed.purpose == "sudo":
            self.get_record(slug, "password")
            return {"status": "unlocked", "slug": slug, "record_type": "password"}
        try:
            self.get_record(slug, "key")
            return {"status": "unlocked", "slug": slug, "record_type": "key"}
        except CredentialNotFound:
            self.get_record(slug, "password")
            return {"status": "unlocked", "slug": slug, "record_type": "password"}

    def remove_record(self, slug: str, record_type: CredentialRecordType) -> CredentialMetadata:
        parsed = parse_slug(slug)
        self._validate_record_type(parsed, record_type)
        result = self._run(["gopass", "rm", "-f", self._record_path(slug, record_type)], input_text=None, check=False)
        if result.returncode != 0:
            metadata = self._load_index().get(slug)
            if metadata is not None and self._metadata_has_record_type(metadata, record_type):
                reconciled = self._reconcile_metadata(metadata)
                if reconciled is None or not self._metadata_has_record_type(reconciled, record_type):
                    return self._update_index(slug, record_type, exists=False)
            raise CredentialNotFound(f"No {record_type} credential record exists for {slug}")
        return self._update_index(slug, record_type, exists=False)

    def record_exists(self, slug: str, record_type: CredentialRecordType) -> bool:
        parsed = parse_slug(slug)
        self._validate_record_type(parsed, record_type)
        result = self._run(["gopass", "show", self._record_path(slug, record_type)], input_text=None, check=False)
        return result.returncode == 0

    def list_metadata(
        self,
        *,
        host: str | None = None,
        user: str | None = None,
        purpose: CredentialPurpose | None = None,
    ) -> list[CredentialMetadata]:
        if purpose is not None and purpose not in ("ssh", "sudo", "winrm"):
            raise CredentialValidationError("credential purpose must be 'ssh', 'sudo', or 'winrm'")
        host_filter = host.strip().lower() if isinstance(host, str) and host.strip() else None
        user_filter = user.strip() if isinstance(user, str) and user.strip() else None
        rows = []
        for metadata in self._reconcile_index().values():
            if host_filter is not None and metadata.canonical_host != host_filter:
                continue
            if user_filter is not None and metadata.username != user_filter:
                continue
            if purpose is not None and metadata.purpose != purpose:
                continue
            rows.append(metadata)
        return sorted(rows, key=lambda item: (item.canonical_host, item.username, item.purpose))

    def show_metadata(self, slug: str) -> CredentialMetadata:
        parse_slug(slug)
        metadata = self._reconcile_index().get(slug)
        if metadata is None:
            raise CredentialNotFound(f"No credential metadata exists for {slug}")
        return metadata

    def _run(self, args: Sequence[str], *, input_text: str | None, check: bool) -> subprocess.CompletedProcess[str]:
        if self._runner is subprocess.run and args and args[0] == "gopass" and shutil.which("gopass") is None:
            raise CredentialBackendUnavailable(
                "gopass is required. Install and initialize gopass, then add Bifrost MCP credentials with 'bifrost-mcp credential add'."
            )
        result = self._runner(args, input=input_text, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise CredentialError(result.stderr.strip() or "gopass command failed")
        return result

    def _record_path(self, slug: str, record_type: CredentialRecordType) -> str:
        encoded = base64.urlsafe_b64encode(slug.encode("utf-8")).decode("ascii").rstrip("=")
        return f"bifrost_mcp/{encoded}/{record_type}"

    @property
    def _default_index_path(self) -> Path:
        return self._index_path.with_name("default_credential.json")

    @staticmethod
    def _default_record_path(record_type: CredentialRecordType) -> str:
        return f"bifrost_mcp/default/{record_type}"

    def _store_default_record(self, record_type: CredentialRecordType, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise CredentialValidationError("default credential secret must not be blank")
        record_path = self._default_record_path(record_type)
        self._ensure_record_parent(record_path)
        self._run(["gopass", "insert", "-f", "-m", record_path], input_text=json.dumps({"type": record_type, "secret": secret}), check=True)

    def _get_default_record(self, record_type: CredentialRecordType) -> str:
        result = self._run(["gopass", "show", self._default_record_path(record_type)], input_text=None, check=False)
        if result.returncode != 0:
            raise CredentialDecryptionFailed(f"Failed to decrypt default {record_type} credential record. Unlock gopass/GPG and retry.")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CredentialValidationError(f"Stored default {record_type} credential record is not valid JSON") from exc
        secret = data.get("secret")
        if data.get("type") != record_type or not isinstance(secret, str) or not secret:
            raise CredentialValidationError(f"Stored default {record_type} credential record is invalid")
        return secret

    def _save_default_credential(self, metadata: DefaultCredential) -> None:
        self._default_index_path.parent.mkdir(parents=True, exist_ok=True)
        with self._default_index_path.open("w", encoding="utf-8") as handle:
            json.dump({"username": metadata.username, "has_password": metadata.has_password, "has_ssh_key": metadata.has_ssh_key}, handle, indent=2, sort_keys=True)

    def _ensure_record_parent(self, record_path: str) -> None:
        password_store_dir = self._resolved_password_store_dir()
        if password_store_dir is None:
            return
        (password_store_dir / record_path).parent.mkdir(parents=True, exist_ok=True)

    def _resolved_password_store_dir(self) -> Path | None:
        if self._password_store_dir is not None:
            return self._password_store_dir
        if self._runner is not subprocess.run:
            return None
        configured = os.environ.get("PASSWORD_STORE_DIR")
        if configured:
            return Path(configured).expanduser()
        return Path.home() / ".password-store"

    def _validate_record_type(self, parsed: CredentialSlug, record_type: str) -> None:
        if record_type not in ("password", "key"):
            raise CredentialValidationError("credential record type must be 'password' or 'key'")
        if parsed.purpose == "sudo" and record_type == "key":
            raise CredentialValidationError("sudo credentials support password records only")

    def _load_index(self) -> dict[str, CredentialMetadata]:
        if not self._index_path.exists():
            return {}
        with self._index_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        rows: dict[str, CredentialMetadata] = {}
        for slug, data in raw.items():
            parsed = parse_slug(slug)
            rows[slug] = CredentialMetadata(
                slug=slug,
                purpose=parsed.purpose,
                username=parsed.username,
                canonical_host=parsed.canonical_host,
                has_password=bool(data.get("has_password", False)),
                has_key=bool(data.get("has_key", False)),
            )
        return rows

    def _reconcile_index(self) -> dict[str, CredentialMetadata]:
        rows = self._load_index()
        reconciled: dict[str, CredentialMetadata] = {}
        changed = False
        for slug, metadata in rows.items():
            updated = self._reconcile_metadata(metadata)
            if updated is None:
                changed = True
                continue
            reconciled[slug] = updated
            if updated != metadata:
                changed = True
        if changed:
            self._save_index(reconciled)
        return reconciled

    def _reconcile_metadata(self, metadata: CredentialMetadata) -> CredentialMetadata | None:
        password_exists = self._record_file_exists(metadata.slug, "password") if metadata.has_password else None
        key_exists = self._record_file_exists(metadata.slug, "key") if metadata.has_key else None
        if password_exists is None and key_exists is None:
            return metadata
        reconciled = CredentialMetadata(
            slug=metadata.slug,
            purpose=metadata.purpose,
            username=metadata.username,
            canonical_host=metadata.canonical_host,
            has_password=metadata.has_password if password_exists is None else password_exists,
            has_key=metadata.has_key if key_exists is None else key_exists,
        )
        if not reconciled.has_password and not reconciled.has_key:
            return None
        return reconciled

    def _record_file_exists(self, slug: str, record_type: CredentialRecordType) -> bool | None:
        record_file = self._record_file_path(slug, record_type)
        if record_file is None:
            return None
        return record_file.exists()

    def _record_file_path(self, slug: str, record_type: CredentialRecordType) -> Path | None:
        password_store_dir = self._resolved_password_store_dir()
        if password_store_dir is None:
            return None
        record_path = password_store_dir / self._record_path(slug, record_type)
        gpg_path = record_path.with_suffix(".gpg")
        if gpg_path.exists() or not record_path.exists():
            return gpg_path
        return record_path

    @staticmethod
    def _metadata_has_record_type(metadata: CredentialMetadata, record_type: CredentialRecordType) -> bool:
        return metadata.has_key if record_type == "key" else metadata.has_password

    def _save_index(self, rows: dict[str, CredentialMetadata]) -> None:
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {slug: row.to_dict() for slug, row in sorted(rows.items())}
        with self._index_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def _update_index(self, slug: str, record_type: CredentialRecordType, *, exists: bool) -> CredentialMetadata:
        parsed = parse_slug(slug)
        rows = self._load_index()
        current = rows.get(
            slug,
            CredentialMetadata(slug=slug, purpose=parsed.purpose, username=parsed.username, canonical_host=parsed.canonical_host),
        )
        metadata = CredentialMetadata(
            slug=slug,
            purpose=parsed.purpose,
            username=parsed.username,
            canonical_host=parsed.canonical_host,
            has_password=exists if record_type == "password" else current.has_password,
            has_key=exists if record_type == "key" else current.has_key,
        )
        if not metadata.has_password and not metadata.has_key:
            rows.pop(slug, None)
        else:
            rows[slug] = metadata
        self._save_index(rows)
        return metadata
