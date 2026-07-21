from __future__ import annotations

import argparse
import atexit
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from bifrost_mcp.credentials import (
    CredentialDecryptionFailed,
    CredentialError,
    CredentialNotFound,
    CredentialRecord,
    CredentialRecordExists,
    CredentialRecordType,
    CredentialPurpose,
    CredentialStore,
    CredentialValidationError,
    build_slug,
    canonicalize_host,
    parse_slug,
)
from bifrost_mcp.session import RemoteSessionHandler
from bifrost_mcp.session_registry import SessionRegistry
from bifrost_mcp.ssh_handler import SSHHandler
from bifrost_mcp.winrm_handler import WinRMHandler

_IDLE_TIMEOUT_SECONDS = float(os.getenv("BIFROST_MCP_SESSION_IDLE_TIMEOUT_SECONDS", "3600"))
_sessions: dict[str, RemoteSessionHandler] = {}
_registry = SessionRegistry(idle_timeout_seconds=_IDLE_TIMEOUT_SECONDS, sessions=_sessions)


def _server_instructions() -> str:
    return (
        "Bifrost MCP provides interactive SSH sessions with file transfer and bounded WinRM command execution. "
        "Sessions for either transport can be listed and closed. "
        "Secrets are resolved server-side from gopass credentials; never ask the agent to pass passwords."
    )


def _error(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error": {"code": code, "message": message}}


def _credential_error(exc: Exception) -> dict[str, Any]:
    code = getattr(exc, "code", "credential_error")
    return _error(str(code), str(exc))


def _missing_credential_error(exc: CredentialNotFound | CredentialDecryptionFailed) -> dict[str, Any]:
    if isinstance(exc, CredentialDecryptionFailed):
        return _credential_error(exc)
    return _error("missing_credential", str(exc))


def _resolve_after_unlock_retry(
    store: CredentialStore,
    slug: str,
    resolver,
    *,
    unlock_record_type: CredentialRecordType | None = None,
):
    try:
        return resolver()
    except CredentialDecryptionFailed:
        # If gpg-agent cache expired, try one explicit unlock pass for the same
        # credential slug before surfacing the error back to the caller.
        store.unlock_record(slug, unlock_record_type)
        return resolver()


def _unsupported_operation(operation: str, transport: str) -> dict[str, Any]:
    return _error("unsupported_operation", f"Operation {operation} is not supported for {transport} sessions.")


def _validate_create_session_inputs(
    host: str,
    username: str | None,
    port: int,
    **legacy_fields: Any,
) -> None:
    supplied_legacy = [name for name, value in legacy_fields.items() if value is not None]
    if supplied_legacy:
        raise ValueError(
            "create_ssh_session no longer accepts raw password/private key fields: " + ", ".join(sorted(supplied_legacy))
        )
    canonicalize_host(host, port)
    if username is None or username.strip() == "":
        raise ValueError("create_ssh_session requires username.")


# Backward-compatible private helper name for tests/importers; now validates the
# retired raw-auth API by rejecting any supplied legacy secret fields.
def _validate_auth_inputs(
    auth_mode: Literal["password", "inline_key"] | None = None,
    password: str | None = None,
    private_key: str | None = None,
    private_key_passphrase: str | None = None,
) -> None:
    supplied = {
        "auth_mode": auth_mode,
        "password": password,
        "private_key": private_key,
        "private_key_passphrase": private_key_passphrase,
    }
    supplied_legacy = [name for name, value in supplied.items() if value is not None]
    if supplied_legacy:
        raise ValueError("raw SSH auth inputs are not accepted by agent-facing tools: " + ", ".join(supplied_legacy))


def _create_ssh_session_impl(host: str, username: str | None = None, port: int = 22, *, store: CredentialStore | None = None) -> dict[str, Any]:
    store = store or CredentialStore()
    used_default = False
    if username is None or not username.strip():
        try:
            username = store.get_default_credential().username
            used_default = True
        except (CredentialNotFound, CredentialDecryptionFailed) as exc:
            return _missing_credential_error(exc)
        except CredentialError as exc:
            return _credential_error(exc)
    _validate_create_session_inputs(host, username, port)
    canonical_host = canonicalize_host(host, port)
    slug = build_slug("ssh", username, canonical_host)
    try:
        auth = _resolve_after_unlock_retry(store, slug, lambda: store.resolve_ssh_auth(slug))
    except CredentialNotFound:
        try:
            default = store.get_default_credential()
            if default.username != username:
                raise CredentialNotFound(f"No stored SSH credential exists for {username}@{canonical_host}")
            auth = store.resolve_default_ssh_auth()
            used_default = True
        except (CredentialNotFound, CredentialDecryptionFailed) as exc:
            return _missing_credential_error(exc)
        except CredentialError as exc:
            return _credential_error(exc)
    except CredentialDecryptionFailed as exc:
        return _missing_credential_error(exc)
    except CredentialError as exc:
        return _credential_error(exc)

    try:
        handler = _open_ssh_handler(host, username, port, auth)
    except Exception as exc:
        return _error("ssh_connection_failed", str(exc))
    if used_default:
        store.attach_default_credential("ssh", username, canonical_host)
    _registry.register(handler)
    return {"status": "created", "session_id": handler.session_id, "transport": handler.transport, "host": canonical_host, "username": username, "port": port}


def _canonicalize_winrm_host(host: str, port: int, *, use_ssl: bool) -> str:
    default_port = 5986 if use_ssl else 5985
    return canonicalize_host(host) if port == default_port else canonicalize_host(host, port)


def _create_winrm_session_impl(
    host: str,
    username: str | None = None,
    port: int = 5985,
    *,
    use_ssl: bool = False,
    auth: str = "ntlm",
    store: CredentialStore | None = None,
) -> dict[str, Any]:
    store = store or CredentialStore()
    used_default = False
    if username is None or not username.strip():
        try:
            username = store.get_default_credential().username
            used_default = True
        except (CredentialNotFound, CredentialDecryptionFailed) as exc:
            return _missing_credential_error(exc)
        except CredentialError as exc:
            return _credential_error(exc)
    _validate_create_session_inputs(host, username, port)
    domain, separator, account = username.partition("\\")
    if (
        "@" in username
        or not separator
        or not domain.strip()
        or not account.strip()
        or "\\" in account
    ):
        return _error("invalid_username", "WinRM username must use DOMAIN\\user format; UPN usernames are not supported.")
    if auth not in ("ntlm", "basic"):
        return _error("invalid_auth", "WinRM auth must be 'ntlm' or 'basic'.")
    canonical_host = _canonicalize_winrm_host(host, port, use_ssl=use_ssl)
    slug = build_slug("winrm", username, canonical_host)
    try:
        record = _resolve_after_unlock_retry(
            store,
            slug,
            lambda: store.get_record(slug, "password"),
            unlock_record_type="password",
        )
    except CredentialNotFound:
        try:
            default = store.get_default_credential()
            if default.username != username:
                raise CredentialNotFound(f"No stored WinRM credential exists for {username}@{canonical_host}")
            record = CredentialRecord(slug=slug, record_type="password", secret=store.resolve_default_winrm_password())
            used_default = True
        except (CredentialNotFound, CredentialDecryptionFailed) as exc:
            return _missing_credential_error(exc)
        except CredentialError as exc:
            return _credential_error(exc)
    except CredentialDecryptionFailed as exc:
        return _missing_credential_error(exc)
    except CredentialError as exc:
        return _credential_error(exc)

    try:
        handler = _open_winrm_handler(host, username, port, record.secret, use_ssl=use_ssl, auth=auth)
    except Exception as exc:
        return _error("winrm_connection_failed", str(exc))
    if used_default:
        store.attach_default_credential("winrm", username, canonical_host)
    _registry.register(handler)
    return {"status": "created", "session_id": handler.session_id, "transport": handler.transport, "host": canonical_host, "username": username, "port": port}


def _open_ssh_handler(host: str, username: str, port: int, auth) -> SSHHandler:
    handler = SSHHandler()
    session_id = handler.open_session(
        host=host,
        username=username,
        port=port,
        auth_mode="key" if auth.auth_type == "key" else "password",
        password=auth.secret if auth.auth_type == "password" else None,
        private_key=auth.secret if auth.auth_type == "key" else None,
    )
    if session_id != handler.session_id:
        raise RuntimeError("SSH handler returned mismatched session_id")
    return handler


def _open_winrm_handler(host: str, username: str, port: int, password: str, *, use_ssl: bool, auth: str) -> WinRMHandler:
    handler = WinRMHandler()
    session_id = handler.open_session(
        host=host,
        username=username,
        port=port,
        password=password,
        use_ssl=use_ssl,
        auth=auth,
    )
    if session_id != handler.session_id:
        raise RuntimeError("WinRM handler returned mismatched session_id")
    return handler


def _list_credentials_impl(host: str, *, store: CredentialStore | None = None) -> dict[str, Any]:
    canonical_host = canonicalize_host(host)
    store = store or CredentialStore()
    rows = store.list_metadata(host=canonical_host)
    by_user: dict[str, dict[str, object]] = {}
    for row in rows:
        user = by_user.setdefault(row.username, {"username": row.username, "ssh": False, "sudo": False})
        if row.purpose == "ssh" and (row.has_password or row.has_key):
            user["ssh"] = True
        if row.purpose == "sudo" and row.has_password:
            user["sudo"] = True
    users = sorted(by_user.values(), key=lambda item: str(item["username"]))
    ssh_users = [user for user in users if user["ssh"]]
    if len(ssh_users) == 0:
        guidance = "no_ssh_credentials_choose_username"
    elif len(ssh_users) == 1:
        guidance = "single_user_available"
    else:
        guidance = "multiple_users_choose_username"
    return {"status": "ok", "host": canonical_host, "users": users, "guidance": guidance}


def _get_session(session_id: str) -> RemoteSessionHandler:
    return _registry.get(session_id)


def _list_sessions_impl() -> dict[str, Any]:
    return {"sessions": [info.to_dict() for info in _registry.list_info()]}


def _send_input_impl(session_id: str, text: str) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("send_input", handler.transport)
    handler.send_input(text)
    return {"status": "accepted", "session_id": session_id}


def _send_control_impl(session_id: str, key: str) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("send_control", handler.transport)
    handler.send_control(key)
    return {"status": "accepted", "session_id": session_id}


def _resize_session_impl(session_id: str, width: int, height: int) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("resize_session", handler.transport)
    handler.resize_session(width, height)
    return {"status": "resized", "session_id": session_id}


def _read_output_impl(session_id: str, clear_buffer: bool = True) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("read_output", handler.transport)
    output = handler.flush_output_buffer() if clear_buffer else handler.read_output()
    return {"status": "ok", "session_id": session_id, "output": output}


def _wait_for_output_impl(session_id: str, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("wait_for_output", handler.transport)
    result = handler.wait_for_output(pattern, timeout, regex=regex, clear_buffer=clear_buffer)
    result["session_id"] = session_id
    return result


def _run_command_impl(session_id: str, command: str, timeout: float = 30) -> dict[str, Any]:
    handler = _get_session(session_id)
    result = handler.run_command(command, timeout=timeout)
    result["session_id"] = session_id
    return result


def _check_sudo_cache_impl(session_id: str, timeout: float = 10) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("check_sudo_cache", handler.transport)
    return handler.check_sudo_cache(timeout=timeout)


def _warm_sudo_cache_impl(session_id: str, timeout: float = 10) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("warm_sudo_cache", handler.transport)
    if not handler.username or not handler.canonical_host:
        return _error("missing_session_metadata", "Session is missing username or canonical host metadata.")
    slug = build_slug("sudo", handler.username, handler.canonical_host)
    store = CredentialStore()
    try:
        password = _resolve_after_unlock_retry(
            store,
            slug,
            lambda: store.resolve_sudo_password(slug),
            unlock_record_type="password",
        )
    except (CredentialNotFound, CredentialDecryptionFailed) as exc:
        return _missing_credential_error(exc)
    except CredentialError as exc:
        return _credential_error(exc)
    return handler.warm_sudo_cache(password, timeout=timeout)


def _clear_sudo_cache_impl(session_id: str, timeout: float = 10) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("clear_sudo_cache", handler.transport)
    return handler.clear_sudo_cache(timeout=timeout)


def _upload_file_impl(session_id: str, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("upload_file", handler.transport)
    return handler.upload_file(local_path, remote_path, create_parents=create_parents)


def _download_file_impl(session_id: str, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, Any]:
    handler = _get_session(session_id)
    if handler.transport == "winrm":
        return _unsupported_operation("download_file", handler.transport)
    return handler.download_file(remote_path, local_path, create_parents=create_parents)


def _close_session_impl(session_id: str) -> dict[str, str]:
    handler = _get_session(session_id)
    handler.close_session()
    _sessions.pop(session_id, None)
    return {"status": "closed", "session_id": session_id}


def create_server() -> FastMCP:
    server = FastMCP(name="bifrost", instructions=_server_instructions())

    @server.tool(description="List non-secret stored credential metadata for one host.")
    def list_credentials(host: str) -> dict[str, Any]:
        return _list_credentials_impl(host)

    @server.tool(description="Open a new interactive SSH session using server-side stored credentials.")
    def create_ssh_session(host: str, username: str | None = None, port: int = 22) -> dict[str, Any]:
        return _create_ssh_session_impl(host, username, port)

    @server.tool(description="Open a new WinRM session using server-side stored credentials.")
    def create_winrm_session(host: str, username: str | None = None, port: int = 5985, use_ssl: bool = False, auth: str = "ntlm") -> dict[str, Any]:
        return _create_winrm_session_impl(host, username, port, use_ssl=use_ssl, auth=auth)

    @server.tool(description="Send raw text to an active SSH session.")
    def send_input(session_id: str, text: str) -> dict[str, str]:
        return _send_input_impl(session_id, text)

    @server.tool(description="Send a supported terminal control key to an active SSH session.")
    def send_control(session_id: str, key: str) -> dict[str, str]:
        return _send_control_impl(session_id, key)

    @server.tool(description="Resize the active SSH session pseudo-terminal.")
    def resize_session(session_id: str, width: int, height: int) -> dict[str, str]:
        return _resize_session_impl(session_id, width, height)

    @server.tool(description="Read buffered output from an active SSH session and optionally clear it.")
    def read_output(session_id: str, clear_buffer: bool = True) -> dict[str, str]:
        return _read_output_impl(session_id, clear_buffer=clear_buffer)

    @server.tool(description="Wait for remote session output matching a regex or literal pattern.")
    def wait_for_output(session_id: str, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, Any]:
        return _wait_for_output_impl(session_id, pattern, timeout, regex=regex, clear_buffer=clear_buffer)

    @server.tool(description="Run a command in the existing session. SSH uses the interactive shell; WinRM expects PowerShell script text and runs it via pywinrm run_ps().")
    def run_command(session_id: str, command: str, timeout: float = 30) -> dict[str, Any]:
        return _run_command_impl(session_id, command, timeout=timeout)

    @server.tool(description="Check whether sudo cache is warm without prompting.")
    def check_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        return _check_sudo_cache_impl(session_id, timeout=timeout)

    @server.tool(description="Warm sudo credentials using server-managed gopass sudo password.")
    def warm_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        return _warm_sudo_cache_impl(session_id, timeout=timeout)

    @server.tool(description="Clear remote sudo timestamp cache with sudo -k.")
    def clear_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        return _clear_sudo_cache_impl(session_id, timeout=timeout)

    @server.tool(description="Upload an MCP-server-local file to the remote host over SFTP.")
    def upload_file(session_id: str, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, Any]:
        return _upload_file_impl(session_id, local_path, remote_path, create_parents=create_parents)

    @server.tool(description="Download a remote file to an MCP-server-local path over SFTP.")
    def download_file(session_id: str, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, Any]:
        return _download_file_impl(session_id, remote_path, local_path, create_parents=create_parents)

    @server.tool(description="List all active remote sessions managed by this MCP server.")
    def list_sessions() -> dict[str, Any]:
        return _list_sessions_impl()

    @server.tool(description="Close an active remote session and remove it from server state.")
    def close_session(session_id: str) -> dict[str, str]:
        return _close_session_impl(session_id)

    return server


def _cleanup_sessions() -> None:
    _registry.cleanup_all()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bifrost-mcp")
    parser.add_argument("--transport", choices=("stdio", "sse", "streamable-http"), default="stdio", help="MCP transport to serve. Codex CLI should use stdio.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind for HTTP-based transports.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind for HTTP-based transports.")
    parser.add_argument("--mount-path", default="/", help="Mount path for HTTP-based transports.")
    parser.add_argument("--session-idle-timeout-seconds", type=float, default=_IDLE_TIMEOUT_SECONDS, help="Idle session timeout before cleanup; defaults to BIFROST_MCP_SESSION_IDLE_TIMEOUT_SECONDS or 3600.")

    subparsers = parser.add_subparsers(dest="command")
    credential = subparsers.add_parser("credential", help="Manage server-side gopass credentials.")
    credential_sub = credential.add_subparsers(dest="credential_command", required=True)

    add = credential_sub.add_parser("add", help="Add a password or private-key credential record.")
    add.add_argument("slug")
    add_group = add.add_mutually_exclusive_group()
    add_group.add_argument("--password", action="store_true", help="Read password secret from stdin (default).")
    add_group.add_argument("--key", help="Read private-key secret from this MCP-server-local file path.")

    credential_sub.add_parser("set-default", help="Interactively configure the single cross-transport default account.")

    list_cmd = credential_sub.add_parser("list", help="List non-secret credential metadata.")
    list_cmd.add_argument("--host")
    list_cmd.add_argument("--user")
    list_cmd.add_argument("--purpose", choices=("ssh", "sudo", "winrm"))
    list_cmd.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of the default table.")

    show = credential_sub.add_parser("show", help="Show non-secret credential metadata for a slug.")
    show.add_argument("slug")

    remove = credential_sub.add_parser("remove", help="Remove one credential record from a slug.")
    remove.add_argument("slug")
    remove_group = remove.add_mutually_exclusive_group(required=True)
    remove_group.add_argument("--password", action="store_true")
    remove_group.add_argument("--key", action="store_true")

    unlock = credential_sub.add_parser("unlock", help="Decrypt one stored record to warm gpg-agent without printing the secret.")
    unlock.add_argument("slug", nargs="?", help="Exact credential slug, e.g. ssh://user@example.com")
    unlock.add_argument("--host", help="Resolve a single credential by host instead of exact slug.")
    unlock.add_argument("--user", help="Resolve a single credential by username instead of exact slug.")
    unlock.add_argument("--purpose", choices=("ssh", "sudo", "winrm"))
    unlock_record_group = unlock.add_mutually_exclusive_group()
    unlock_record_group.add_argument("--password", action="store_true")
    unlock_record_group.add_argument("--key", action="store_true")

    return parser


def _read_password_secret(prompt: str = "Credential password: ") -> str:
    if getattr(sys.stdin, "isatty", lambda: False)():
        return getpass.getpass(prompt)
    return sys.stdin.read().rstrip("\n")


def _read_optional_sudo_password_for_ssh_slug() -> str:
    if not getattr(sys.stdin, "isatty", lambda: False)():
        return ""
    return getpass.getpass("Sudo Password (Leave blank for none): ")


def _prompt_default_credential(store: CredentialStore):
    try:
        current = store.get_default_credential()
    except CredentialNotFound:
        current = None
    username_prompt = f"Username [{current.username}]: " if current else "Username: "
    username = input(username_prompt).strip() or (current.username if current else "")
    password = getpass.getpass("Password [unchanged]: " if current and current.has_password else "Password (Leave blank for none): ")
    ssh_key = getpass.getpass("SSH key [unchanged]: " if current and current.has_ssh_key else "SSH key (Leave blank for none): ")
    return username, password or None, ssh_key or None


def _format_credential_list(rows: list[Any], default_credential: Any | None = None) -> str:
    if not rows and default_credential is None:
        return "No Bifrost credentials found."

    default_summary = ""
    if default_credential is not None:
        records = []
        if default_credential.has_password:
            records.append("password")
        if default_credential.has_ssh_key:
            records.append("key")
        default_summary = f"Default credential: {default_credential.username} ({','.join(records) or '-'})"

    table_rows = []
    for row in rows:
        records = []
        if row.has_password:
            records.append("password")
        if row.has_key:
            records.append("key")
        table_rows.append(
            {
                "purpose": row.purpose,
                "host": row.canonical_host,
                "username": row.username,
                "records": ",".join(records) or "-",
                "slug": row.slug,
            }
        )

    if not table_rows:
        return "\n".join(["Bifrost credentials:", default_summary])

    headers = {
        "purpose": "Purpose",
        "host": "Host",
        "username": "Username",
        "records": "Records",
        "slug": "Slug",
    }
    columns = list(headers)
    widths = {
        column: max(len(headers[column]), *(len(str(row[column])) for row in table_rows))
        for column in columns
    }
    header = "  ".join(headers[column].ljust(widths[column]) for column in columns)
    separator = "  ".join("-" * widths[column] for column in columns)
    body = ["  ".join(str(row[column]).ljust(widths[column]) for column in columns) for row in table_rows]
    return "\n".join(["Bifrost credentials:", default_summary, header, separator, *body])


def _select_unlock_target(
    store: CredentialStore,
    *,
    slug: str | None = None,
    host: str | None = None,
    user: str | None = None,
    purpose: CredentialPurpose | None = None,
    record_type: CredentialRecordType | None = None,
) -> tuple[str, CredentialRecordType]:
    if slug:
        slug = slug.strip()
        metadata = store.show_metadata(slug)
        selected_record_type: CredentialRecordType = record_type or ("key" if metadata.has_key else "password")
        if selected_record_type == "key" and not metadata.has_key:
            raise CredentialNotFound(f"No key credential record exists for {slug}")
        if selected_record_type == "password" and not metadata.has_password:
            raise CredentialNotFound(f"No password credential record exists for {slug}")
        return slug, selected_record_type

    normalized_host = canonicalize_host(host) if host else None
    rows = store.list_metadata(host=normalized_host, user=user, purpose=purpose)
    usable = [row for row in rows if row.has_password or row.has_key]
    if not usable:
        if host or user or purpose:
            raise CredentialNotFound("No matching credential exists for unlock request")
        raise CredentialNotFound("No Bifrost credentials are installed. Add one with 'bifrost-mcp credential add ...'.")

    # Any successful decrypt warms the same gpg-agent cache, so auto-select a
    # deterministic record rather than forcing operators to spell an exact slug.
    usable = sorted(
        usable,
        key=lambda row: (0 if row.purpose == "ssh" else 1, row.canonical_host, row.username, row.slug),
    )
    selected = usable[0]
    selected_record_type = record_type or ("key" if selected.has_key else "password")
    if selected_record_type == "key" and not selected.has_key:
        raise CredentialNotFound(f"No key credential record exists for {selected.slug}")
    if selected_record_type == "password" and not selected.has_password:
        raise CredentialNotFound(f"No password credential record exists for {selected.slug}")
    return selected.slug, selected_record_type



def _handle_credential_cli(args: argparse.Namespace, *, store: CredentialStore | None = None) -> int:
    store = store or CredentialStore()
    try:
        if args.credential_command == "set-default":
            if not getattr(sys.stdin, "isatty", lambda: False)():
                raise CredentialValidationError("credential set-default requires an interactive terminal")
            username, password, ssh_key = _prompt_default_credential(store)
            metadata = store.set_default_credential(username, password=password, ssh_key=ssh_key)
            print(json.dumps({"status": "stored", "default_credential": {"username": metadata.username, "has_password": metadata.has_password, "has_ssh_key": metadata.has_ssh_key}}, sort_keys=True))
            return 0
        if args.credential_command == "add":
            slug = args.slug.strip()
            parsed = parse_slug(slug)
            record_type = "key" if args.key else "password"
            if record_type == "key":
                secret = Path(args.key).read_text(encoding="utf-8")
            else:
                secret = _read_password_secret()
            sudo_password = _read_optional_sudo_password_for_ssh_slug() if parsed.purpose == "ssh" else ""
            if store.record_exists(slug, record_type):
                raise CredentialRecordExists(f"{record_type} record already exists for {slug}")
            if sudo_password:
                sudo_slug = build_slug("sudo", parsed.username, parsed.canonical_host)
                if store.record_exists(sudo_slug, "password"):
                    raise CredentialRecordExists(f"password record already exists for {sudo_slug}")
            metadata = store.store_record(slug, record_type, secret)
            if sudo_password:
                store.store_record(build_slug("sudo", parsed.username, parsed.canonical_host), "password", sudo_password)
            print(json.dumps({"status": "stored", "credential": metadata.to_dict()}, sort_keys=True))
            return 0
        if args.credential_command == "list":
            rows = store.list_metadata(host=args.host, user=args.user, purpose=args.purpose)
            try:
                default_credential = store.get_default_credential()
            except CredentialNotFound:
                default_credential = None
            if args.json:
                print(json.dumps({"status": "ok", "credentials": [row.to_dict() for row in rows], "default_credential": default_credential.to_dict() if default_credential else None}, sort_keys=True))
            else:
                print(_format_credential_list(rows, default_credential))
            return 0
        if args.credential_command == "show":
            slug = args.slug.strip()
            print(json.dumps({"status": "ok", "credential": store.show_metadata(slug).to_dict()}, sort_keys=True))
            return 0
        if args.credential_command == "remove":
            slug = args.slug.strip()
            record_type = "password" if args.password else "key"
            metadata = store.remove_record(slug, record_type)
            print(json.dumps({"status": "removed", "credential": metadata.to_dict()}, sort_keys=True))
            return 0
        if args.credential_command == "unlock":
            record_type = "key" if args.key else "password" if args.password else None
            slug_arg = args.slug.strip() if args.slug else None
            if not slug_arg and not args.host and not args.user and not args.purpose:
                try:
                    result = store.unlock_default_credential(record_type)
                except CredentialNotFound:
                    pass
                else:
                    print(json.dumps(result, sort_keys=True))
                    return 0
            slug, record_type = _select_unlock_target(
                store,
                slug=slug_arg,
                host=args.host,
                user=args.user,
                purpose=args.purpose,
                record_type=record_type,
            )
            result = store.unlock_record(slug, record_type)
            print(json.dumps(result, sort_keys=True))
            return 0
    except (CredentialError, CredentialValidationError, OSError) as exc:
        print(json.dumps(_credential_error(exc), sort_keys=True), file=sys.stderr)
        return 1
    raise ValueError(f"Unknown credential command: {args.credential_command}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _registry.idle_timeout_seconds = args.session_idle_timeout_seconds
    if args.command == "credential":
        return _handle_credential_cli(args)

    server = create_server()
    server.settings.host = args.host
    server.settings.port = args.port
    server.settings.mount_path = args.mount_path
    server.run(args.transport)
    return 0


atexit.register(_cleanup_sessions)

if __name__ == "__main__":
    raise SystemExit(main())
