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
    CredentialError,
    CredentialNotFound,
    CredentialRecordExists,
    CredentialStore,
    CredentialValidationError,
    build_slug,
    canonicalize_host,
)
from bifrost_mcp.session_registry import SessionRegistry
from bifrost_mcp.ssh_handler import SSHHandler

_IDLE_TIMEOUT_SECONDS = float(os.getenv("BIFROST_MCP_SESSION_IDLE_TIMEOUT_SECONDS", "3600"))
_sessions: dict[str, SSHHandler] = {}
_registry = SessionRegistry(idle_timeout_seconds=_IDLE_TIMEOUT_SECONDS, sessions=_sessions)


def _server_instructions() -> str:
    return (
        "Bifrost MCP provides tools to create, interact with, read from, transfer files for, and close SSH sessions. "
        "Secrets are resolved server-side from gopass credentials; never ask the agent to pass passwords."
    )


def _error(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error": {"code": code, "message": message}}


def _credential_error(exc: Exception) -> dict[str, Any]:
    code = getattr(exc, "code", "credential_error")
    return _error(str(code), str(exc))


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


def _create_ssh_session_impl(host: str, username: str, port: int = 22, *, store: CredentialStore | None = None) -> dict[str, Any]:
    _validate_create_session_inputs(host, username, port)
    canonical_host = canonicalize_host(host, port)
    slug = build_slug("ssh", username, canonical_host)
    store = store or CredentialStore()
    try:
        auth = store.resolve_ssh_auth(slug)
    except CredentialNotFound as exc:
        return _error("missing_credential", str(exc))
    except CredentialError as exc:
        return _credential_error(exc)

    handler = SSHHandler()
    try:
        session_id = handler.open_session(
            host=host,
            username=username,
            port=port,
            auth_mode="key" if auth.auth_type == "key" else "password",
            password=auth.secret if auth.auth_type == "password" else None,
            private_key=auth.secret if auth.auth_type == "key" else None,
        )
    except Exception as exc:
        return _error("ssh_connection_failed", str(exc))
    _registry.register(handler)
    return {"status": "created", "session_id": session_id, "host": canonical_host, "username": username, "port": port}


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


def _get_session(session_id: str) -> SSHHandler:
    return _registry.get(session_id)


def create_server() -> FastMCP:
    server = FastMCP(name="bifrost", instructions=_server_instructions())

    @server.tool(description="List non-secret stored credential metadata for one host.")
    def list_credentials(host: str) -> dict[str, Any]:
        return _list_credentials_impl(host)

    @server.tool(description="Open a new interactive SSH session using server-side stored credentials.")
    def create_ssh_session(host: str, username: str, port: int = 22) -> dict[str, Any]:
        return _create_ssh_session_impl(host, username, port)

    @server.tool(description="Send raw text to an active SSH session.")
    def send_input(session_id: str, text: str) -> dict[str, str]:
        handler = _get_session(session_id)
        handler.send_input(text)
        return {"status": "accepted", "session_id": session_id}

    @server.tool(description="Send a supported terminal control key to an active SSH session.")
    def send_control(session_id: str, key: str) -> dict[str, str]:
        handler = _get_session(session_id)
        handler.send_control(key)
        return {"status": "accepted", "session_id": session_id}

    @server.tool(description="Resize the active SSH session pseudo-terminal.")
    def resize_session(session_id: str, width: int, height: int) -> dict[str, str]:
        handler = _get_session(session_id)
        handler.resize_session(width, height)
        return {"status": "resized", "session_id": session_id}

    @server.tool(description="Read buffered output from an active SSH session and optionally clear it.")
    def read_output(session_id: str, clear_buffer: bool = True) -> dict[str, str]:
        handler = _get_session(session_id)
        output = handler.flush_output_buffer() if clear_buffer else handler.read_output()
        return {"status": "ok", "session_id": session_id, "output": output}

    @server.tool(description="Wait for remote session output matching a regex or literal pattern.")
    def wait_for_output(session_id: str, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, Any]:
        handler = _get_session(session_id)
        result = handler.wait_for_output(pattern, timeout, regex=regex, clear_buffer=clear_buffer)
        result["session_id"] = session_id
        return result

    @server.tool(description="Run a command inside the existing interactive SSH shell session.")
    def run_command(session_id: str, command: str, timeout: float = 30) -> dict[str, Any]:
        handler = _get_session(session_id)
        result = handler.run_command(command, timeout=timeout)
        result["session_id"] = session_id
        return result

    @server.tool(description="Check whether sudo cache is warm without prompting.")
    def check_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        return _get_session(session_id).check_sudo_cache(timeout=timeout)

    @server.tool(description="Warm sudo credentials using server-managed gopass sudo password.")
    def warm_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        handler = _get_session(session_id)
        if not handler.username or not handler.canonical_host:
            return _error("missing_session_metadata", "Session is missing username or canonical host metadata.")
        slug = build_slug("sudo", handler.username, handler.canonical_host)
        try:
            password = CredentialStore().resolve_sudo_password(slug)
        except CredentialNotFound as exc:
            return _error("missing_credential", str(exc))
        except CredentialError as exc:
            return _credential_error(exc)
        return handler.warm_sudo_cache(password, timeout=timeout)

    @server.tool(description="Clear remote sudo timestamp cache with sudo -k.")
    def clear_sudo_cache(session_id: str, timeout: float = 10) -> dict[str, Any]:
        return _get_session(session_id).clear_sudo_cache(timeout=timeout)

    @server.tool(description="Upload an MCP-server-local file to the remote host over SFTP.")
    def upload_file(session_id: str, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, Any]:
        return _get_session(session_id).upload_file(local_path, remote_path, create_parents=create_parents)

    @server.tool(description="Download a remote file to an MCP-server-local path over SFTP.")
    def download_file(session_id: str, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, Any]:
        return _get_session(session_id).download_file(remote_path, local_path, create_parents=create_parents)

    @server.tool(description="List all active SSH sessions managed by this MCP server.")
    def list_sessions() -> dict[str, Any]:
        return {"sessions": [info.to_dict() for info in _registry.list_info()]}

    @server.tool(description="Close an active SSH session and remove it from server state.")
    def close_ssh_session(session_id: str) -> dict[str, str]:
        handler = _get_session(session_id)
        handler.close_session()
        _sessions.pop(session_id, None)
        return {"status": "closed", "session_id": session_id}

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

    list_cmd = credential_sub.add_parser("list", help="List non-secret credential metadata.")
    list_cmd.add_argument("--host")
    list_cmd.add_argument("--user")
    list_cmd.add_argument("--purpose", choices=("ssh", "sudo"))

    show = credential_sub.add_parser("show", help="Show non-secret credential metadata for a slug.")
    show.add_argument("slug")

    remove = credential_sub.add_parser("remove", help="Remove one credential record from a slug.")
    remove.add_argument("slug")
    remove_group = remove.add_mutually_exclusive_group(required=True)
    remove_group.add_argument("--password", action="store_true")
    remove_group.add_argument("--key", action="store_true")
    return parser


def _read_password_secret() -> str:
    if getattr(sys.stdin, "isatty", lambda: False)():
        return getpass.getpass("Credential password: ")
    return sys.stdin.read().rstrip("\n")


def _handle_credential_cli(args: argparse.Namespace, *, store: CredentialStore | None = None) -> int:
    store = store or CredentialStore()
    try:
        if args.credential_command == "add":
            record_type = "key" if args.key else "password"
            if record_type == "key":
                secret = Path(args.key).read_text(encoding="utf-8")
            else:
                secret = _read_password_secret()
            metadata = store.store_record(args.slug, record_type, secret)
            print(json.dumps({"status": "stored", "credential": metadata.to_dict()}, sort_keys=True))
            return 0
        if args.credential_command == "list":
            rows = [row.to_dict() for row in store.list_metadata(host=args.host, user=args.user, purpose=args.purpose)]
            print(json.dumps({"status": "ok", "credentials": rows}, sort_keys=True))
            return 0
        if args.credential_command == "show":
            print(json.dumps({"status": "ok", "credential": store.show_metadata(args.slug).to_dict()}, sort_keys=True))
            return 0
        if args.credential_command == "remove":
            record_type = "password" if args.password else "key"
            metadata = store.remove_record(args.slug, record_type)
            print(json.dumps({"status": "removed", "credential": metadata.to_dict()}, sort_keys=True))
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
