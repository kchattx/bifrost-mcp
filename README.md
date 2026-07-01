# Bifrost MCP

Bifrost MCP exposes an MCP server for managing persistent interactive SSH sessions. Codex, Hermes Agent, or another MCP client can install this project locally and use it over stdio through the `bifrost-mcp` entrypoint.

Bifrost MCP is an MCP server for bridging AI agents to persistent remote SSH sessions, with command execution, terminal interaction, sudo cache management, and SFTP file transfer. It uses Paramiko as its SSH client; it does not shell out to `ssh`, does not use `sshpass`, and does not assume access to host-mounted key files inside a container. Command execution is MCP-first and runs through the existing interactive shell session; `exec_command` is intentionally not implemented.

Bifrost MCP currently focuses on SSH-backed remote shells. Future versions are intended to extend the same MCP-first control plane to additional remote-management transports such as WinRM, while preserving the same safety model: server-side credential resolution, explicit session state, and no secret material returned to the agent.

## Requirements

- Python 3.11 or newer
- `mcp[cli]`
- `paramiko`
- `gopass` CLI for credential storage, installed and initialized in the same operating-system environment that runs `bifrost-mcp`

## Local Installation

Install Bifrost MCP in the same operating-system environment that will run the MCP client. For example, if Codex or Hermes Agent runs inside WSL, create the venv in WSL and use WSL paths. If the client runs on Windows, create a Windows venv and use Windows paths.

WSL/Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
.venv/bin/bifrost-mcp --help
.venv/bin/python -m bifrost_mcp --help
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\bifrost-mcp.exe --help
.\.venv\Scripts\python.exe -m bifrost_mcp --help
```

## Install In Codex

Register the local stdio server with Codex. Prefer the installed `bifrost-mcp` console script instead of `python -m bifrost_mcp`; it avoids CLI parsing problems with dash-prefixed Python arguments in some MCP registration commands.

WSL/Linux, using the WSL virtualenv:

```bash
codex mcp add bifrost -- /path/to/bifrost-mcp/.venv/bin/bifrost-mcp
```

Windows PowerShell, using the Windows virtualenv:

```powershell
codex mcp add bifrost -- C:\path\to\bifrost-mcp\.venv\Scripts\bifrost-mcp.exe
```

You can also edit Codex's config file directly. Use the config file for the environment where Codex runs, for example `~/.codex/config.toml` in WSL/Linux or `%USERPROFILE%\.codex\config.toml` on Windows:

```toml
[mcp_servers.bifrost]
command = "/path/to/bifrost-mcp/.venv/bin/bifrost-mcp"
args = []
```

Windows equivalent:

```toml
[mcp_servers.bifrost]
command = "C:\\path\\to\\bifrost-mcp\\.venv\\Scripts\\bifrost-mcp.exe"
args = []
```

## Install In Hermes Agent

Hermes Agent has a native MCP client. Register Bifrost MCP as a stdio MCP server with the `hermes mcp add` command. Use the console script as the command and leave `--args` empty.

For most users, prefer the setup helper. It creates the virtualenv, installs Bifrost, verifies `gopass`, registers the MCP server, and writes runtime path settings to Hermes MCP config rather than `.env`:

```bash
scripts/setup-hermes-mcp.sh --profile lseng --home /home/hermes
```

Why explicit `--home` matters: Hermes profiles, containers, systemd units, and web UIs may run MCP subprocesses with a profile-scoped or service-specific `HOME`. Bifrost credentials are stored under the operating-system account home that owns the `gopass` and GPG store. The setup helper therefore registers Bifrost with explicit environment values such as:

```yaml
mcp_servers:
  bifrost:
    command: /home/hermes/mcp_servers/bifrost-mcp/.venv/bin/bifrost-mcp
    env:
      HOME: /home/hermes
      GNUPGHOME: /home/hermes/.gnupg
```

Do not put SSH passwords, GPG passphrases, or private keys in Hermes `.env` or `config.yaml`. `.env` is for application secrets such as API tokens; Bifrost SSH/sudo secrets belong in `gopass`, GPG agent, SSH agent, or another real secret manager.

WSL/Linux, using the WSL virtualenv:

```bash
hermes mcp add bifrost \
  --command /path/to/bifrost-mcp/.venv/bin/bifrost-mcp
```

Windows PowerShell, using the Windows virtualenv:

```powershell
hermes mcp add bifrost `
  --command C:\path\to\bifrost-mcp\.venv\Scripts\bifrost-mcp.exe
```

The `hermes mcp add` command connects immediately and prompts which discovered tools to enable. Accept all tools, or choose selectively.

Direct `~/.hermes/config.yaml` equivalent:

```yaml
mcp_servers:
  bifrost:
    command: "/path/to/bifrost-mcp/.venv/bin/bifrost-mcp"
    args: []
```

Windows path equivalent, for a Hermes process running on Windows:

```yaml
mcp_servers:
  bifrost:
    command: "C:\\path\\to\\bifrost-mcp\\.venv\\Scripts\\bifrost-mcp.exe"
    args: []
```

Verify the Hermes MCP registration:

```bash
hermes mcp test bifrost
hermes mcp list
```

After adding or changing the MCP server, restart Hermes Agent or run `/reload-mcp` inside an active Hermes session. Bifrost MCP tools are exposed with Hermes' MCP prefix, for example:

```text
mcp_bifrost_create_ssh_session
mcp_bifrost_run_command
```

## Running The MCP Server Directly

Codex should use the default `stdio` transport:

```bash
bifrost-mcp --transport stdio
```

For MCP protocol debugging, the server also supports MCP HTTP transports:

```bash
bifrost-mcp --transport sse --host 127.0.0.1 --port 8000
bifrost-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

Session cleanup defaults to one hour of inactivity and can be configured with either:

```bash
BIFROST_MCP_SESSION_IDLE_TIMEOUT_SECONDS=1800 bifrost-mcp
bifrost-mcp --session-idle-timeout-seconds 1800
```

## gopass Setup

Bifrost MCP reads SSH and sudo secrets from `gopass`. Install and initialize `gopass` in the same operating-system environment that runs the `bifrost-mcp` server process:

- If Codex or Hermes Agent launches Bifrost MCP from a WSL/Linux virtualenv, install and initialize `gopass` in WSL/Linux.
- If Codex or Hermes Agent launches Bifrost MCP from a Windows virtualenv, install and initialize Windows `gopass` and make sure it is on that process's `PATH`.
- Do not initialize only Windows `gopass` for a WSL/Linux MCP server, or only WSL/Linux `gopass` for a Windows MCP server.

Install examples:

```bash
# Debian/Ubuntu/WSL
sudo apt update
sudo apt install gopass gnupg
```

```bash
# macOS
brew install gopass gnupg
```

```powershell
# Windows, for a Windows-native Bifrost MCP server
winget install gopass.gopass
# or: choco install gopass
```

Initialize a password store with a GPG identity. If you do not already have a GPG key, create one first:

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format=long
gopass init <gpg-key-id-or-email>
```

If you already have a usable GPG key, you can skip key generation and run only `gopass init <gpg-key-id-or-email>`.

Verify `gopass` is ready in the Bifrost MCP runtime environment:

```bash
command -v gopass
gopass ls
```

`gopass ls` must succeed before `bifrost-mcp credential ...`, `create_ssh_session`, or the sudo cache tools can resolve stored secrets.

Optional sanity test:

```bash
printf '%s' 'test-secret' | gopass insert -m bifrost_mcp/readme-test
gopass show bifrost_mcp/readme-test
gopass rm -f bifrost_mcp/readme-test
```

The sanity-test path is only a temporary `gopass` entry. It is not a Bifrost credential slug.

If `gopass` works in an interactive shell but fails when Bifrost MCP is launched by Codex or Hermes Agent, start the MCP client from the shell where `command -v gopass` and `gopass ls` work, or update the service/desktop environment so the launched process inherits the right `PATH`, GPG agent, and password-store environment. On Windows, restart the terminal or agent after installing `gopass` so `PATH` changes are visible.

## Credential Store Setup

Bifrost MCP requires `gopass` for SSH and sudo secrets. Secrets are managed out-of-band by the local user and are never accepted as normal MCP tool parameters. After `gopass ls` succeeds in the Bifrost MCP runtime environment, add Bifrost credentials with deterministic slugs.

Bifrost stores secret records in `gopass` under `bifrost_mcp/...`; the credential slug remains the stable user-facing identifier. Bifrost keeps only non-secret metadata in `~/.config/bifrost_mcp/credentials.json` so list/show commands do not need to read every secret.

### GPG unlock model

Bifrost intentionally does not accept raw passwords or private keys from agent-facing MCP tools. The MCP server resolves secrets server-side through `gopass`, which in turn relies on GPG. For interactive desktops and developer machines, the recommended security model is:

1. Store SSH/sudo credentials in `gopass`.
2. Warm `gpg-agent` from a real terminal when needed:

   ```bash
   export GPG_TTY=$(tty)
   bifrost-mcp credential unlock
   ```

3. Let `gpg-agent` cache the unlock for a bounded time. You usually unlock once per cache window, not before every MCP tool call. After the TTL expires or after reboot, run `bifrost-mcp credential unlock` again.

The credential unlock command decrypts one existing Bifrost credential only to warm the agent; it does not print secret values. Credentials encrypted to the same GPG key should then work until the cache expires. Use filters only if you need to target a specific credential:

```bash
bifrost-mcp credential unlock --host example-host --user admin
bifrost-mcp credential unlock --purpose ssh
bifrost-mcp credential unlock ssh://admin@example-host
```

A reasonable `~/.gnupg/gpg-agent.conf` is:

```conf
default-cache-ttl 1800
max-cache-ttl 7200
pinentry-program /usr/bin/pinentry-curses
```

Reload it with:

```bash
gpgconf --kill gpg-agent
gpgconf --launch gpg-agent
```

This keeps secrets encrypted at rest, requires an explicit human unlock, and limits the window in which a non-interactive MCP process can decrypt records. For unattended servers, prefer a dedicated service account and a real secret-manager integration or a tightly scoped GPG/pass store. Avoid putting GPG passphrases or SSH passwords in `.env`, shell history, or Hermes config.

Credential slugs are deterministic and safe to display:

```text
<purpose>://<username>@<canonical-host>
```

Rules:

- `purpose` is `ssh` or `sudo`.
- Hosts are lowercase.
- Include `:<port>` only for non-default SSH ports.
- SSH credentials can have a password record, a key record, or both; key records are preferred automatically.
- Sudo credentials are password records only.

Examples:

```text
ssh://admin@example-host
sudo://admin@example-host
ssh://deploy@example-host:2222
```

## Credential CLI

Credentials are managed locally through CLI commands. These commands assume `gopass ls` succeeds in the same environment that runs `bifrost-mcp`:

```bash
# Password record: prompts securely when run from a terminal
bifrost-mcp credential add ssh://admin@example-host --password
bifrost-mcp credential add sudo://admin@example-host --password

# Or read from piped stdin for scripts
printf '%s' 'ssh-password' | bifrost-mcp credential add ssh://admin@example-host --password

# Private key record under the same SSH slug
bifrost-mcp credential add ssh://admin@example-host --key ~/.ssh/id_ed25519

# Metadata only; never prints secrets
bifrost-mcp credential list --host example-host
bifrost-mcp credential show ssh://admin@example-host

# Warm gpg-agent without printing the secret; use once per cache window
bifrost-mcp credential unlock
bifrost-mcp credential unlock ssh://admin@example-host
bifrost-mcp credential unlock --host example-host --user admin

# Remove one record type from an exact slug
bifrost-mcp credential remove ssh://admin@example-host --key
bifrost-mcp credential remove ssh://admin@example-host --password
```

`credential add` refuses to overwrite an existing record of the same type. Use `credential remove` first if rotation is intentional.

### Troubleshooting gopass

- If Bifrost reports that `gopass` is unavailable, install `gopass` in the same OS environment that runs `bifrost-mcp` and confirm `command -v gopass` works there.
- If `gopass ls` fails, initialize the password store with `gopass init <gpg-key-id-or-email>`, unlock the store if needed, or fix the local GPG/password-store configuration.
- If `gopass` works in a shell but not through Codex or Hermes Agent, start the client from the working shell or update the launch environment so `PATH`, GPG agent, and password-store state are available to the MCP server process.
- If WSL/Linux and Windows are both present, initialize `gopass` in the environment whose virtualenv path was registered with Codex or Hermes Agent.

## Available MCP Tools

- `list_credentials(host)`: lists non-secret user metadata for one host, grouped by username.
- `create_ssh_session(host, username, port=22)`: opens a new interactive SSH session using stored `ssh://...` credentials.
- `send_input(session_id, text)`: sends raw text to an existing session.
- `send_control(session_id, key)`: sends one of `ctrl-c`, `ctrl-d`, `ctrl-z`, `enter`, or `escape`.
- `read_output(session_id, clear_buffer=True)`: reads buffered output from a session.
- `wait_for_output(session_id, pattern, timeout, regex=True, clear_buffer=True)`: waits until buffered output matches a regex or literal.
- `run_command(session_id, command, timeout=30)`: runs a command inside the existing interactive shell and waits for a sentinel.
- `check_sudo_cache(session_id, timeout=10)`: runs `sudo -n -v` to check whether sudo is already warm.
- `warm_sudo_cache(session_id, timeout=10)`: derives `sudo://<session-user>@<session-host>`, sends the password server-side, and warms sudo with `sudo -S ... -v`.
- `clear_sudo_cache(session_id, timeout=10)`: invalidates sudo timestamp state with `sudo -k`.
- `upload_file(session_id, local_path, remote_path, create_parents=False)`: uploads one MCP-server-local file over SFTP without overwriting.
- `download_file(session_id, remote_path, local_path, create_parents=False)`: downloads one remote file to an MCP-server-local destination file path without overwriting.
- `resize_session(session_id, width, height)`: resizes the remote PTY.
- `list_sessions()`: returns active session metadata and idle time.
- `close_ssh_session(session_id)`: closes a session and removes it from server state.

## Credential-Backed SSH Flow

1. Call `list_credentials(host)`.
2. If exactly one SSH user is available, use that username. If zero or multiple SSH users are returned, ask the human which login user to use; do not guess.
3. Call `create_ssh_session(host, username, port=22)`.
4. Bifrost MCP derives `ssh://<username>@<canonical-host>` internally, resolves gopass records exactly, prefers key auth if present, otherwise uses password auth, and returns only non-secret session metadata.

Agent-facing SSH session creation does **not** accept `password`, `auth_mode`, `private_key`, or `private_key_passphrase`.

## Command Execution And Interaction

Use `run_command` for ordinary non-interactive shell commands. It runs in the current interactive shell session, preserving state like `cd`, exported variables, and activated virtual environments. If a timeout occurs, Bifrost MCP returns partial output and leaves the remote command running; use `send_control(session_id, "ctrl-c")` if interruption is appropriate.

Use `send_input`, `wait_for_output`, and `send_control` for prompts, installers, pagers, REPLs, and terminal programs.

## Sudo Cache Warming Flow

1. Optionally call `check_sudo_cache(session_id)`.
2. If sudo needs a password, call `warm_sudo_cache(session_id)`.
3. Bifrost MCP derives `sudo://<session-user>@<canonical-host>` internally, retrieves the password server-side, and runs:

```bash
sudo -S -p '[bifrost-mcp sudo password] ' -v && printf '\n__BIFROST_MCP_SUDO_OK__\n' || printf '\n__BIFROST_MCP_SUDO_FAILED__\n'
```

This warms the sudo timestamp cache with `sudo -v`; it does not enter a root shell and does not return the sudo password.

## File Transfer

`local_path` is local to the Bifrost MCP server process filesystem, not necessarily the chat client. V1 supports files only, not recursive directories.

Uploads and downloads refuse to overwrite destination files. Set `create_parents=True` to create missing destination parent directories; otherwise missing parents return structured errors.

```python
upload_file(session_id, "/tmp/local.tgz", "/home/user/local.tgz", create_parents=False)
download_file(session_id, "/var/log/app.log", "/tmp/app.log", create_parents=True)
```

## Transport Architecture

Bifrost currently implements SSH sessions through `SSHHandler`. Internal session storage is transport-neutral so future transports such as WinRM can register sessions with the same metadata and lifecycle shape.

Future WinRM support should add a separate `WinRMHandler` that satisfies the same internal session protocol. It should not emulate a PTY unless the WinRM backend can actually support equivalent behavior; shell-like operations such as `send_input`, `wait_for_output`, and `resize_session` must either return structured `unsupported_operation` errors or be exposed through WinRM-specific tools.

WinRM is not SSH-over-HTTP. Before adding tools, decide per operation:

- `run_command`: likely supported as a command/script execution primitive.
- `send_input`: likely unsupported unless an interactive shell channel is implemented.
- `wait_for_output`: likely unnecessary for one-shot WinRM command execution.
- `resize_session`: unsupported.
- SFTP upload/download: requires a separate file-transfer strategy, not SFTP.
- sudo tools: SSH/Linux-specific; do not apply to WinRM.

## Host Key Handling

Bifrost MCP uses Paramiko host-key handling with an accept-new policy:

- first-seen hosts are added automatically
- changed host keys still fail
- known hosts are stored in a dedicated file under the runtime user's `~/.ssh` directory

## Not Implemented In This Plan

The following features remain deferred by design: host allowlist, audit logging, command mediation/policy enforcement, broad policy subsystem, additional remote-management transports, and Paramiko `exec_command`.
