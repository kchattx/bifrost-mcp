import time
from pathlib import Path

from bifrost_mcp.session import RemoteSessionHandler
from bifrost_mcp.session_registry import SessionRegistry


class FakeRemoteSession:
    transport = "fake"

    def __init__(self, session_id="fake-1"):
        self.session_id = session_id
        self.host = "host.example"
        self.canonical_host = "host.example"
        self.username = "user"
        self.port = 1234
        self.created_at = time.monotonic()
        self.last_activity_at = self.created_at
        self.closed = False

    def close_session(self) -> None:
        self.closed = True

    def send_input(self, text: str) -> None:
        return None

    def send_control(self, key: str) -> None:
        return None

    def resize_session(self, width: int, height: int) -> None:
        return None

    def read_output(self) -> str:
        return ""

    def flush_output_buffer(self) -> str:
        return ""

    def wait_for_output(self, pattern: str, timeout: float, regex: bool = True, clear_buffer: bool = True) -> dict[str, object]:
        return {"status": "matched", "output": ""}

    def run_command(self, command: str, timeout: float = 30) -> dict[str, object]:
        return {"status": "completed", "stdout": "", "stderr": "", "exit_code": 0}

    def check_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        return {"status": "ok"}

    def warm_sudo_cache(self, sudo_password: str, timeout: float = 10) -> dict[str, object]:
        return {"status": "ok"}

    def clear_sudo_cache(self, timeout: float = 10) -> dict[str, object]:
        return {"status": "ok"}

    def upload_file(self, local_path: str, remote_path: str, create_parents: bool = False) -> dict[str, object]:
        return {"status": "ok"}

    def download_file(self, remote_path: str, local_path: str, create_parents: bool = False) -> dict[str, object]:
        return {"status": "ok"}


def test_registry_accepts_transport_neutral_session():
    handler: RemoteSessionHandler = FakeRemoteSession()
    registry = SessionRegistry(sessions={})

    registry.register(handler)

    [info] = registry.list_info()
    assert info.session_id == "fake-1"
    assert info.transport == "fake"
    assert info.to_dict()["transport"] == "fake"


def test_registry_lists_winrm_transport():
    handler: RemoteSessionHandler = FakeRemoteSession("winrm-1")
    handler.transport = "winrm"
    registry = SessionRegistry(sessions={})

    registry.register(handler)

    [info] = registry.list_info()
    assert info.session_id == "winrm-1"
    assert info.transport == "winrm"


def test_transport_neutral_modules_do_not_reference_ssh_handler():
    checked = [
        Path("bifrost_mcp/session.py"),
        Path("bifrost_mcp/session_registry.py"),
    ]
    forbidden = "SSH" + "Handler"
    for path in checked:
        assert forbidden not in path.read_text(encoding="utf-8")
