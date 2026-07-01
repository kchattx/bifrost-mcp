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


def test_registry_accepts_transport_neutral_session():
    handler: RemoteSessionHandler = FakeRemoteSession()
    registry = SessionRegistry(sessions={})

    registry.register(handler)

    [info] = registry.list_info()
    assert info.session_id == "fake-1"
    assert info.transport == "fake"
    assert info.to_dict()["transport"] == "fake"


def test_transport_neutral_modules_do_not_reference_ssh_handler():
    checked = [
        Path("bifrost_mcp/session.py"),
        Path("bifrost_mcp/session_registry.py"),
    ]
    forbidden = "SSH" + "Handler"
    for path in checked:
        assert forbidden not in path.read_text(encoding="utf-8")
