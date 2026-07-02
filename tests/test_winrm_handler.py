from types import SimpleNamespace

from bifrost_mcp.winrm_handler import WinRMHandler


def test_winrm_handler_reports_transport():
    handler = WinRMHandler()

    assert handler.transport == "winrm"


def test_winrm_handler_run_command_without_open_session_raises():
    handler = WinRMHandler()

    try:
        handler.run_command("hostname")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "not open" in str(exc).lower()


def test_winrm_handler_open_session_sets_metadata():
    handler = WinRMHandler()

    session_id = handler.open_session(host="example.com", username="Administrator", port=5985, password="secret")

    assert session_id == handler.session_id
    assert handler.host == "example.com"
    assert handler.username == "Administrator"
    assert handler.port == 5985
    assert handler.canonical_host == "example.com"


def test_winrm_handler_unsupported_interactive_operations():
    handler = WinRMHandler()
    handler.open_session(host="example.com", username="Administrator", port=5985, password="secret")

    for call in [
        lambda: handler.send_input("dir\n"),
        lambda: handler.send_control("ctrl-c"),
        lambda: handler.resize_session(120, 40),
        lambda: handler.read_output(),
        lambda: handler.flush_output_buffer(),
    ]:
        try:
            call()
            assert False, "expected NotImplementedError"
        except NotImplementedError:
            pass


def test_winrm_handler_run_command_passes_powershell_script_text_to_run_ps(monkeypatch):
    calls = {}

    class FakeSession:
        def __init__(self, target, auth, transport, server_cert_validation, read_timeout_sec, operation_timeout_sec):
            calls.update(
                target=target,
                auth=auth,
                transport=transport,
                server_cert_validation=server_cert_validation,
                read_timeout_sec=read_timeout_sec,
                operation_timeout_sec=operation_timeout_sec,
            )

        def run_ps(self, command):
            calls["command"] = command
            return SimpleNamespace(status_code=0, std_out=b"host\r\n", std_err=b"")

    monkeypatch.setattr("bifrost_mcp.winrm_handler.winrm.Session", FakeSession)
    handler = WinRMHandler()
    handler.open_session(host="Example.COM", username="EXAMPLE\\Administrator", port=5985, password="secret")

    script = "Get-ChildItem | ForEach-Object { $_.Name }"
    result = handler.run_command(script)

    assert result["status"] == "completed"
    assert result["exit_code"] == 0
    assert result["stdout"] == "host\r\n"
    assert result["stderr"] == ""
    assert calls["target"] == "http://Example.COM:5985/wsman"
    assert calls["auth"] == ("EXAMPLE\\Administrator", "secret")
    assert calls["transport"] == "ntlm"
    assert calls["server_cert_validation"] == "ignore"
    assert calls["command"] == script


def test_winrm_handler_run_command_returns_nonzero_exit(monkeypatch):
    class FakeSession:
        def __init__(self, target, auth, transport, server_cert_validation, read_timeout_sec, operation_timeout_sec):
            pass

        def run_ps(self, command):
            return SimpleNamespace(status_code=5, std_out=b"", std_err=b"Access denied")

    monkeypatch.setattr("bifrost_mcp.winrm_handler.winrm.Session", FakeSession)
    handler = WinRMHandler()
    handler.open_session(host="example.com", username="EXAMPLE\\Administrator", port=5986, password="secret", use_ssl=True, auth="basic")

    result = handler.run_command("Get-Item C:\\")

    assert result == {
        "status": "completed",
        "stdout": "",
        "stderr": "Access denied",
        "exit_code": 5,
    }
