"""Bounded checks for the forensic command timeout and process cleanup."""

import copy
import tempfile

import pytest
from pydantic import ValidationError

from forensic_app import kape_plan, worker
from forensic_app.modes import KAPE_TEMPLATE, CommandStep


@pytest.mark.parametrize("value", [True, False, 1.0, 1.5, "10", 0, 604801])
def test_command_timeout_requires_bounded_integer(value):
    with pytest.raises(ValidationError):
        CommandStep(timeout_seconds=value)
    assert CommandStep().timeout_seconds == 86400
    assert CommandStep(timeout_seconds=1).timeout_seconds == 1
    assert CommandStep(timeout_seconds=604800).timeout_seconds == 604800


def test_compiled_command_and_mode_snapshot_keep_timeout(tmp_path, monkeypatch):
    executable = tmp_path / "kape.exe"
    executable.write_bytes(b"synthetic fixture, never executed")
    monkeypatch.setattr(kape_plan, "windows_arguments", lambda _: [
        "--msource", "Targets\\C", "--mdest", "PostMortem", "--module", "Synthetic"
    ])
    mode = {"id": "synthetic-mode", **copy.deepcopy(KAPE_TEMPLATE).model_dump()}
    mode["steps"][0].update(tool_id="synthetic-kape", timeout_seconds=17)
    plan = kape_plan.compile_plan(mode, [{"id": "synthetic-kape", "path": str(executable)}])
    assert plan["mode"]["steps"][0]["timeout_seconds"] == 17
    assert plan["commands"][0]["timeout_seconds"] == 17


@pytest.mark.parametrize("configured, expected", [(2, 2), (None, 86400)])
def test_timeout_closes_guard_and_process(tmp_path, monkeypatch, configured, expected):
    executable = tmp_path / "synthetic.exe"
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(worker, "is_admin", lambda: True)
    monkeypatch.setattr(worker, "sha256_file", lambda _: "matching")
    clock = iter([0.0, float(expected + 1)])
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(clock))
    events = []

    class FakeGuard:
        def assign(self, handle):
            events.append("assign")

        def resume(self, pid):
            events.append("resume")

        def close(self):
            events.append("close")

    class FakeProcess:
        def __init__(self, stdout):
            self.pid = 123
            self._handle = 456
            self.stdout = stdout
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            events.append("kill")
            self.returncode = -9

        def wait(self, timeout):
            events.append("wait")
            return self.returncode

    monkeypatch.setattr(worker, "ProcessGuard", FakeGuard)
    plan = {"tool": {"path": str(executable), "sha256": "matching"}, "argv": [str(executable)]}
    if configured is not None:
        plan["timeout_seconds"] = configured
    with tempfile.TemporaryFile() as stdout:
        monkeypatch.setattr(worker.subprocess, "Popen", lambda *args, **kwargs: FakeProcess(stdout))
        with pytest.raises(ValueError, match=f"Zeitlimit von {expected} Sekunden"):
            worker.execute(plan, tmp_path, lambda: None, lambda _: None)
    assert events == ["assign", "resume", "close", "kill", "wait"]
