"""Regression tests: no shell interpolation of CLI arguments.

Defect: run_command() built a shell string with subprocess.Popen(shell=True).
main() passed `f"waybackurls {args.target} > {output_file}"`
(sqli-checker.py:55 before the fix) and
`f"sqlmap -m {sqliurls_file} ... | tee -a {args.output}"`
(sqli-checker.py:93 before the fix), where args.target (sqli-checker.py:72)
and args.output (sqli-checker.py:73) come straight from argv.

So `python sqli-checker.py -t "x; touch /tmp/pwned" -o out.txt` executed
`touch /tmp/pwned` with the operator's privileges.

Fails on the original module, passes on the patched one.
"""
import importlib.util
import os
import pathlib
import subprocess
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "sqli-checker.py"
_spec = importlib.util.spec_from_file_location("sqli_checker", SRC)
sqli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sqli)

URL_LINE = "http://example.test/index.php?id=1\n"


class _FakeProc:
    """Stands in for both CompletedProcess and Popen."""

    def __init__(self, stdout_fh=None):
        self._fh = stdout_fh
        self.stdout = b"sqlmap done\n"
        self.stderr = b""
        self.returncode = 0

    def communicate(self):
        if self._fh is not None and hasattr(self._fh, "write"):
            self._fh.write(URL_LINE)
        return self.stdout, self.stderr


def _spy(monkeypatch):
    """Intercept every subprocess call the module could make, without executing."""
    calls = []

    def fake_run(argv, shell=False, stdout=None, stderr=None, timeout=None, **kw):
        calls.append({"argv": argv, "shell": shell})
        return _FakeProc(stdout)

    def fake_popen(command, shell=False, stdout=None, stderr=None, **kw):
        calls.append({"argv": command, "shell": shell})
        return _FakeProc(stdout)

    monkeypatch.setattr(sqli.subprocess, "run", fake_run)
    monkeypatch.setattr(sqli.subprocess, "Popen", fake_popen)
    # Pretend both tools are installed so no installer path is taken.
    monkeypatch.setattr(sqli.shutil, "which", lambda name: f"/usr/bin/{name}")
    return calls


def _run_main(monkeypatch, target, output):
    monkeypatch.setattr(
        sys, "argv", ["sqli-checker.py", "-t", target, "-o", output]
    )
    sqli.main()
    sqli.DEBUG = False


def test_no_subprocess_call_ever_enables_a_shell(monkeypatch, tmp_path):
    calls = _spy(monkeypatch)
    monkeypatch.chdir(tmp_path)

    _run_main(monkeypatch, "example.test", "results.txt")

    assert calls, "expected the scanner to invoke waybackurls/sqlmap"
    for call in calls:
        assert call["shell"] is False, f"shell enabled for: {call['argv']!r}"


def test_target_injection_payload_is_passed_as_one_literal_argument(monkeypatch, tmp_path):
    calls = _spy(monkeypatch)
    monkeypatch.chdir(tmp_path)
    payload = "x; touch /tmp/pwned"

    _run_main(monkeypatch, payload, "results.txt")

    matched = [
        call for call in calls
        if isinstance(call["argv"], list) and payload in call["argv"]
    ]
    assert matched, f"payload never reached a tool as a single argv element: {calls!r}"
    # No argument was split apart by a shell, so `touch` is not its own command.
    for call in calls:
        argv = call["argv"]
        if isinstance(argv, list):
            assert "touch" not in argv, f"payload was split into a command: {argv!r}"


def test_output_injection_payload_is_not_interpolated(monkeypatch, tmp_path):
    calls = _spy(monkeypatch)
    monkeypatch.chdir(tmp_path)
    payload = "out.txt & touch /tmp/pwned2"

    _run_main(monkeypatch, "example.test", payload)

    for call in calls:
        argv = call["argv"]
        if isinstance(argv, list):
            assert "touch" not in argv, f"payload was split into a command: {argv!r}"
    assert not (tmp_path / "pwned2").exists()


def test_run_command_executes_without_a_shell_for_real(tmp_path):
    """End-to-end proof with a genuine subprocess: no shell, no side effect."""
    sep = "&" if os.name == "nt" else ";"
    marker = tmp_path / "pwned"
    payload = f"x {sep} echo PWNED> {marker}"

    stdout, _stderr = sqli.run_command(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", payload]
    )

    assert not marker.exists(), "shell metacharacters were interpreted"
    assert payload in stdout, "argument was mangled instead of passed literally"


def test_source_contains_no_shell_true():
    src = SRC.read_text(encoding="utf-8")
    assert "shell=True" not in src, "shell=True must not exist in this module"