"""Unit tests for tools.forensics and tools.crypto_binary — file/binary
analysis tools that operate on container-local paths and skip the allowlist."""

from __future__ import annotations

from tools import crypto_binary, forensics


def test_analyze_memory_volatility_skips_allowlist(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "vol", 0, "PID PPID ImageFileName\n1  0  System\n")
    result = forensics.analyze_memory_volatility(dump_path="/tmp/dump.raw", plugin="windows.pslist")
    assert result["success"] is True
    assert fake_container.calls[0] == ["vol", "-f", "/tmp/dump.raw", "windows.pslist"]


def test_disassemble_binary_r2_default_command(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "r2", 0, "0x08048000  main\n")
    result = forensics.disassemble_binary_r2(binary_path="/tmp/vuln")
    assert result["success"] is True
    assert fake_container.calls[0] == ["r2", "-q", "-c", "aaa; afl", "/tmp/vuln"]


def test_extract_binwalk_uses_extract_flag(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "binwalk", 0, "DECIMAL  HEX  DESCRIPTION\n")
    result = forensics.extract_binwalk(file_path="/tmp/firmware.bin")
    assert result["success"] is True
    assert fake_container.calls[0] == ["binwalk", "-e", "/tmp/firmware.bin"]


def test_analyze_binary_angr_writes_script_then_runs_python(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "python3", 0, "42\n")
    result = crypto_binary.analyze_binary_angr(binary_path="/tmp/vuln", analysis="result = 42")

    assert result["success"] is True
    write_calls = [c for c in fake_container.calls if c[0] == "sh"]
    assert write_calls  # the base64-write step happened
    run_calls = [c for c in fake_container.calls if c[0] == "python3"]
    assert run_calls
    assert run_calls[0][1].startswith("/tmp/angr_")


def test_exploit_pwntools_helper_skips_allowlist(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "python3", 0, "b'flag{test}'\n")
    result = crypto_binary.exploit_pwntools_helper(script="from pwn import *\nprint('hi')")
    assert result["success"] is True
