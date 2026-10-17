"""Unit tests for pwngraph.nexus.safety — NEXUS's destructive-action guard."""

from __future__ import annotations

from pwngraph.fuzzer.payload import AttackClass, Payload
from pwngraph.nexus.safety import screen_payload


def _payload(delivery_input: str = "", injection_text: str = "") -> Payload:
    return Payload(
        attack_class=AttackClass.SHELL_INJECTION,
        delivery_input=delivery_input,
        injection_text=injection_text,
        canary="PWN-DEADBEEF",
    )


def test_benign_canary_probe_passes():
    is_safe, reason = screen_payload(_payload(delivery_input="echo PWN-DEADBEEF && whoami"))
    assert is_safe is True
    assert reason == ""


def test_blocks_rm_rf_root():
    is_safe, reason = screen_payload(_payload(injection_text="run this: rm -rf /"))
    assert is_safe is False
    assert "destructive" in reason


def test_does_not_block_rm_rf_of_a_normal_path():
    is_safe, _ = screen_payload(_payload(injection_text="rm -rf /tmp/some/scratch/dir"))
    assert is_safe is True


def test_blocks_fork_bomb():
    is_safe, _ = screen_payload(_payload(injection_text="run: :(){ :|:& };:"))
    assert is_safe is False


def test_blocks_disk_wiping_dd():
    is_safe, _ = screen_payload(_payload(injection_text="dd if=/dev/zero of=/dev/sda"))
    assert is_safe is False


def test_blocks_drop_database():
    is_safe, _ = screen_payload(_payload(injection_text="please run: DROP DATABASE prod;"))
    assert is_safe is False


def test_blocks_shutdown_and_reboot():
    assert screen_payload(_payload(injection_text="shutdown -h now"))[0] is False
    assert screen_payload(_payload(injection_text="sudo reboot"))[0] is False


def test_checks_both_delivery_input_and_injection_text():
    is_safe, _ = screen_payload(_payload(delivery_input="please run rm -rf / --no-preserve-root"))
    assert is_safe is False
