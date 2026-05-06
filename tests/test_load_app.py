from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.loadApp import (
    auto_int,
    main,
    parse_bip32_path,
    parse_slip21_path,
    string_to_bytes,
)

FIXTURES = Path(__file__).parent / "fixtures"
TEST_ROOT_PRIVATE_KEY = "aa" * 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_offline(
    hex_file: Path,
    output_file: Path,
    extra_args: list[str] | None = None,
    debug: bool = False,
) -> str | None:
    args = []
    args += ["--fileName", str(hex_file)]
    args += ["--appName", "TestApp"]
    args += ["--offline", str(output_file)]
    args += ["--appFlags", "0"]
    args += ["--targetId", "0x33000004"]
    args += ["--appVersion", "1.0.0"]
    args += ["--tlv"]
    args += ["--rootPrivateKey", TEST_ROOT_PRIVATE_KEY]
    if extra_args:
        args += extra_args
    return main(args, debug=debug)


def assert_matches_reference(output: Path, reference_name: str) -> None:
    reference = FIXTURES / reference_name
    if os.environ.get("UPDATE_SNAPSHOTS"):
        reference.write_bytes(output.read_bytes())
        pytest.skip("Snapshot updated")
    assert output.read_bytes() == reference.read_bytes()


# ---------------------------------------------------------------------------
# Pure-function unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0x10", 16),
        ("255", 255),
    ],
)
def test_auto_int(value: str, expected: int) -> None:
    assert auto_int(value) == expected


def test_string_to_bytes() -> None:
    assert string_to_bytes("hello") == b"hello"


@pytest.mark.parametrize(
    "path,expected",
    [
        ("", b""),
        (
            "44'/0'/0'",
            struct.pack(">B", 3)
            + struct.pack(">I", 0x80000000 | 44)
            + struct.pack(">I", 0x80000000 | 0)
            + struct.pack(">I", 0x80000000 | 0),
        ),
        (
            "0/1",
            struct.pack(">B", 2) + struct.pack(">I", 0) + struct.pack(">I", 1),
        ),
    ],
)
def test_parse_bip32_path(path: str, expected: bytes) -> None:
    assert parse_bip32_path(path) == expected


def test_parse_slip21_path() -> None:
    result = parse_slip21_path("SLIP21")
    length_byte = 0x80 | (len("SLIP21") + 1)
    expected = struct.pack(">B", length_byte) + b"\x00" + b"SLIP21"
    assert result == expected


# ---------------------------------------------------------------------------
# Offline integration tests — loadApp argument combinations
# ---------------------------------------------------------------------------


def test_offline_debug_prints(
    tmp_path: Path,
    boilerplate_nanox_hex: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output.apdu"
    run_offline(boilerplate_nanox_hex, output, debug=True)
    captured = capsys.readouterr()
    assert "Application full hash" in captured.out


@pytest.mark.parametrize(
    "extra_args,reference",
    [
        (["--bootAddr", "0xC0DE0001"], "ref_boot_addr_above_min.apdu"),
        (["--curve", "secp256k1"], "ref_curve_secp256k1.apdu"),
        (["--curve", "secp256r1"], "ref_curve_secp256r1.apdu"),
        (["--curve", "ed25519"], "ref_curve_ed25519.apdu"),
        (["--curve", "bls12381g1"], "ref_curve_bls12381g1.apdu"),
        (["--path", "44'/0'/0'"], "ref_path.apdu"),
        (["--path", ""], "ref_empty_path.apdu"),
        (["--path_slip21", "SLIP21Test"], "ref_slip21.apdu"),
        (["--path_slip21", "MyPath"], "ref_slip21_no_bip32_path.apdu"),
        (["--icon", "010203"], "ref_icon.apdu"),
        (["--signature", "deadbeef"], "ref_signature.apdu"),
        (["--installparamsSize", "8"], "ref_installparams_size.apdu"),
        (["--dep", "Bitcoin:1.0.0"], "ref_dep_with_version.apdu"),
        (["--dep", "Bitcoin"], "ref_dep_no_version.apdu"),
        (["--tlvraw", "20:deadbeef"], "ref_tlvraw.apdu"),
        (["--delete"], "ref_delete.apdu"),
        (["--nocrc"], "ref_nocrc.apdu"),
    ],
    ids=[
        "boot_addr_above_min",
        "curve_secp256k1",
        "curve_secp256r1",
        "curve_ed25519",
        "curve_bls12381g1",
        "path",
        "empty_path",
        "slip21",
        "slip21_no_bip32_path",
        "icon",
        "signature",
        "installparams_size",
        "dep_with_version",
        "dep_no_version",
        "tlvraw",
        "delete",
        "nocrc",
    ],
)
def test_offline_arg(
    tmp_path: Path,
    boilerplate_nanox_hex: Path,
    extra_args: list[str],
    reference: str,
) -> None:
    output = tmp_path / "output.apdu"
    result = run_offline(boilerplate_nanox_hex, output, extra_args=extra_args)
    assert isinstance(result, str) and len(result) == 64  # hex-encoded sha256
    assert_matches_reference(output, reference)


def test_offline_unknown_curve_raises(
    tmp_path: Path, boilerplate_nanox_hex: Path
) -> None:
    output = tmp_path / "output.apdu"
    with pytest.raises(Exception, match="Unknown curve"):
        run_offline(boilerplate_nanox_hex, output, extra_args=["--curve", "badcurve"])


def test_offline_with_apdu_flag(
    tmp_path: Path,
    boilerplate_nanox_hex: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "output.apdu"
    run_offline(boilerplate_nanox_hex, output, extra_args=["--apdu"])
    captured = capsys.readouterr()
    assert len(captured.out) > 0
    assert_matches_reference(output, "ref_apdu_flag.apdu")


# ---------------------------------------------------------------------------
# Smoke tests — verify each code path runs without error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra_args",
    [[], ["--icon", "010203040506"]],
    ids=["no_icon", "with_icon"],
)
def test_smoke_params_mode(
    tmp_path: Path, boilerplate_nanox_hex: Path, extra_args: list[str]
) -> None:
    output = tmp_path / "output.apdu"
    main([
        "--fileName", str(boilerplate_nanox_hex),
        "--appName", "TestApp",
        "--offline", str(output),
        "--params",
        "--appFlags", "0",
        "--targetId", "0x33000004",
        "--appVersion", "1.0.0",
    ] + extra_args, debug=False)
    assert output.stat().st_size > 0


def test_smoke_no_tlv_no_params(tmp_path: Path, boilerplate_nanox_hex: Path) -> None:
    output = tmp_path / "output.apdu"
    main([
        "--fileName", str(boilerplate_nanox_hex),
        "--appName", "TestApp",
        "--offline", str(output),
        "--appFlags", "0",
        "--targetId", "0x33000004",
        "--appVersion", "1.0.0",
    ], debug=False)
    assert output.stat().st_size > 0


@pytest.mark.parametrize("debug", [True, False], ids=["debug", "no_debug"])
def test_smoke_sign_app(
    tmp_path: Path, boilerplate_nanox_hex: Path, debug: bool
) -> None:
    output = tmp_path / "output.apdu"
    key = PrivateKey()
    run_offline(
        boilerplate_nanox_hex,
        output,
        extra_args=["--signApp", "--signPrivateKey", key.serialize()],
        debug=debug,
    )
    assert output.stat().st_size > 0


def test_smoke_boot_addr_at_min(tmp_path: Path, boilerplate_nanox_hex: Path) -> None:
    output = tmp_path / "output.apdu"
    run_offline(boilerplate_nanox_hex, output, extra_args=["--bootAddr", "0xC0DE0000"])
    assert output.stat().st_size > 0


def test_smoke_main_entry_point(tmp_path: Path, boilerplate_nanox_hex: Path) -> None:
    import runpy
    import sys

    output = tmp_path / "output.apdu"
    sys.argv = [
        "loadApp",
        "--fileName", str(boilerplate_nanox_hex),
        "--appName", "TestApp",
        "--offline", str(output),
        "--tlv",
        "--appFlags", "0",
        "--targetId", "0x33000004",
        "--appVersion", "1.0.0",
    ]
    with pytest.raises(SystemExit):
        runpy.run_module("ledgerblue.loadApp", run_name="__main__", alter_sys=True)
    assert output.stat().st_size > 0
