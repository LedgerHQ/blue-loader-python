from __future__ import annotations

import struct
from pathlib import Path

import pytest

from ledgerblue.hexLoader import (
    BOLOS_TAG_APPNAME,
    HexLoader,
    encodelv,
    encodetlv,
)

# ---------------------------------------------------------------------------
# Mock card
# ---------------------------------------------------------------------------


class MockCard:
    """Captures sent APDUs and returns pre-configured responses."""

    def __init__(self, responses: list[bytearray] | None = None) -> None:
        self.sent: list[bytes] = []
        self._responses: list[bytearray] = list(responses or [])

    def exchange(self, apdu: bytes | bytearray) -> bytearray:
        self.sent.append(bytes(apdu))
        if self._responses:
            return bytearray(self._responses.pop(0))
        return bytearray()

    def apduMaxDataSize(self) -> int:
        return 240

    def close(self) -> None:
        pass

    def last_data(self) -> bytes:
        """Return the data payload (bytes after CLA INS P1 P2 LC) of the last APDU."""
        return self.sent[-1][5:]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def make_loader():
    def _factory(responses=None, **kwargs):
        card = MockCard(responses)
        kwargs.setdefault("secure", False)
        return HexLoader(card, cla=0xE0, **kwargs)

    return _factory


# ---------------------------------------------------------------------------
# encodelv / encodetlv
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size,expected_prefix",
    [
        (2, b"\x02"),  # short: single-byte length
        (127, b"\x7f"),  # short: upper boundary
        (200, b"\x81\xc8"),  # medium: 0x81 + one length byte
        (300, b"\x82\x01\x2c"),  # large:  0x82 + two length bytes
    ],
)
def test_encodelv(size: int, expected_prefix: bytes) -> None:
    data = b"\xaa" * size
    result = encodelv(data)
    assert result[: len(expected_prefix)] == expected_prefix
    assert result[len(expected_prefix) :] == data


def test_encodetlv_basic() -> None:
    result = encodetlv(BOLOS_TAG_APPNAME, b"App")
    assert result[0] == BOLOS_TAG_APPNAME
    assert result[1] == 3
    assert result[2:] == b"App"


# ---------------------------------------------------------------------------
# APDU-level command tests (via captured MockCard APDUs)
# ---------------------------------------------------------------------------


def test_delete_app(make_loader) -> None:
    loader = make_loader()
    loader.deleteApp(b"TestApp")
    data = loader.card.last_data()
    assert data[0:1] == b"\x0c"
    assert data[1] == len(b"TestApp")
    assert data[2:] == b"TestApp"


def test_delete_app_by_hash_valid(make_loader) -> None:
    loader = make_loader()
    h = b"\xab" * 32
    loader.deleteAppByHash(h)
    data = loader.card.last_data()
    assert data[0:1] == b"\x15"
    assert data[1:] == h


def test_delete_app_by_hash_invalid(make_loader) -> None:
    loader = make_loader()
    with pytest.raises(BaseException, match="sha256 expected"):
        loader.deleteAppByHash(b"\xab" * 16)


@pytest.mark.parametrize("signature", [None, b"\xde\xad\xbe\xef"])
def test_boot(make_loader, signature: bytes | None) -> None:
    loader = make_loader()
    kwargs = {"signature": signature} if signature is not None else {}
    loader.boot(0x1000, **kwargs)
    data = loader.card.last_data()
    assert data[0:1] == b"\x09"
    assert struct.unpack(">I", data[1:5])[0] == 0x1001  # thumb bit set
    if signature is not None:
        assert data[5] == len(signature)
        assert data[6:] == signature


@pytest.mark.parametrize(
    "signature,expected_data",
    [
        (None, b"\x09"),
        (b"\x01\x02\x03", b"\x09\x03\x01\x02\x03"),
    ],
)
def test_commit(make_loader, signature: bytes | None, expected_data: bytes) -> None:
    loader = make_loader()
    kwargs = {"signature": signature} if signature is not None else {}
    loader.commit(**kwargs)
    assert loader.card.last_data() == expected_data


@pytest.mark.parametrize(
    "api_level,expected",
    [
        (5,  b"\x0b" + struct.pack(">BIIIII", 5, 256, 16, 8, 0, 1)),
        (-1, b"\x0b" + struct.pack(">IIIII",    256, 16, 8, 0, 1)),
    ],
    ids=["with_api_level", "no_api_level"],
)
def test_create_app(make_loader, api_level: int, expected: bytes) -> None:
    loader = make_loader()
    loader.createApp(
        code_length=256,
        api_level=api_level,
        data_length=16,
        install_params_length=8,
        flags=0,
        bootOffset=1,
    )
    assert loader.card.last_data() == expected


@pytest.mark.parametrize(
    "options,expected_in_payload",
    [
        ({}, b"TestApp\x00"),  # null byte after name when no icon/path
        ({"icon": b"\x01\x02\x03"}, b"\x01\x02\x03"),  # icon bytes present
        (
            {"path": b"\x01\x80\x00\x00\x2c"},
            b"\x01\x80\x00\x00\x2c",
        ),  # path bytes present
        (
            {"iconOffset": 0x100, "iconSize": 64},
            b"\x00\x00\x01\x00",
        ),  # iconOffset encoded big-endian
        ({"appversion": b"1.2.3"}, b"1.2.3"),  # version string present
    ],
)
def test_create_app_no_install_params(
    make_loader, options: dict[str, object], expected_in_payload: bytes
) -> None:
    loader = make_loader()
    loader.createAppNoInstallParams(0, 1024, b"TestApp", **options)
    assert expected_in_payload in loader.card.last_data()


def test_reset_custom_ca(make_loader) -> None:
    loader = make_loader()
    loader.resetCustomCA()
    assert loader.card.last_data() == b"\x13"


def test_setup_custom_ca(make_loader) -> None:
    loader = make_loader()
    loader.setupCustomCA("MyCa", b"\xab\xcd")
    data = loader.card.last_data()
    assert data[0:1] == b"\x12"
    assert data[1] == 4
    assert data[2:6] == b"MyCa"


def test_run_app(make_loader) -> None:
    loader = make_loader()
    loader.runApp(b"MyApp")
    apdu = loader.card.sent[-1]
    assert apdu[1] == 0xD8
    assert apdu[5:] == b"MyApp"


def test_validate_target_id(make_loader) -> None:
    loader = make_loader()
    loader.validateTargetId(0x33000004)
    apdu = loader.card.sent[-1]
    assert apdu[1] == 0x04
    assert struct.unpack(">I", apdu[5:9])[0] == 0x33000004


def test_create_pack(make_loader) -> None:
    loader = make_loader()
    loader.createPack(language=1, code_length=512)
    apdu = loader.card.sent[-1]
    assert apdu[1] == 0x30
    assert apdu[2] == 1
    assert struct.unpack(">I", apdu[5:9])[0] == 512


def test_load_pack_segment_chunk(make_loader) -> None:
    loader = make_loader()
    loader.createPack(language=1, code_length=512)
    loader.loadPackSegmentChunk(0, b"\xaa\xbb")
    assert loader.card.sent[-1][1] == 0x31


@pytest.mark.parametrize(
    "signature,expected_data",
    [
        (None, b""),
        (b"\xab\xcd", b"\x02\xab\xcd"),
    ],
)
def test_commit_pack(
    make_loader, signature: bytes | None, expected_data: bytes
) -> None:
    loader = make_loader()
    loader.createPack(language=1, code_length=512)
    kwargs = {"signature": signature} if signature is not None else {}
    loader.commitPack(**kwargs)
    apdu = loader.card.sent[-1]
    assert apdu[1] == 0x32
    assert loader.card.last_data() == expected_data


def test_delete_pack(make_loader) -> None:
    loader = make_loader()
    loader.deletePack(language=2)
    apdu = loader.card.sent[-1]
    assert apdu[1] == 0x33
    assert apdu[2] == 2


# ---------------------------------------------------------------------------
# Response-parsing methods
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra_bytes,has_mcu_hash",
    [
        (b"\x00" * 32, True),
        (b"", False),
    ],
    ids=["with_mcu_hash", "no_mcu_hash"],
)
def test_get_version(
    make_loader, extra_bytes: bytes, has_mcu_hash: bool
) -> None:
    response = bytearray(
        struct.pack(">I", 0x33000004)
        + b"\x05" + b"2.0.0" + b"\x00"
        + struct.pack(">I", 0xDEAD)
        + b"\x07" + b"MCU1.0"
        + extra_bytes
    )
    loader = make_loader([response])
    result = loader.getVersion()
    assert result["targetId"] == 0x33000004
    assert result["osVersion"] == "2.0.0"
    assert result["flags"] == 0xDEAD
    assert result["mcuVersion"] == "MCU1.0"
    assert ("mcuHash" in result) == has_mcu_hash


def test_get_mem_info(make_loader) -> None:
    r = struct.pack(">IIIII", 1000, 2000, 3000, 5, 20)
    loader = make_loader([bytearray(r)])
    result = loader.getMemInfo()
    assert result["systemSize"] == 1000
    assert result["applicationsSize"] == 2000
    assert result["freeSize"] == 3000
    assert result["usedAppSlots"] == 5
    assert result["totalAppSlots"] == 20


def test_list_app_new_format(make_loader) -> None:
    entry = struct.pack(">I", 0) + b"\xab" * 32 + b"\xcd" * 32 + b"\x05MyApp"
    response = bytearray(b"\x01") + struct.pack(">B", len(entry)) + entry
    loader = make_loader([response])
    result = loader.listApp()
    assert len(result) == 1
    assert result[0]["name"] == "MyApp"
    assert result[0]["flags"] == 0


def test_list_app_old_format(make_loader) -> None:
    name = b"OldApp"
    r = bytearray()
    r += b"\x00"
    r += struct.pack(">B", len(name)) + name
    r += struct.pack(">I", 0xBEEF)
    r += b"\xee" * 32
    loader = make_loader([r])
    result = loader.listApp()
    assert len(result) == 1
    assert result[0]["name"] == "OldApp"
    assert result[0]["flags"] == 0xBEEF


def test_list_app_empty_response(make_loader) -> None:
    loader = make_loader([bytearray()])
    assert loader.listApp() == []


@pytest.mark.parametrize(
    "restart,expected_ins",
    [
        (True, 0xDE),
        (False, 0xDF),
    ],
)
def test_list_app_nonsecure(make_loader, restart: bool, expected_ins: int) -> None:
    loader = make_loader([bytearray()])
    loader.listApp(restart=restart)
    assert loader.card.sent[-1][1] == expected_ins


def test_secure_exchange_encrypts_payload(make_loader) -> None:
    mutauth = b"\x01" * 16
    plaintext = b"\x0c\x07TestApp"  # deleteApp wire format

    loader = make_loader(secure=True, mutauth_result=mutauth)
    loader.deleteApp(b"TestApp")

    wrapped = loader.card.last_data()
    assert wrapped != plaintext  # payload is not sent in cleartext

    decryptor = HexLoader(None, secure=True, mutauth_result=mutauth)
    assert decryptor.scpUnwrap(wrapped) == plaintext


@pytest.mark.parametrize(
    "language_id,expected_substring",
    [
        (0, "English"),
        (99, "Unknown"),
    ],
)
def test_list_packs_language(
    make_loader, language_id: int, expected_substring: str
) -> None:
    entry = (
        struct.pack(">B", 1)
        + struct.pack(">B", language_id)
        + struct.pack(">B", 0)
        + struct.pack(">I", 65536)
        + b"\x051.0.0"
    )
    response = bytearray(b"\x01") + struct.pack(">B", len(entry)) + entry
    loader = make_loader([response])
    result = loader.listPacks()
    assert len(result) == 1
    assert expected_substring in result[0]["Language ID"]


def test_list_packs_empty(make_loader) -> None:
    loader = make_loader([bytearray()])
    assert loader.listPacks() == []


def test_list_packs_restart_vs_no_restart(make_loader) -> None:
    loader = make_loader([bytearray(), bytearray()])
    loader.listPacks(restart=True)
    assert loader.card.sent[-1][2] == 0x00
    loader.listPacks(restart=False)
    assert loader.card.sent[-1][2] == 0x01


def test_list_packs_unsupported_version(make_loader) -> None:
    loader = make_loader([bytearray([0x02])])
    with pytest.raises(Exception, match="Unsupported version format"):
        loader.listPacks()


# ---------------------------------------------------------------------------
# Recovery commands
# ---------------------------------------------------------------------------


def test_recover_confirm_id(make_loader) -> None:
    loader = make_loader()
    loader.recoverConfirmID(b"\xaa" * 4, b"\xbb" * 8)
    assert loader.card.last_data()[0:1] == b"\xd4"


def test_recover_set_ca(make_loader) -> None:
    loader = make_loader()
    loader.recoverSetCA("TestCA", b"\x01\x02")
    data = loader.card.last_data()
    assert data[0:1] == b"\xd2"
    assert b"TestCA" in data


def test_recover_delete_ca(make_loader) -> None:
    loader = make_loader()
    loader.recoverDeleteCA("OldCA", b"\xff")
    assert loader.card.last_data()[0:1] == b"\xd3"


@pytest.mark.parametrize(
    "last,expected_byte",
    [
        (True, b"\x80"),
        (False, b"\x00"),
    ],
)
def test_recover_validate_certificate(
    make_loader, last: bool, expected_byte: bytes
) -> None:
    loader = make_loader()
    loader.recoverValidateCertificate(
        b"\x01", b"\x00", "Name", b"\xab", b"\xcd", last=last
    )
    data = loader.card.last_data()
    assert data[0:1] == b"\xd5"
    assert data[1:2] == expected_byte


def test_recover_mutual_auth(make_loader) -> None:
    loader = make_loader()
    loader.recoverMutualAuth()
    assert loader.card.last_data() == b"\xd6"


def test_recover_validate_hash(make_loader) -> None:
    loader = make_loader([bytearray(b"\x01\x02")])
    loader.recoverValidateHash(b"\xaa" * 16, b"\xbb" * 32)
    assert loader.card.last_data()[0:1] == b"\xd7"


@pytest.mark.parametrize(
    "share_type,expected_byte",
    [
        (None, b"\x00"),
        ("commitments", b"\x01"),
        ("point", b"\x10"),
    ],
)
def test_recover_get_share(
    make_loader, share_type: str | None, expected_byte: bytes
) -> None:
    loader = make_loader([bytearray()])
    args = (share_type,) if share_type is not None else ()
    loader.recoverGetShare(*args)
    data = loader.card.last_data()
    assert data[0:1] == b"\xd8"
    assert data[1:2] == expected_byte


@pytest.mark.parametrize(
    "p1,data,kwargs,expected_byte",
    [
        (0x2, b"\xaa" * 10, {}, b"\x02"),
        (0x3, b"", {"tag": b"\xaa" * 16, "ciphertext": b"\xbb" * 32}, b"\x03"),
        (0x4, b"\xcc" * 5, {}, b"\x04"),
        (0x99, b"", {}, b"\x00"),
    ],
)
def test_recover_validate_commit(
    make_loader, p1: int, data: bytes, kwargs: dict, expected_byte: bytes
) -> None:
    loader = make_loader()
    loader.recoverValidateCommit(p1, data, **kwargs)
    assert loader.card.last_data()[1:2] == expected_byte


@pytest.mark.parametrize(
    "words_number,expected_byte",
    [
        (12, b"\x0c"),
        (18, b"\x12"),
        (24, b"\x00"),
    ],
)
def test_recover_restore_seed(
    make_loader, words_number: int, expected_byte: bytes
) -> None:
    loader = make_loader()
    loader.recoverRestoreSeed(b"\xaa" * 16, b"\xbb" * 32, words_number=words_number)
    assert loader.card.last_data()[1:2] == expected_byte


def test_recover_delete_backup(make_loader) -> None:
    loader = make_loader([bytearray()])
    loader.recoverDeleteBackup(b"\xaa" * 4, b"\xbb" * 8)
    assert loader.card.last_data()[0:1] == b"\xdb"


# ---------------------------------------------------------------------------
# SCP wrap / unwrap
# ---------------------------------------------------------------------------


def test_scp_wrap_noop_when_insecure() -> None:
    loader = HexLoader(None, secure=False)
    data = b"\x01\x02\x03"
    assert loader.scpWrap(data) == data


def test_scp_wrap_noop_on_empty_payload() -> None:
    loader = HexLoader(None, secure=True, mutauth_result=b"\x01" * 16)
    assert loader.scpWrap(b"") == b""


@pytest.mark.parametrize(
    "mutauth,scpv3",
    [
        pytest.param(b"\x01" * 16, False, id="legacy_scp2"),
        pytest.param({"ecdh_secret": b"\x02" * 32}, False, id="scp3_dict"),
        pytest.param(b"\x03" * 32, True, id="scpv3"),
    ],
)
def test_scp_wrap_unwrap_roundtrip(mutauth: object, scpv3: bool) -> None:
    data = b"\xde\xad\xbe\xef"
    loader_w = HexLoader(None, secure=True, mutauth_result=mutauth, scpv3=scpv3)
    wrapped = loader_w.scpWrap(data)
    loader_u = HexLoader(None, secure=True, mutauth_result=mutauth, scpv3=scpv3)
    assert loader_u.scpUnwrap(wrapped) == data


# ---------------------------------------------------------------------------
# exchange / load
# ---------------------------------------------------------------------------


def test_exchange_card_none_prints(capsys: pytest.CaptureFixture[str]) -> None:
    loader = HexLoader(None, secure=False)
    loader.exchange(0xE0, 0x00, 0x00, 0x00, b"\x01\x02")
    assert len(capsys.readouterr().out) > 0


@pytest.mark.parametrize(
    "code_length,target_id,target_version",
    [
        pytest.param(None, 0x33000004, "2.0.0", id="current_target"),
        pytest.param(26947, 0x31000003, "1.0", id="old_format"),
    ],
)
def test_load_returns_hex_hash(
    make_loader,
    boilerplate_nanox_hex: Path,
    code_length: int | None,
    target_id: int,
    target_version: str,
) -> None:
    from ledgerblue.hexParser import IntelHexParser, IntelHexPrinter

    printer = IntelHexPrinter(IntelHexParser(str(boilerplate_nanox_hex)))
    actual_code_length = (
        printer.maxAddr() - printer.minAddr() if code_length is None else code_length
    )
    loader = make_loader()
    loader.createApp(
        code_length=actual_code_length,
        api_level=-1,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    )
    result = loader.load(
        0x00,
        0xF0,
        printer,
        doCRC=True,
        targetId=target_id,
        targetVersion=target_version,
    )
    assert isinstance(result, str) and len(result) == 64


def test_load_reverse(make_loader, boilerplate_nanox_hex: Path) -> None:
    from ledgerblue.hexParser import IntelHexParser, IntelHexPrinter

    printer = IntelHexPrinter(IntelHexParser(str(boilerplate_nanox_hex)))
    loader = make_loader()
    loader.createApp(
        code_length=32,
        api_level=-1,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    )
    result = loader.load(
        0x00,
        0xF0,
        printer,
        reverse=True,
        doCRC=True,
        targetId=0x33000004,
        targetVersion="2.0.0",
    )
    assert len(result) == 64


def test_load_with_cleardata_block_len(make_loader) -> None:
    from ledgerblue.hexParser import IntelHexPrinter

    # 224 bytes (> 222 byte APDU limit) with cleardata_block_len=7:
    # natural chunkLen = 208 (16-aligned), 208%7=5 → adjusted to 203
    # remaining = 21, 21%7=0 → no error
    printer = IntelHexPrinter()
    printer.addArea(0xC0010000, bytes(224))
    loader = make_loader(cleardata_block_len=7)
    loader.createApp(
        code_length=224,
        api_level=-1,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    )
    assert len(loader.load(0x00, 0xF0, printer, doCRC=False)) == 64


def test_load_cleardata_block_len_raises(make_loader) -> None:
    from ledgerblue.hexParser import IntelHexPrinter

    # 31 bytes with cleardata_block_len=16: first chunk → 16, remaining 15 < 16
    printer = IntelHexPrinter()
    printer.addArea(0xC0010000, bytes(31))
    loader = make_loader(cleardata_block_len=16)
    loader.createApp(
        code_length=31,
        api_level=-1,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    )
    with pytest.raises(Exception, match="Cannot transport"):
        loader.load(0x00, 0xF0, printer, doCRC=False)


def test_load_pack_mode(make_loader, boilerplate_nanox_hex: Path) -> None:
    from ledgerblue.hexParser import IntelHexParser, IntelHexPrinter

    printer = IntelHexPrinter(IntelHexParser(str(boilerplate_nanox_hex)))
    loader = make_loader()
    loader.createPack(language=1, code_length=32)
    result = loader.load(0x00, 0xF0, printer, doCRC=False)
    assert len(result) == 64
    assert 0x31 in [apdu[1] for apdu in loader.card.sent]


def test_load_target_version_none(
    make_loader, capsys: pytest.CaptureFixture[str]
) -> None:
    from ledgerblue.hexParser import IntelHexPrinter

    printer = IntelHexPrinter()
    printer.addArea(0xC0010000, bytes(32))
    loader = make_loader()
    loader.createApp(
        code_length=32,
        api_level=-1,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    )
    loader.load(
        0x00, 0xF0, printer, doCRC=False, targetId=0x33000004, targetVersion=None
    )
    assert "not set" in capsys.readouterr().out
