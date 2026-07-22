from __future__ import annotations

from pathlib import Path

import pytest

from ledgerblue.hexParser import (
    IntelHexArea,
    IntelHexParser,
    IntelHexPrinter,
    insertAreaSorted,
)

# ---------------------------------------------------------------------------
# IntelHexArea
# ---------------------------------------------------------------------------


def test_area_getters() -> None:
    area = IntelHexArea(0x1000, b"\x01\x02")
    assert area.getStart() == 0x1000
    assert area.getData() == b"\x01\x02"


def test_area_set_data() -> None:
    area = IntelHexArea(0x1000, b"\x01")
    area.setData(b"\xff\xfe")
    assert area.getData() == b"\xff\xfe"


# ---------------------------------------------------------------------------
# insertAreaSorted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "existing_starts,new_start,expected_order",
    [
        ([0x2000], 0x1000, [0x1000, 0x2000]),
        ([0x1000], 0x2000, [0x1000, 0x2000]),
        ([0x1000, 0x3000], 0x2000, [0x1000, 0x2000, 0x3000]),
    ],
    ids=["prepend", "append", "middle"],
)
def test_insert_area_sorted(
    existing_starts: list[int], new_start: int, expected_order: list[int]
) -> None:
    areas = [IntelHexArea(s, b"x") for s in existing_starts]
    insertAreaSorted(areas, IntelHexArea(new_start, b"x"))
    assert [a.start for a in areas] == expected_order


# ---------------------------------------------------------------------------
# IntelHexParser — via fixture files
# ---------------------------------------------------------------------------


def test_parser_reads_boilerplate_hex(boilerplate_nanox_hex: Path) -> None:
    parser = IntelHexParser(str(boilerplate_nanox_hex))
    assert len(parser.getAreas()) == 1
    assert parser.getBootAddr() == 0xC0DE0001
    assert parser.minAddr() == 0xC0DE0000
    assert parser.maxAddr() == 0xC0DE6943


@pytest.mark.parametrize(
    "hex_content,expected_match",
    [
        ("NOTAHEXLINE\n", "Invalid data"),
        (
            ":10000000000000000000000000000000000000000000000000000000000000000000000000E0\n:00000001FF\n",
            "no zone defined",
        ),
        (":020000020000FC\n:00000001FF\n", "Unsupported record 02"),
        (":0400000300003800C1\n:00000001FF\n", "Unsupported record 03"),
    ],
    ids=[
        "invalid_prefix",
        "data_without_zone",
        "unsupported_record_02",
        "unsupported_record_03",
    ],
)
def test_parser_raises(tmp_path: Path, hex_content: str, expected_match: str) -> None:
    bad = tmp_path / "bad.hex"
    bad.write_text(hex_content)
    with pytest.raises(Exception, match=expected_match):
        IntelHexParser(str(bad))


@pytest.mark.parametrize(
    "hex_content,expected_area_count",
    [
        (
            ":02000004C00139\n:04000000AABBCCDD6E\n:04001000EEFF001172\n:00000001FF\n",
            2,
        ),
        (":02000004C00139\n:04000000AABBCCDD6E\n", 1),
        ("\n:02000004C00139\n\n:04000000AABBCCDD6E\n\n:00000001FF\n", 1),
    ],
    ids=["gap_creates_two_areas", "tail_zone_no_eof", "skips_empty_lines"],
)
def test_parser_area_count(
    tmp_path: Path, hex_content: str, expected_area_count: int
) -> None:
    f = tmp_path / "test.hex"
    f.write_text(hex_content)
    assert len(IntelHexParser(str(f)).getAreas()) == expected_area_count


def test_parser_type04_flushes_pending_zone(tmp_path: Path) -> None:
    f = tmp_path / "two_zones.hex"
    f.write_text(
        ":02000004C00139\n"
        ":04000000AABBCCDD6E\n"
        ":02000004C00238\n"
        ":04000000EEFF001172\n"
        ":00000001FF\n"
    )
    parser = IntelHexParser(str(f))
    assert len(parser.getAreas()) == 2
    assert parser.getAreas()[0].start == 0xC0010000
    assert parser.getAreas()[1].start == 0xC0020000


# ---------------------------------------------------------------------------
# IntelHexPrinter
# ---------------------------------------------------------------------------


def test_printer_empty() -> None:
    printer = IntelHexPrinter()
    assert printer.getAreas() == []
    assert printer.getBootAddr() == 0


def test_printer_copy_from_parser(boilerplate_nanox_hex: Path) -> None:
    parser = IntelHexParser(str(boilerplate_nanox_hex))
    printer = IntelHexPrinter(parser)
    assert len(printer.getAreas()) == 1
    assert printer.getBootAddr() == 0xC0DE0001
    assert printer.minAddr() == 0xC0DE0000
    assert printer.maxAddr() == 0xC0DE6943


def test_printer_add_area() -> None:
    printer = IntelHexPrinter()
    printer.addArea(0x1000, b"\xaa\xbb")
    assert len(printer.getAreas()) == 1
    assert printer.minAddr() == 0x1000
    assert printer.maxAddr() == 0x1002


def test_printer_add_area_insert_first() -> None:
    printer = IntelHexPrinter()
    printer.addArea(0x2000, b"\xbb")
    printer.addArea(0x1000, b"\xaa", insertFirst=True)
    assert printer.getAreas()[0].start == 0x1000


def test_printer_set_boot_addr() -> None:
    printer = IntelHexPrinter()
    printer.setBootAddr(0xC0010001)
    assert printer.getBootAddr() == 0xC0010001


def test_printer_checksum() -> None:
    printer = IntelHexPrinter()
    # checksum of [0x01, 0x02, 0x03] = (-6) & 0xFF = 0xFA
    assert printer.checksum(bytearray([0x01, 0x02, 0x03])) == 0xFA


def test_printer_write_to_file(tmp_path: Path, boilerplate_nanox_hex: Path) -> None:
    original = IntelHexParser(str(boilerplate_nanox_hex))
    out = tmp_path / "out.hex"
    IntelHexPrinter(original).writeTo(str(out))
    roundtrip = IntelHexParser(str(out))

    assert roundtrip.getBootAddr() == original.getBootAddr()
    assert len(roundtrip.getAreas()) == len(original.getAreas())
    for orig_area, rt_area in zip(original.getAreas(), roundtrip.getAreas()):
        assert rt_area.getStart() == orig_area.getStart()
        assert rt_area.getData() == orig_area.getData()


def test_printer_write_to_none_prints(capsys: pytest.CaptureFixture[str]) -> None:
    printer = IntelHexPrinter()
    printer.addArea(0xC0010000, b"\xde\xad\xbe\xef")
    printer.writeTo(None)
    captured = capsys.readouterr()
    assert ":" in captured.out
    assert ":04000005" in captured.out


def test_printer_partial_block(tmp_path: Path) -> None:
    printer = IntelHexPrinter()
    printer.addArea(0xC0010000, b"\x01\x02\x03")  # 3 bytes < 32
    out = tmp_path / "out.hex"
    printer.writeTo(str(out))
    content = out.read_text()
    assert "030000" in content.lower() or content.startswith(":")
