from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from intelhex import IntelHex

# ---------------------------------------------------------------------------
# App Boilerplate 2.1.0 ELF release URLs
# ---------------------------------------------------------------------------

_RELEASE_BASE = "https://github.com/LedgerHQ/app-boilerplate/releases/download/2.1.0"
BOILERPLATE_ELF_URLS: dict[str, str] = {
    "nanox": f"{_RELEASE_BASE}/app-2.1.0-nanox.elf",
    "nanos2": f"{_RELEASE_BASE}/app-2.1.0-nanos2.elf",
    "stax": f"{_RELEASE_BASE}/app-2.1.0-stax.elf",
    "flex": f"{_RELEASE_BASE}/app-2.1.0-flex.elf",
    "apex_p": f"{_RELEASE_BASE}/app-2.1.0-apex_p.elf",
}

_CACHE = Path(__file__).parent / ".cache"


def _fetch_hex(device: str) -> Path:
    """Download the ELF for *device* and convert to Intel HEX, with caching."""
    _CACHE.mkdir(exist_ok=True)
    url = BOILERPLATE_ELF_URLS[device]
    elf = _CACHE / f"app-2.1.0-{device}.elf"
    hex_path = _CACHE / f"app-2.1.0-{device}.hex"

    if not elf.exists():
        try:
            urllib.request.urlretrieve(url, elf)
        except (urllib.error.URLError, OSError) as exc:
            pytest.skip(f"Could not download {url}: {exc}")

    if not hex_path.exists():
        ih = IntelHex()
        with elf.open("rb") as f:
            ef = ELFFile(f)
            for segment in ef.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    ih.frombytes(segment.data(), offset=segment["p_paddr"])
            ih.start_addr = {"EIP": ef["e_entry"]}
        ih.write_hex_file(str(hex_path))

    return hex_path


@pytest.fixture(scope="session")
def boilerplate_nanox_hex() -> Path:
    return _fetch_hex("nanox")


@pytest.fixture(scope="session")
def boilerplate_nanos2_hex() -> Path:
    return _fetch_hex("nanos2")


@pytest.fixture(scope="session")
def boilerplate_stax_hex() -> Path:
    return _fetch_hex("stax")


@pytest.fixture(scope="session")
def boilerplate_flex_hex() -> Path:
    return _fetch_hex("flex")


@pytest.fixture(scope="session")
def boilerplate_apex_p_hex() -> Path:
    return _fetch_hex("apex_p")
