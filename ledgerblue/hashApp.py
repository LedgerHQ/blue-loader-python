"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************

Compute the SHA-256 application hash from a .hex file.

The digest matches the value computed device-side at install time. It is built
by hashing, in order:

    target_id            (4 bytes, big endian)
    api_level            (1 byte)
    code_length          (4 bytes, big endian)
    data_length          (4 bytes, big endian)
    install_params_length(4 bytes, big endian)
    flags                (4 bytes, big endian)
    boot_offset          (4 bytes, big endian)
    image                (the loaded bytes, minAddr..maxAddr, gaps zero-padded)

code_length is derived as ``maxAddr - minAddr - data_length - install_params_length``.
boot_offset comes from the HEX start-linear-address record (type 0x05), made
relative to minAddr and OR-ed with 1 (Thumb bit).

Parameters not stored in the .hex (target_id, api_level, flags, data_length,
install_params_length) must be supplied by the caller; retrieve them from the
ELF ledger.* sections or the target device SDK.

This module is the single source of truth for the application hash and is reused
by :mod:`ledgerblue.loadApp`.
"""

import argparse
import hashlib
import struct

from .hexParser import IntelHexParser


def auto_int(x):
    return int(x, 0)


def get_argparser():
    parser = argparse.ArgumentParser(
        description="Calculate an application hash from the application's hex file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Parameters not stored in the .hex must be supplied on the command line;
retrieve them from the ELF ledger.* sections or the target device SDK:

  --targetId            ledger.target_id
  --apiLevel            ledger.api_level
  --appFlags            ledger.app_flags
  --dataSize            _envram_data - _nvram_data          (symbol arithmetic)
  --installparamsSize   _einstall_parameters - _install_parameters

code_length is derived automatically as:
    maxAddr - minAddr - dataSize - installparamsSize

boot_offset is taken from the HEX start-linear-address record (type 0x05),
made relative to minAddr and OR-ed with 1 (Thumb bit).
""",
    )
    parser.add_argument(
        "--hex", help="The application hex file to be hashed", required=True
    )
    parser.add_argument(
        "--targetId",
        help="The device's target ID (e.g. 0x33100004)",
        type=auto_int,
        required=True,
    )
    parser.add_argument(
        "--apiLevel", help="API level (e.g. 26)", type=int, required=True
    )
    parser.add_argument(
        "--appFlags",
        help="Application flags (e.g. 0x800)",
        type=auto_int,
        required=True,
    )
    parser.add_argument(
        "--dataSize",
        help="_envram_data - _nvram_data in bytes",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--installparamsSize",
        help="_einstall_parameters - _install_parameters in bytes",
        type=int,
        required=True,
    )
    return parser


def compute_app_hash(
    hex_path, target_id, api_level, flags, data_length, install_params_length
):
    """Return (digest_hex, info) for the application described by hex_path.

    The digest matches the application hash computed device-side: it hashes the
    target ID, the createApp parameters (api_level, code_length, data_length,
    install_params_length, flags, boot_offset) and the loaded image bytes.
    """
    parser = IntelHexParser(hex_path)

    min_addr = parser.minAddr()
    max_addr = parser.maxAddr()  # exclusive end (start + len)
    span = max_addr - min_addr

    code_length = span - data_length - install_params_length
    if code_length < 0:
        raise ValueError("dataSize + installparamsSize exceeds the image span")

    # Build the contiguous image, zero-padding any gaps between areas.
    data = bytearray(span)
    for area in parser.getAreas():
        offset = area.getStart() - min_addr
        chunk = area.getData()
        data[offset : offset + len(chunk)] = chunk

    # boot_offset: relative to minAddr, Thumb bit forced.
    boot_addr = parser.getBootAddr()
    if boot_addr > min_addr:
        boot_addr -= min_addr
    boot_offset = boot_addr | 1

    m = hashlib.sha256()
    m.update(struct.pack(">I", target_id))
    # maintain compatibility with SDKs not handling API level: when api_level is
    # -1 (e.g. Nano S), HexLoader.createApp omits the api_level byte from the
    # createApp parameters.
    if api_level != -1:
        m.update(struct.pack(">B", api_level))
    m.update(struct.pack(">I", code_length))
    m.update(struct.pack(">I", data_length))
    m.update(struct.pack(">I", install_params_length))
    m.update(struct.pack(">I", flags))
    m.update(struct.pack(">I", boot_offset))
    m.update(bytes(data))

    info = {
        "target_id": target_id,
        "api_level": api_level,
        "flags": flags,
        "code_length": code_length,
        "data_length": data_length,
        "install_params_length": install_params_length,
        "boot_offset": boot_offset,
        "load_length": len(data),
    }
    return m.hexdigest(), info


def main():
    args = get_argparser().parse_args()

    digest, info = compute_app_hash(
        args.hex,
        args.targetId,
        args.apiLevel,
        args.appFlags,
        args.dataSize,
        args.installparamsSize,
    )

    print(f"{'hex':>24} = {args.hex}")
    for name, value in info.items():
        print(f"{name:>24} = {value} (0x{value:x})")
    print(f"{'sha256':>24} = {digest}")


if __name__ == "__main__":
    main()
