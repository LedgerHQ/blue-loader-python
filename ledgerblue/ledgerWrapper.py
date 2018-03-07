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
"""

import struct
from .commException import CommException


def wrapCommandAPDU(channel, command, packetSize, ble=False):
    if packetSize < 3:
        raise CommException("Can't handle Ledger framing with less than 3 bytes for the report")
    sequence_idx = 0
    offset = 0
    if not ble:
        result = struct.pack(">H", channel)
        extra_header_size = 2
    else:
        result = ""
        extra_header_size = 0
    result += struct.pack(">BHH", 0x05, sequence_idx, len(command))
    sequence_idx = sequence_idx + 1
    if len(command) > packetSize - 5 - extra_header_size:
        block_size = packetSize - 5 - extra_header_size
    else:
        block_size = len(command)
    result += command[offset: offset + block_size]
    offset = offset + block_size
    while offset != len(command):
        if not ble:
            result += struct.pack(">H", channel)
        result += struct.pack(">BH", 0x05, sequence_idx)
        sequence_idx = sequence_idx + 1
        if (len(command) - offset) > packetSize - 3 - extra_header_size:
            block_size = packetSize - 3 - extra_header_size
        else:
            block_size = len(command) - offset
        result += command[offset: offset + block_size]
        offset = offset + block_size
    if not ble:
        while (len(result) % packetSize) != 0:
            result += b"\x00"
    return bytearray(result)


def unwrapResponseAPDU(channel, data, packetSize, ble=False):
    sequence_idx = 0
    offset = 0
    if not ble:
        extra_header_size = 2
    else:
        extra_header_size = 0
    if (data is None) or (len(data) < 5 + extra_header_size + 5):
        return None
    if not ble:
        if struct.unpack(">H", data[offset: offset + 2])[0] != channel:
            raise CommException("Invalid channel")
        offset += 2
    if data[offset] != 0x05:
        raise CommException("Invalid tag")
    offset += 1
    if struct.unpack(">H", data[offset: offset + 2])[0] != sequence_idx:
        raise CommException("Invalid sequence")
    offset += 2
    response_length = struct.unpack(">H", data[offset: offset + 2])[0]
    offset += 2
    if len(data) < 5 + extra_header_size + response_length:
        return None
    if response_length > packetSize - 5 - extra_header_size:
        block_size = packetSize - 5 - extra_header_size
    else:
        block_size = response_length
    result = data[offset: offset + block_size]
    offset += block_size
    while len(result) != response_length:
        sequence_idx = sequence_idx + 1
        if offset == len(data):
            return None
        if not ble:
            if struct.unpack(">H", data[offset: offset + 2])[0] != channel:
                raise CommException("Invalid channel")
            offset += 2
        if data[offset] != 0x05:
            raise CommException("Invalid tag")
        offset += 1
        if struct.unpack(">H", data[offset: offset + 2])[0] != sequence_idx:
            raise CommException("Invalid sequence")
        offset += 2
        if (response_length - len(result)) > packetSize - 3 - extra_header_size:
            block_size = packetSize - 3 - extra_header_size
        else:
            block_size = response_length - len(result)
        result += data[offset: offset + block_size]
        offset += block_size
    return bytearray(result)
