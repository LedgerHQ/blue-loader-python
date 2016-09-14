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
	sequenceIdx = 0		
	offset = 0	
	if not ble:
		result = struct.pack(">H", channel)
		extraHeaderSize = 2
	else:
		result = ""
		extraHeaderSize = 0
	result += struct.pack(">BHH", 0x05, sequenceIdx, len(command))
	sequenceIdx = sequenceIdx + 1
	if len(command) > packetSize - 5 - extraHeaderSize:
		blockSize = packetSize - 5 - extraHeaderSize
	else:
		blockSize = len(command)
	result += command[offset : offset + blockSize]
	offset = offset + blockSize
	while offset != len(command):
		if not ble:
			result += struct.pack(">H", channel) 		
		result += struct.pack(">BH", 0x05, sequenceIdx)
		sequenceIdx = sequenceIdx + 1
		if (len(command) - offset) > packetSize - 3 - extraHeaderSize:
			blockSize = packetSize - 3 - extraHeaderSize
		else:
			blockSize = len(command) - offset
		result += command[offset : offset + blockSize]
		offset = offset + blockSize
	if not ble:		
		while (len(result) % packetSize) != 0:
			result += b"\x00"
	return bytearray(result)

def unwrapResponseAPDU(channel, data, packetSize, ble=False):
	sequenceIdx = 0		
	offset = 0
	if not ble:
		extraHeaderSize = 2
	else:
		extraHeaderSize = 0	
	if ((data is None) or (len(data) < 5 + extraHeaderSize + 5)):
		return None
	if not ble:
		if struct.unpack(">H", data[offset : offset + 2])[0] != channel:
			raise CommException("Invalid channel")
		offset += 2
	if data[offset] != 0x05:
		raise CommException("Invalid tag")
	offset += 1
	if struct.unpack(">H", data[offset : offset + 2])[0] != sequenceIdx:
		raise CommException("Invalid sequence")
	offset += 2
	responseLength = struct.unpack(">H", data[offset : offset + 2])[0]
	offset += 2
	if len(data) < 5 + extraHeaderSize + responseLength:
		return None
	if responseLength > packetSize - 5 - extraHeaderSize:
		blockSize = packetSize - 5 - extraHeaderSize
	else:
		blockSize = responseLength
	result = data[offset : offset + blockSize]
	offset += blockSize
	while (len(result) != responseLength):
		sequenceIdx = sequenceIdx + 1
		if (offset == len(data)):
			return None
		if not ble:
			if struct.unpack(">H", data[offset : offset + 2])[0] != channel:
				raise CommException("Invalid channel")
			offset += 2
		if data[offset] != 0x05:
			raise CommException("Invalid tag")
		offset += 1
		if struct.unpack(">H", data[offset : offset + 2])[0] != sequenceIdx:
			raise CommException("Invalid sequence")
		offset += 2
		if (responseLength - len(result)) > packetSize - 3 - extraHeaderSize:
			blockSize = packetSize - 3 - extraHeaderSize
		else:
			blockSize = responseLength - len(result)
		result += data[offset : offset + blockSize]
		offset += blockSize
	return bytearray(result)
