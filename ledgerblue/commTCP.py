"""
*******************************************************************************
*   Ledger Blue
*   (c) 2019 Ledger
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

from .commException import CommException
from binascii import hexlify
import socket
import struct

class DongleServer(object):
	def __init__(self, server, port, debug=False):
		self.server = server
		self.port = port
		self.debug = debug
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.socket.connect((self.server, self.port))
		except:
			raise CommException("Proxy connection failed")

	def exchange(self, apdu, timeout=20000):
		if self.debug:
			print("=> %s" % hexlify(apdu))		
		self.socket.send(struct.pack(">I", len(apdu)))
		self.socket.send(apdu)
		size = struct.unpack(">I", self.socket.recv(4))[0]
		response = self.socket.recv(size)
		sw = struct.unpack(">H", self.socket.recv(2))[0]
		if self.debug:
			print("<= %s%.2x" % (hexlify(response), sw))
		if sw != 0x9000:
			raise CommException("Invalid status %04x" % sw, sw)
		return bytearray(response)

	def apduMaxDataSize(self):
		return 240

	def close(self):
		try:
			self.socket.close()
		except:
			pass

def getDongle(server="127.0.0.1", port=9999, debug=False):
    return DongleServer(server, port, debug)
