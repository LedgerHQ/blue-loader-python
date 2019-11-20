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
		self.opened = True
		try:
			self.socket.connect((self.server, self.port))
		except:
			raise CommException("Proxy connection failed")

	def exchange(self, apdu, timeout=20000):

		def send_apdu(apdu):
			if self.debug:
				print("=> %s" % hexlify(apdu))
			self.socket.send(struct.pack(">I", len(apdu)))
			self.socket.send(apdu)

		def get_data():
			size = struct.unpack(">I", self.socket.recv(4))[0]
			response = self.socket.recv(size)
			sw = struct.unpack(">H", self.socket.recv(2))[0]
			if self.debug:
				print("<= %s%.2x" % (hexlify(response), sw))
			return (sw, response)


		send_apdu(apdu)
		(sw, response) = get_data()
		if sw == 0x9000:
			return bytearray(response)
		else:
			# handle the get response case:
			# When more data is available, the chip sends 0x61XX
			# So 0x61xx as a SW must not be interpreted as an error
			if (sw & 0xFF00) != 0x6100:
				raise CommException("Invalid status %04x" % sw, sw)
			else:
				while (sw & 0xFF00) == 0x6100:
					send_apdu(bytes.fromhex("00c0000000"))  # GET RESPONSE
					(sw, data) = get_data()
					response += data

				# Check that the last received SW is indeed 0x9000
				if sw == 0x9000:
					return bytearray(response)

		# In any other case return an exception
		raise CommException("Invalid status %04x" % sw, sw)

	def apduMaxDataSize(self):
		return 240

	def close(self):
		try:
			self.socket.close()
			self.socket = None
		except:
			pass
		self.opened = False

def getDongle(server="127.0.0.1", port=9999, debug=False):
    return DongleServer(server, port, debug)
