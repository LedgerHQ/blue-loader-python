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

from binascii import hexlify
import hid
import os
import time
import sys

import nfc
from nfc.clf import RemoteTarget

from .commException import CommException
from .commHTTP import getDongle as getDongleHTTP
from .commTCP import getDongle as getDongleTCP
from .commU2F import getDongle as getDongleU2F
from .Dongle import Dongle, DongleWait, TIMEOUT
from .ledgerWrapper import wrapCommandAPDU, unwrapResponseAPDU
from .BleComm import BleDevice


APDUGEN=None
if "APDUGEN" in os.environ and len(os.environ["APDUGEN"]) != 0:
	APDUGEN=os.environ["APDUGEN"]
# Force use of U2F if required
U2FKEY=None
if "U2FKEY" in os.environ and len(os.environ["U2FKEY"]) != 0:
	U2FKEY=os.environ["U2FKEY"]
# Force use of MCUPROXY if required
MCUPROXY=None
if "MCUPROXY" in os.environ and len(os.environ["MCUPROXY"]) != 0:
	MCUPROXY=os.environ["MCUPROXY"]
# Force use of TCP PROXY if required
TCP_PROXY=None
if "LEDGER_PROXY_ADDRESS" in os.environ and len(os.environ["LEDGER_PROXY_ADDRESS"]) != 0 and \
   "LEDGER_PROXY_PORT" in os.environ and len(os.environ["LEDGER_PROXY_PORT"]) != 0:
	TCP_PROXY=(os.environ["LEDGER_PROXY_ADDRESS"], int(os.environ["LEDGER_PROXY_PORT"]))
NFC_PROXY=None
if "LEDGER_NFC_PROXY" in os.environ:
	NFC_PROXY=True

BLE_PROXY=None
if "LEDGER_BLE_PROXY" in os.environ:
	BLE_PROXY=True

# Force use of MCUPROXY if required
PCSC=None
if "PCSC" in os.environ and len(os.environ["PCSC"]) != 0:
	PCSC=os.environ["PCSC"]
if PCSC:
	try:
		from smartcard.Exceptions import NoCardException
		from smartcard.System import readers
		from smartcard.util import toHexString, toBytes
	except ImportError:
		PCSC = False

class HIDDongleHIDAPI(Dongle, DongleWait):

	def __init__(self, device, ledger=False, debug=False):
		self.device = device
		self.ledger = ledger
		self.debug = debug
		self.waitImpl = self
		self.opened = True

	def exchange(self, apdu, timeout=TIMEOUT):
		if APDUGEN:
			print(apdu.hex())
			return b""

		if self.debug:
			print("HID => %s" % apdu.hex())
		if self.ledger:
			apdu = wrapCommandAPDU(0x0101, apdu, 64)
		padSize = len(apdu) % 64
		tmp = apdu
		if padSize != 0:
			tmp.extend([0] * (64 - padSize))
		offset = 0
		while offset != len(tmp):
			data = tmp[offset:offset + 64]
			data = bytearray([0]) + data
			if self.device.write(data) < 0:
				raise BaseException("Error while writing")
			offset += 64
		dataLength = 0
		dataStart = 2
		result = self.waitImpl.waitFirstResponse(timeout)
		if not self.ledger:
			if result[0] == 0x61: # 61xx : data available
				self.device.set_nonblocking(False)
				dataLength = result[1]
				dataLength += 2
				if dataLength > 62:
					remaining = dataLength - 62
					while remaining != 0:
						if remaining > 64:
							blockLength = 64
						else:
							blockLength = remaining
						result.extend(bytearray(self.device.read(65))[0:blockLength])
						remaining -= blockLength
				swOffset = dataLength
				dataLength -= 2
				self.device.set_nonblocking(True)
			else:
				swOffset = 0
		else:
			self.device.set_nonblocking(False)
			while True:
				response = unwrapResponseAPDU(0x0101, result, 64)
				if response is not None:
					result = response
					dataStart = 0
					swOffset = len(response) - 2
					dataLength = len(response) - 2
					self.device.set_nonblocking(True)
					break
				result.extend(bytearray(self.device.read(65)))
		sw = (result[swOffset] << 8) + result[swOffset + 1]
		response = result[dataStart : dataLength + dataStart]
		if self.debug:
			print("HID <= %s%.2x" % (response.hex(), sw))
		if sw != 0x9000 and (sw & 0xFF00) != 0x6100 and (sw & 0xFF00) != 0x6C00:
			possibleCause = "Unknown reason"
			if sw == 0x6982:
				possibleCause = "Have you uninstalled the existing CA with resetCustomCA first?"
			if sw == 0x6985:
				possibleCause = "Condition of use not satisfied (denied by the user?)"
			if sw == 0x6a84 or sw == 0x6a85:
				possibleCause = "Not enough space?"
			if sw == 0x6a83:
				possibleCause = "Maybe this app requires a library to be installed first?"
			if sw == 0x6484:
				possibleCause = "Are you using the correct targetId?"
			if sw == 0x6d00:
				possibleCause = "Unexpected state of device: verify that the right application is opened?"
			if sw == 0x6e00:
				possibleCause = "Unexpected state of device: verify that the right application is opened?"
			raise CommException("Invalid status %04x (%s)" % (sw, possibleCause), sw, response)
		return response

	def waitFirstResponse(self, timeout):
		start = time.time()
		data = ""
		while len(data) == 0:
			data = self.device.read(65)
			if not len(data):
				if time.time() - start > timeout:
					raise CommException("Timeout")
				time.sleep(0.0001)
		return bytearray(data)

	def apduMaxDataSize(self):
		return 255

	def close(self):
		if self.opened:
			try:
				self.device.close()
			except:
				pass
		self.opened = False

from nfc.tag.tt4 import Type4TagCommandError

NFC_CLA = 0x00
NFC_INS_WRITE = 0x5e
NFC_INS_READ = 0x5f
NFC_P1 = 0x00
NFC_P2 = 0x00

DEBUG_NFC_APDU = False

class DongleNFC(Dongle, DongleWait):
	def __init__(self, debug = False):
		self.waitImpl = self
		self.opened = True
		self.debug = debug
		self.clf = nfc.ContactlessFrontend('usb')
		self.tag = self.clf.connect(rdwr={'on-connect': lambda tag: False})
		print(self.tag)
		if self.tag.ndef is not None:
			for record in self.tag.ndef.records:
				print(record)

	def _exchange_write(self, apdu, timeout=TIMEOUT):
		success = False
		nb_ex = 0
		while success is False:
			try:
				if DEBUG_NFC_APDU:
					debug = bytearray([NFC_CLA, NFC_INS_WRITE, NFC_P1, NFC_P2, len(apdu)]) + apdu
					print(debug.hex())
				response = self.tag.send_apdu(NFC_CLA, NFC_INS_WRITE, NFC_P1, NFC_P2, apdu, check_status=False)
				if DEBUG_NFC_APDU:
					print(response.hex())
				sw = (response[-2] << 8) + response[-1]
				if (sw&0xF000) != 0x9000 and (sw&0xFF00) != 0x6100 and (sw&0xFF00) != 0x6C00:
					raise BaseException("Invalid status word received: " + hex(sw))
			except Type4TagCommandError as ex:
				if (nb_ex > 2):
					raise ex
				time.sleep(0.1)
				nb_ex = nb_ex+1
				continue
			success = True
		return response

	def _exchange_read(self, timeout=TIMEOUT):
		sw = 0x6100
		nb_ex = 0
		while sw == 0x6100:
			try:
				if DEBUG_NFC_APDU:
					debug = bytearray([NFC_CLA, NFC_INS_READ, NFC_P1, NFC_P2])
					print(debug.hex())
				response = self.tag.send_apdu(NFC_CLA, NFC_INS_READ, NFC_P1, NFC_P2, None, check_status=False)
				if DEBUG_NFC_APDU:
					print(response.hex())
				sw = (response[-2] << 8) + response[-1]
				if (sw&0xF000) != 0x9000 and (sw&0xFF00) != 0x6100 and (sw&0xFF00) != 0x6C00:
					raise BaseException("Invalid status word received: " + hex(sw))
			except Type4TagCommandError as ex:
				if (nb_ex > 2):
					raise ex
				time.sleep(0.1)
				nb_ex = nb_ex+1
			time.sleep(0.001)
		return response

	def exchange(self, apdu, timeout=TIMEOUT):
		if self.debug:
			print(f"[NFC] => {apdu.hex()}")
		response = self._exchange_write(apdu, timeout)
		sw = (response[-2] << 8) + response[-1]
		if response != 0x9000:
			response = self._exchange_read(timeout)
		if self.debug:
			print(f"[NFC] <= {response.hex()}")
		return response

	def apduMaxDataSize(self):
		return 255

	def close(self):
		pass

class DongleBLE(Dongle, DongleWait):
	def __init__(self, debug = False):
		self.waitImpl = self
		self.debug = debug
		try:
			self.device = BleDevice(os.environ['LEDGER_BLE_MAC'])
			self.device.open()
		except KeyError as ex:
			sys.exit(f"Key Error\nPlease run 'python -m ledgerblue.BleComm' to select wich device to connect to")
		self.opened = self.device.opened

	def exchange(self, apdu, timeout=TIMEOUT):
		if self.debug:
			print(f"[BLE] => {apdu.hex()}")
		response = self.device.exchange(apdu, timeout)
		sw = (response[-2] << 8) + response[-1]
		response = response[0:-2]
		if self.debug:
			print("[BLE] <= %s%.2x" % (response.hex(), sw))
		if sw != 0x9000 and (sw & 0xFF00) != 0x6100 and (sw & 0xFF00) != 0x6C00:
			possibleCause = "Unknown reason"
			if sw == 0x6982:
				possibleCause = "Have you uninstalled the existing CA with resetCustomCA first?"
			if sw == 0x6985:
				possibleCause = "Condition of use not satisfied (denied by the user?)"
			if sw == 0x6a84 or sw == 0x6a85:
				possibleCause = "Not enough space?"
			if sw == 0x6a83:
				possibleCause = "Maybe this app requires a library to be installed first?"
			if sw == 0x6484:
				possibleCause = "Are you using the correct targetId?"
			if sw == 0x6d00:
				possibleCause = "Unexpected state of device: verify that the right application is opened?"
			if sw == 0x6e00:
				possibleCause = "Unexpected state of device: verify that the right application is opened?"
			self.close()
			raise CommException("Invalid status %04x (%s)" % (sw, possibleCause), sw, response)
		return response

	def apduMaxDataSize(self):
		return 0x99

	def close(self):
		self.device.close()

class DongleSmartcard(Dongle):

	def __init__(self, device, debug=False):
		self.device = device
		self.debug = debug
		self.waitImpl = self
		self.opened = True

	def exchange(self, apdu, timeout=TIMEOUT):
		if self.debug:
			print("SC => %s" % apdu.hex())
		response, sw1, sw2 = self.device.transmit(toBytes(hexlify(apdu)))
		sw = (sw1 << 8) | sw2
		if self.debug:
			print("SC <= %s%.2x" % (response.hex(), sw))
		if sw != 0x9000 and (sw & 0xFF00) != 0x6100 and (sw & 0xFF00) != 0x6C00:
			raise CommException("Invalid status %04x" % sw, sw, bytearray(response))
		return bytearray(response)

	def close(self):
		if self.opened:
			try:
				self.device.disconnect()
			except:
				pass
		self.opened = False

def getDongle(debug=False, selectCommand=None):
	if APDUGEN:
		return HIDDongleHIDAPI(None, True, debug)

	if not U2FKEY is None:
		return getDongleU2F(scrambleKey=U2FKEY, debug=debug)
	elif MCUPROXY is not None:
		return getDongleHTTP(remote_host=MCUPROXY, debug=debug)
	elif TCP_PROXY is not None:
		return getDongleTCP(server=TCP_PROXY[0], port=TCP_PROXY[1], debug=debug)
	elif NFC_PROXY:
		return DongleNFC(debug)
	elif BLE_PROXY:
		return DongleBLE(debug)
	dev = None
	hidDevicePath = None
	ledger = True
	for hidDevice in hid.enumerate(0, 0):
		if hidDevice['vendor_id'] == 0x2c97:
			if ('interface_number' in hidDevice and hidDevice['interface_number'] == 0) or ('usage_page' in hidDevice and hidDevice['usage_page'] == 0xffa0):
				hidDevicePath = hidDevice['path']
	if hidDevicePath is not None:
		dev = hid.device()
		dev.open_path(hidDevicePath)
		dev.set_nonblocking(True)
		return HIDDongleHIDAPI(dev, ledger, debug)
	if PCSC:
		connection = None
		for reader in readers():
			try:
				connection = reader.createConnection()
				connection.connect()
				if selectCommand != None:
					response, sw1, sw2 = connection.transmit(toBytes("00A4040010FF4C4547522E57414C5430312E493031"))
					sw = (sw1 << 8) | sw2
					if sw == 0x9000:
						break
					else:
						connection.disconnect()
						connection = None
				else:
					break
			except:
				connection = None
				pass
		if connection is not None:
			return DongleSmartcard(connection, debug)
	raise CommException("No dongle found")
