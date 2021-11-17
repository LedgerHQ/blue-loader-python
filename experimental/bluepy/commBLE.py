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

from ledgerblue.comm import Dongle
from ledgerblue.commException import CommException
from ledgerblue.ledgerWrapper import wrapCommandAPDU, unwrapResponseAPDU
from binascii import hexlify
from bluepy import btle

SERVICE_UUID = "D973F2E0-B19E-11E2-9E96-0800200C9A66"
WRITE_CHARACTERISTICS_UUID = "D973F2E2-B19E-11E2-9E96-0800200C9A66"
NOTIFY_CHARACTERISTICS_UUID = "D973F2E1-B19E-11E2-9E96-0800200C9A66"
CLIENT_CHARACTERISTICS_CONFIG_DESCRIPTOR_UUID = "00002902-0000-1000-8000-00805f9b34fb"
ENABLE_NOTIFICATION = "0100".decode('hex')
DEFAULT_BLE_CHUNK = 20
BLE_NOTIFICATION_TIMEOUT = 5.0

class BLEDongleDelegate(btle.DefaultDelegate):
	def __init__(self, dongle):
		btle.DefaultDelegate.__init__(self)
		self.dongle = dongle

	def handleNotification(self, cHandle, data):		
		self.dongle.result += bytearray(data)

class BLEDongle(Dongle):

	# Must be called with the Client Characteristics Configuration descriptor handle as bluepy fails to retrieve it
	# From gatttools
	# [device mac][LE]> char-desc
  # handle: 0x000f, uuid: 00002902-0000-1000-8000-00805f9b34fb
	def __init__(self, bleAddress, configDescriptor, debug=False):
		self.device = btle.Peripheral(bleAddress)		
		self.device.setDelegate(BLEDongleDelegate(self))
		self.service = self.device.getServiceByUUID(SERVICE_UUID)
		self.writeCharacteristic = self.service.getCharacteristics(forUUID=WRITE_CHARACTERISTICS_UUID)[0]
		self.device.writeCharacteristic(configDescriptor, ENABLE_NOTIFICATION, withResponse=True)
		self.debug = debug
		self.opened = True

	def exchange(self, apdu, timeout=20000):
		if self.debug:
			print("=> %s" % hexlify(apdu))
		apdu = wrapCommandAPDU(0, apdu, DEFAULT_BLE_CHUNK, True)		
		offset = 0
		while offset < len(apdu):
			data = apdu[offset:offset + DEFAULT_BLE_CHUNK]
			self.writeCharacteristic.write(data, withResponse=True)
			offset += DEFAULT_BLE_CHUNK
			self.result = ""
		while True:
			if not self.device.waitForNotifications(BLE_NOTIFICATION_TIMEOUT):
				raise CommException("Timeout")
			response = unwrapResponseAPDU(0, self.result, DEFAULT_BLE_CHUNK, True)
			if response is not None:
				result = response
				dataStart = 0
				swOffset = len(response) - 2
				dataLength = len(response) - 2
				break
		sw = (result[swOffset] << 8) + result[swOffset + 1]
		response = result[dataStart : dataLength + dataStart]
		if self.debug:
			print("<= %s%.2x" % (hexlify(response), sw))
		if sw != 0x9000:
			raise CommException("Invalid status %04x" % sw, sw)
		return response

	def close(self):
		if self.opened:
			try:
				self.device.disconnect()
			except:
				pass
		self.opened = False
