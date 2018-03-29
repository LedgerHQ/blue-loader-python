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

from Crypto.Cipher import AES
import sys
import struct
import hashlib
import binascii
from .ecWrapper import PrivateKey, PublicKey
from builtins import int
from ecpy.curves import Curve
import os
#from builtins import str

LOAD_SEGMENT_CHUNK_HEADER_LENGTH = 3
MIN_PADDING_LENGTH = 1
SCP_MAC_LENGTH = 0xE

BOLOS_TAG_APPNAME = 0x01
BOLOS_TAG_APPVERSION = 0x02
BOLOS_TAG_ICON = 0x03
BOLOS_TAG_DERIVEPATH = 0x04
BOLOS_TAG_DATASIZE = 0x05
BOLOS_TAG_DEPENDENCY = 0x06

def encodelv(v):
	l = len(v)
	s = b""
	if l < 128:
		s += struct.pack(">B", l)
	elif l < 256:
		s += struct.pack(">B", 0x81)
		s += struct.pack(">B", l)
	elif l < 65536:
		s += struct.pack(">B", 0x82)
		s += struct.pack(">H", l)
	else:
		raise Exception("Unimplemented LV encoding")
	s += v
	return s

def encodetlv(t, v):
	l = len(v)
	s = struct.pack(">B", t)
	if l < 128:
		s += struct.pack(">B", l)
	elif l < 256:
		s += struct.pack(">B", 0x81)
		s += struct.pack(">B", l)
	elif l < 65536:
		s += struct.pack(">B", 0x82)
		s += struct.pack(">H", l)
	else:
		raise Exception("Unimplemented TLV encoding")
	s += v
	return s

def str2bool(v):
	if v is not None:
		return v.lower() in ("yes", "true", "t", "1")
	return False
SCP_DEBUG = str2bool(os.getenv("SCP_DEBUG"))

class HexLoader:

	def scp_derive_key(self, ecdh_secret, keyindex):
		retry = 0
		# di = sha256(i || retrycounter || ecdh secret)
		while True:
			sha256 = hashlib.new('sha256')
			sha256.update(struct.pack(">IB", keyindex, retry))
			sha256.update(ecdh_secret)

			# compare di with order
			CURVE_SECP256K1 = Curve.get_curve('secp256k1')
			if int.from_bytes(sha256.digest(), 'big') < CURVE_SECP256K1.order:
				break
			#regenerate a new di satisfying order upper bound
			retry+=1

		# Pi = di*G
		privkey = PrivateKey(bytes(sha256.digest()))
		pubkey = bytearray(privkey.pubkey.serialize(compressed=False))
		# ki = sha256(Pi)
		sha256 = hashlib.new('sha256')
		sha256.update(pubkey)
		#print ("Key " + str (keyindex) + ": " + sha256.hexdigest())
		return sha256.digest()

	def __init__(self, card, cla=0xF0, secure=False, mutauth_result=None, relative=True, cleardata_block_len=None):
		self.card = card
		self.cla = cla
		self.secure = secure
		self.createappParams = None

		#legacy unsecure SCP (pre nanos-1.4, pre blue-2.1)
		self.max_mtu = 0xFE
		if not self.card is None:
			self.max_mtu = min(self.max_mtu, self.card.apduMaxDataSize())
		self.scpVersion = 2
		self.key = mutauth_result
		self.iv = b'\x00' * 16
		self.relative = relative

		#store the aligned block len to be transported if requested
		self.cleardata_block_len=cleardata_block_len
		if not (self.cleardata_block_len is None):
			if not self.card is None:
				self.cleardata_block_len = min(self.cleardata_block_len, self.card.apduMaxDataSize())

		# try:
		if type(mutauth_result) is dict and 'ecdh_secret' in mutauth_result:
			self.scp_enc_key = self.scp_derive_key(mutauth_result['ecdh_secret'], 0)[0:16]
			self.scp_enc_iv = b"\x00" * 16
			self.scp_mac_key = self.scp_derive_key(mutauth_result['ecdh_secret'], 1)[0:16]
			self.scp_mac_iv = b"\x00" * 16
			self.scpVersion = 3
			self.max_mtu = 0xFE
			if not self.card is None:
				self.max_mtu = min(self.max_mtu, self.card.apduMaxDataSize()&0xF0)

		# except:
		# 	pass


	
		
	def crc16(self, data):
		TABLE_CRC16_CCITT = [
			0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
			0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
			0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
			0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
			0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
			0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
			0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
			0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
			0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
			0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
			0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
			0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
			0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
			0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
			0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
			0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
			0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
			0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
			0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
			0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
			0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
			0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
			0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
			0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
			0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
			0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
			0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
			0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
			0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
			0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
			0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
			0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
		]
		crc =  0xFFFF
		for i in range(0, len(data)):
			b = data[i] & 0xff
			b = (b ^ ((crc >> 8) & 0xff)) & 0xff
			crc = (TABLE_CRC16_CCITT[b] ^ (crc << 8)) & 0xffff
		return crc

	def exchange(self, cla, ins, p1, p2, data):
		#wrap
		data = self.scpWrap(data)
		apdu = bytearray([cla, ins, p1, p2, len(data)]) + bytearray(data)
		if self.card == None:
			print("%s" % binascii.hexlify(apdu))
		else:
			# unwrap after exchanged
			return self.scpUnwrap(bytes(self.card.exchange(apdu)))

	def scpWrap(self, data):
		if not self.secure or data is None or len(data) == 0:
			return data

		if self.scpVersion == 3:
			if SCP_DEBUG:
				print(binascii.hexlify(data))
			# ENC
			paddedData = data + b'\x80'
			while (len(paddedData) % 16) != 0:
				paddedData += b'\x00'
			if SCP_DEBUG:
				print(binascii.hexlify(paddedData))
			cipher = AES.new(self.scp_enc_key, AES.MODE_CBC, self.scp_enc_iv)
			if sys.version_info.major == 2:
				paddedData = bytes(paddedData)
			encryptedData = cipher.encrypt(paddedData)
			self.scp_enc_iv = encryptedData[-16:]
			if SCP_DEBUG:
				print(binascii.hexlify(encryptedData))
			# MAC
			cipher = AES.new(self.scp_mac_key, AES.MODE_CBC, self.scp_mac_iv)
			macData = cipher.encrypt(encryptedData)
			self.scp_mac_iv = macData[-16:]

			# only append part of the mac
			encryptedData += self.scp_mac_iv[-SCP_MAC_LENGTH:]
			if SCP_DEBUG:
				print(binascii.hexlify(encryptedData))
		else:
			paddedData = data + b'\x80'
			while (len(paddedData) % 16) != 0:
				paddedData += b'\x00'
			cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
			if SCP_DEBUG:
				print("wrap_old: "+binascii.hexlify(paddedData))
			encryptedData = cipher.encrypt(paddedData)
			self.iv = encryptedData[-16:]

		#print (">>")
		return encryptedData

	def scpUnwrap(self, data):
		if not self.secure or data is None or len(data) == 0 or len(data) == 2:
			return data

		if sys.version_info.major == 3:
			padding_char = 0x80
		else:
			padding_char = chr(0x80)

		if self.scpVersion == 3:
			if SCP_DEBUG:
				print(binascii.hexlify(data))
			# MAC
			cipher = AES.new(self.scp_mac_key, AES.MODE_CBC, self.scp_mac_iv)
			macData = cipher.encrypt(bytes(data[0:-SCP_MAC_LENGTH]))
			self.scp_mac_iv = macData[-16:]
			if self.scp_mac_iv[-SCP_MAC_LENGTH:] != data[-SCP_MAC_LENGTH:] :
				raise BaseException("Invalid SCP MAC")
			# consume mac
			data = data[0:-SCP_MAC_LENGTH]

			if SCP_DEBUG:
				print(binascii.hexlify(data))
			# ENC
			cipher = AES.new(self.scp_enc_key, AES.MODE_CBC, self.scp_enc_iv)
			self.scp_enc_iv = bytes(data[-16:])
			data = cipher.decrypt(bytes(data))
			l = len(data) - 1
			while (data[l] != padding_char):
				l-=1
				if l == -1:
					raise BaseException("Invalid SCP ENC padding")
			data = data[0:l]
			decryptedData = data

			if SCP_DEBUG:
				print(binascii.hexlify(data))
		else:		
			cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
			decryptedData = cipher.decrypt(data)
			if SCP_DEBUG:
				print("unwrap_old: "+binascii.hexlify(decryptedData))
			l = len(decryptedData) - 1
			while (decryptedData[l] != padding_char):
				l-=1
				if l == -1:
					raise BaseException("Invalid SCP ENC padding")
			decryptedData = decryptedData[0:l]
			self.iv = data[-16:]

		#print ("<<")
		return decryptedData

	def selectSegment(self, baseAddress):
		data = b'\x05' + struct.pack('>I', baseAddress)
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def loadSegmentChunk(self, offset, chunk):
		data = b'\x06' + struct.pack('>H', offset) + chunk
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def flushSegment(self):
		data = b'\x07'
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)				

	def crcSegment(self, offsetSegment, lengthSegment, crcExpected):
		data = b'\x08' + struct.pack('>H', offsetSegment) + struct.pack('>I', lengthSegment) + struct.pack('>H', crcExpected)
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)						

	def validateTargetId(self, targetId):
		data = struct.pack('>I', targetId)
		self.exchange(self.cla, 0x04, 0x00, 0x00, data)

	def boot(self, bootadr, signature=None):
		# Force jump into Thumb mode
		bootadr |= 1
		data = b'\x09' + struct.pack('>I', bootadr)
		if (signature != None):
			data += struct.pack('>B', len(signature)) + signature
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def commit(self, signature=None):
		data = b'\x09'
		if (signature != None):
			data += struct.pack('>B', len(signature)) + signature
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def createAppNoInstallParams(self, appflags, applength, appname, icon=None, path=None, iconOffset=None, iconSize=None, appversion=None):
		data = b'\x0B' + struct.pack('>I', applength) + struct.pack('>I', appflags) + struct.pack('>B', len(appname)) + appname
		if iconOffset is None:
			if not (icon is None):
				data += struct.pack('>B', len(icon)) + icon
			else:
				data += b'\x00'

		if not (path is None):
			data += struct.pack('>B', len(path)) + path
		else:
			data += b'\x00'

		if not iconOffset is None:
			data += struct.pack('>I', iconOffset) + struct.pack('>H', iconSize)

		if not appversion is None:
			data += struct.pack('>B', len(appversion)) + appversion

		# in previous version, appparams are not part of the application hash yet
		self.createappParams = None #data[1:]
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)						

	def createApp(self, code_length, data_length=0, install_params_length=0, flags=0, bootOffset=1):
		#keep the create app parameters to be included in the load app hash
		self.createappParams = struct.pack('>IIIII', code_length, data_length, install_params_length, flags, bootOffset)
		data = b'\x0B' + self.createappParams
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def deleteApp(self, appname):
		data = b'\x0C' +  struct.pack('>B',len(appname)) +  appname
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)						

	def deleteAppByHash(self, appfullhash):
		if len(appfullhash) != 32:
			raise BaseException("Invalid hash format, sha256 expected")
		data = b'\x15' +  appfullhash
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def getVersion(self):
		data = b'\x10'
		response = self.exchange(self.cla, 0x00, 0x00, 0x00, data)
		if sys.version_info.major == 2:
			response = bytearray(response)
		result = {}
		offset = 0
		result['targetId'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		result['osVersion'] = response[offset + 1 : offset + 1 + response[offset]].decode('utf-8')
		offset += 1 + response[offset]
		offset += 1
		result['flags'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		result['mcuVersion'] = response[offset + 1 : offset + 1 + response[offset] - 1].decode('utf-8')
		offset += 1 + response[offset]
		if (offset < len(response)):
			result['mcuHash'] = response[offset : offset + 32]
		return result

	def listApp(self, restart=True):
		if restart:
			data = b'\x0E'
		else:
			data = b'\x0F'
		response = self.exchange(self.cla, 0x00, 0x00, 0x00, data)
		if sys.version_info.major == 2:
			response = bytearray(response)
		#print binascii.hexlify(response[0])
		result = []
		offset = 0
		if len(response) > 0:
			if response[0] != 0x01:
				# support old format
				while offset != len(response):
					item = {}
					offset += 1
					item['name'] = response[offset + 1 : offset + 1 + response[offset]].decode('utf-8')
					offset += 1 + response[offset]
					item['flags'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
					offset += 4
					item['hash'] = response[offset : offset + 32]
					offset += 32
					result.append(item)
			else:
				offset += 1
				while offset != len(response):
					item = {}
					#skip the current entry's size
					offset += 1
					item['flags'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
					offset += 4
					item['hash_code_data'] = response[offset : offset + 32]
					offset += 32
					item['hash'] = response[offset : offset + 32]
					offset += 32
					item['name'] = response[offset + 1 : offset + 1 + response[offset]].decode('utf-8')
					offset += 1 + response[offset]
					result.append(item)
		return result

	def getMemInfo(self):
		response = self.exchange(self.cla, 0x00, 0x00, 0x00, b'\x11')
		if sys.version_info.major == 2:
			response = bytearray(response)
		item = {}
		offset = 0
		item['systemSize'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		item['applicationsSize'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		item['freeSize'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		item['usedAppSlots'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		offset += 4
		item['totalAppSlots'] = (response[offset] << 24) | (response[offset + 1] << 16) | (response[offset + 2] << 8) | response[offset + 3]
		return item

	def load(self, erase_u8, max_length_per_apdu, hexFile, reverse=False, doCRC=True):
		if (max_length_per_apdu > self.max_mtu):
			max_length_per_apdu = self.max_mtu
		initialAddress = 0
		if self.relative:
			initialAddress = hexFile.minAddr()
		sha256 = hashlib.new('sha256')
		# stat by hashing the create app params to ensure complete app signature
		if self.createappParams:
			sha256.update(self.createappParams)
		areas = hexFile.getAreas()
		if reverse:
			areas = reversed(hexFile.getAreas())
		for area in areas:
			startAddress = area.getStart() - initialAddress
			data = area.getData()
			self.selectSegment(startAddress)
			if len(data) == 0:
				continue
			if len(data) > 0x10000:
				raise Exception("Invalid data size for loader")
			crc = self.crc16(bytearray(data))
			offset = 0
			length = len(data)
			if reverse:
				offset = length
			while (length > 0):
				if length > max_length_per_apdu - LOAD_SEGMENT_CHUNK_HEADER_LENGTH - MIN_PADDING_LENGTH - SCP_MAC_LENGTH:
					chunkLen = max_length_per_apdu - LOAD_SEGMENT_CHUNK_HEADER_LENGTH - MIN_PADDING_LENGTH - SCP_MAC_LENGTH
					if (chunkLen%16) != 0:
						chunkLen -= (chunkLen%16)
				else:
					chunkLen = length

				if self.cleardata_block_len and chunkLen%self.cleardata_block_len:
					if (chunkLen < self.cleardata_block_len):
						raise Exception("Cannot transport not block aligned data with fixed block len")
					chunkLen -= chunkLen%self.cleardata_block_len;
				# pad with 00's when not complete block and performing NENC
				if reverse:
					chunk = data[offset-chunkLen : offset]
					self.loadSegmentChunk(offset-chunkLen, bytes(chunk))
				else:
					chunk = data[offset : offset + chunkLen]
					sha256.update(chunk)
					self.loadSegmentChunk(offset, bytes(chunk))
				if reverse:
					offset -= chunkLen
				else:
					offset += chunkLen
				length -= chunkLen
			self.flushSegment()
			if doCRC:
				self.crcSegment(0, len(data), crc)
		return sha256.hexdigest()

	def run(self, bootoffset=1, signature=None):
		self.boot(bootoffset, signature)

	def resetCustomCA(self):
		data = b'\x13'
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def setupCustomCA(self, name, public):
		data = b'\x12' + struct.pack('>B', len(name)) + name.encode() + struct.pack('>B', len(public)) + public
		self.exchange(self.cla, 0x00, 0x00, 0x00, data)

	def runApp(self, name):
		data = name
		self.exchange(self.cla, 0xD8, 0x00, 0x00, data)

