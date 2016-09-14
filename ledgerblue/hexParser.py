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

class IntelHexArea:
	def __init__(self, start, data):
		self.start = start
		self.data = data
		self.bootAddr = 0

	def getStart(self):
		return self.start

	def getData(self):
		return self.data

class IntelHexParser:
	def __init__(self, fileName):
		self.areas = []
		lineNumber = 0
		startZone = None
		startFirst = None
		current = None
		zoneData = b''
		file = open(fileName, "r")
		for data in file:
			lineNumber += 1
			data = data.rstrip('\r\n')
			if len(data) == 0:
				continue
			if data[0] != ':':
				raise Exception("Invalid data at line %d" % lineNumber)
			data = bytearray.fromhex(data[1:]) #binascii.unhexlify(data[1:])		 
			count = data[0]
			address = (data[1] << 8) + data[2]
			recordType = data[3]
			if recordType == 0x00:
				if startZone == None:
					raise Exception("Data record but no zone defined at line " + lineNumber) 
				if startFirst == None:
					startFirst = address
					current = startFirst
				if address != current:
					self.areas.append(IntelHexArea((startZone << 16) + startFirst, zoneData))
					zoneData = ""
					startFirst = address
					current = address
				zoneData += data[4:4 + count]
				current += count
			if recordType == 0x01:
				if len(zoneData) != 0:
					self.areas.append(IntelHexArea((startZone << 16) + startFirst, zoneData))
					zoneData = ""
					startZone = None
					startFirst = None
					current = None					
			if recordType == 0x02:
					raise Exception("Unsupported record 02")
			if recordType == 0x03:
					raise Exception("Unsupported record 03")
			if recordType == 0x04:
					if len(zoneData) != 0:
						self.areas.append(IntelHexArea((startZone << 16) + startFirst, zoneData))
						zoneData = ""
						startZone = None
						startFirst = None
						current = None						
					startZone = (data[4] << 8) + data[5]
			if recordType == 0x05:
					self.bootAddr = ((data[4]&0xFF) << 24) + ((data[5]&0xFF) << 16) + ((data[6]&0xFF) << 8) + (data[7]&0xFF)
		file.close()

	def getAreas(self):
		return self.areas

	def getBootAddr(self):
		return self.bootAddr

	def maxAddr(self):
		addr = 0
		for a in self.areas:
			if (a.start+len(a.data) > addr):
				addr = a.start+len(a.data)
		return addr		

import binascii

class IntelHexPrinter:
	def __init__(self, parser=None, eol="\r\n"):
		self.areas = []
		self.eol = eol
		self.bootAddr = 0
		# build bound to the parser
		if (parser):
			self.areas = parser.areas
			self.bootAddr = parser.bootAddr

	def addArea(self, startaddress, data):
		self.areas.append(IntelHexArea(startaddress, data))
                
	def setBootAddr(self, bootAddr):
		self.bootAddr = int(bootAddr)

	def checksum(self, bin):
		cks = 0
		for b in bin:
			cks += b
		cks = (-cks) & 0x0FF
		return cks

	def _emit_binary(self, file, bin):
		cks = self.checksum(bin)
		file.write((":" + binascii.hexlify(bin) + hex(0x100+cks)[3:] + self.eol).upper())

	def writeTo(self, fileName, blocksize=32):
		file = open(fileName, "w")
		for area in self.areas:
			off = 0
			# force the emission of selection record at start
			oldoff = area.start + 0x10000
			while off < len(area.data):
				# emit a offset selection record
				if ((off & 0xFFFF0000) != (oldoff & 0xFFFF0000) ):
					self._emit_binary(file, bytearray(("02000004" + hex(0x10000+(area.start>>16))[3:7]).decode('hex')))

				# emit data record
				if (off+blocksize > len(area.data)):
					self._emit_binary(file, bytearray((hex(0x100+(len(area.data)-off))[3:] + hex(0x10000+off+(area.start&0xFFFF))[3:] + "00").decode('hex')) + area.data[off:len(area.data)])
				else:
					self._emit_binary(file, bytearray((hex(0x100+blocksize)[3:] + hex(0x10000+off+(area.start&0xFFFF))[3:] + "00").decode('hex')) + area.data[off:off+blocksize])

				oldoff = off;
				off += blocksize
                                
		bootAddrHex = hex(0x100000000+self.bootAddr)[3:]
		file.write(":04000005"+bootAddrHex+hex(0x100+self.checksum( bytearray(("04000005"+bootAddrHex).decode('hex'))))[3:]+self.eol)

		file.write(":00000001FF"+self.eol)

		file.close()
			
