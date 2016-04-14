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
		zoneData = ""
		file = open(fileName, "r")
		for data in file:
			lineNumber += 1
			data = data.rstrip('\r\n')
			if len(data) == 0:
				continue
			if data[0] <> ':':
				raise Exception("Invalid data at line " + str(lineNumber))
			data = bytearray(data[1:].decode('hex'))		
			count = data[0]
			address = (data[1] << 8) + data[2]
			recordType = data[3]
			if recordType == 0x00:
				if startZone == None:
					raise Exception("Data record but no zone defined at line " + lineNumber) 
				if startFirst == None:
					startFirst = address
					current = startFirst
				if address <> current:
					self.areas.append(IntelHexArea((startZone << 16) + startFirst, zoneData))
					zoneData = ""
					startFirst = address
					current = address
				zoneData += data[4:4 + count]
				current += count
			if recordType == 0x01:
				if len(zoneData) <> 0:
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
					if len(zoneData) <> 0:
						self.areas.append(IntelHexArea((startZone << 16) + startFirst, zoneData))
						zoneData = ""
						startZone = None
						startFirst = None
						current = None						
					startZone = (data[4] << 8) + data[5]
		file.close()

	def getAreas(self):
		return self.areas
