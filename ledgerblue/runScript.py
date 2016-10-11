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

from .comm import getDongle
from .deployed import getDeployedSecretV2
from .ecWrapper import PrivateKey
from Crypto.Cipher import AES
import argparse
import sys
import fileinput

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--fileName", help="Set the file name to load")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--scp", help="open secure channel to exchange apdu", action='store_true')
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--rootPrivateKey", help="Set the root private key")

args = parser.parse_args()

if args.targetId == None:
	args.targetId = 0x31100002
if not args.fileName:
	#raise Exception("Missing fileName")
	file = sys.stdin
else:
	file = open(args.fileName, "r")

class SCP:
	def __init__(self, dongle, targetId, rootPrivateKey):
		self.key = getDeployedSecretV2(dongle, rootPrivateKey, targetId)
		self.iv = b'\x00' * 16;
		
	def encryptAES(self, data):
		paddedData = data + b'\x80'
		while (len(paddedData) % 16) != 0:
			paddedData += b'\x00'
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		encryptedData = cipher.encrypt(paddedData)
		self.iv = encryptedData[len(encryptedData) - 16:]
		return encryptedData

        def decryptAES(self, data):
                if len(data) == 0:
                        return data
                cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
                decryptedData = cipher.decrypt(data)
                l = len(decryptedData) - 1
                while (decryptedData[l] != chr(0x80)):
                        l-=1
                decryptedData = decryptedData[0:l]
                self.iv = data[len(data) - 16:]
                return decryptedData

dongle = getDongle(args.apdu)
if args.scp:
	if args.rootPrivateKey == None:
		privateKey = PrivateKey()
		publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
		print("Generated random root public key : %s" % publicKey)
		args.rootPrivateKey = privateKey.serialize()
	scp = SCP(dongle, args.targetId, bytearray.fromhex(args.rootPrivateKey))

for data in file:
	data = data.rstrip('\r\n').decode('hex')
	if len(data) < 5:
		continue
	if args.scp:
		data = bytearray(data)
		if data[4] > 0 and len(data)>5:
			apduData = data[5 : 5 + data[4]]
			apduData = scp.encryptAES(str(apduData))
			result = dongle.exchange(data[0:4] + bytearray([len(apduData)]) + bytearray(apduData))
		else:
			result = dongle.exchange(data[0:5])
		result = scp.decryptAES(str(result))
		if args.apdu:
			print "<= Clear " + result.encode('hex')	
	else:
		dongle.exchange(bytearray(data))	

