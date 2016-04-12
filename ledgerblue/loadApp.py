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

from secp256k1 import PrivateKey
from ledgerblue.comm import getDongle
from ledgerblue.hexParser import IntelHexParser
from ledgerblue.hexLoader import HexLoader
from ledgerblue.deployed import getDeployedSecret
import argparse

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--fileName", help="Set the file name to load")
parser.add_argument("--appName", help="Set the application name")
parser.add_argument("--appFlags", help="Set the application flags", type=auto_int)
parser.add_argument("--bootAddr", help="Set the boot address", type=auto_int)
parser.add_argument("--rootPrivateKey", help="Set the root private key")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')

args = parser.parse_args()

if args.targetId == None:
	args.targetId = 0x31000001
if args.fileName == None:
	raise Exception("Missing fileName")
if args.appName == None:
	raise Exception("Missing appName")
if args.appFlags == None:
	args.appFlags = 0
if args.bootAddr == None:
	args.bootAddr = 0xC0D00000
if args.rootPrivateKey == None:
	privateKey = PrivateKey()
	publicKey = str(privateKey.pubkey.serialize(compressed=False)).encode('hex')
	print "Generated random root public key : " + publicKey
	args.rootPrivateKey = privateKey.serialize().encode('ascii')

parser = IntelHexParser(args.fileName)
dongle = getDongle(args.apdu)

secret = getDeployedSecret(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
loader = HexLoader(dongle, 0xe0, True, secret)

if (not (args.appFlags & 2)):
	loader.deleteApp(args.appName)

appLength = 0
for area in parser.getAreas():
	appLength += len(area.getData())	

loader.createApp(args.appFlags, appLength, args.appName)
hash = loader.load(0x0, 0xE0, parser.getAreas(), args.bootAddr)
print "Application hash : " + hash
loader.run(parser.getAreas(), args.bootAddr)
