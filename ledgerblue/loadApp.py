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
from .comm import getDongle
from .hexParser import IntelHexParser
from .hexLoader import HexLoader
from .deployed import getDeployedSecretV1, getDeployedSecretV2
import argparse
import struct

def auto_int(x):
    return int(x, 0)

def parse_bip32_path(path):
        if len(path) == 0:
                return ""
        result = ""
        elements = path.split('/')
        for pathElement in elements:
                element = pathElement.split('\'')
                if len(element) == 1:
                        result = result + struct.pack(">I", int(element[0]))             
                else:
                        result = result + struct.pack(">I", 0x80000000 | int(element[0]))
        return result

parser = argparse.ArgumentParser()
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--fileName", help="Set the file name to load")
parser.add_argument("--icon", help="Set the icon content to use (hex encoded)")
parser.add_argument("--path", help="BIP 32 path to which the derivation is locked (format decimal a'/b'/c)")
parser.add_argument("--appName", help="Set the application name")
parser.add_argument("--signature", help="Optional application's signature (hex encoded)")
parser.add_argument("--appFlags", help="Set the application flags", type=auto_int)
parser.add_argument("--bootAddr", help="Set the boot address", type=auto_int)
parser.add_argument("--rootPrivateKey", help="Set the root private key")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')

args = parser.parse_args()

if args.targetId == None:
	args.targetId = 0x31000002
if args.fileName == None:
	raise Exception("Missing fileName")
if args.appName == None:
	raise Exception("Missing appName")
if args.appFlags == None:
	args.appFlags = 0
if args.rootPrivateKey == None:
	privateKey = PrivateKey()
	publicKey = str(privateKey.pubkey.serialize(compressed=False)).encode('hex')
	print "Generated random root public key : " + publicKey
	args.rootPrivateKey = privateKey.serialize().encode('ascii')

parser = IntelHexParser(args.fileName)
if args.bootAddr == None:
    args.bootAddr = parser.getBootAddr()

dongle = getDongle(args.apdu)

if args.deployLegacy:
	secret = getDeployedSecretV1(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
else:
	secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
loader = HexLoader(dongle, 0xe0, True, secret)

if (not (args.appFlags & 2)):
	loader.deleteApp(args.appName)

appLength = 0
for area in parser.getAreas():
	appLength += len(area.getData())	

icon = None
if args.icon != None:
	icon = bytearray.fromhex(args.icon)

signature = None
if args.signature != None:
	signature = bytearray.fromhex(args.signature)	

path = None
if args.path != None:
	path = parse_bip32_path(args.path)

loader.createApp(args.appFlags, appLength, args.appName, icon, path)
hash = loader.load(0x0, 0xE0, parser.getAreas(), args.bootAddr)
print "Application hash : " + hash
loader.run(parser.getAreas(), args.bootAddr, signature)
