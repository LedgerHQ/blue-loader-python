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

import argparse

def get_argparser():
	parser = argparse.ArgumentParser(description="Delete the app with the specified name.")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--appName", help="The name of the application to delete", action='append')
	parser.add_argument("--appHash", help="Set the application hash")
	parser.add_argument("--rootPrivateKey", help="A private key used to establish a Secure Channel (hex encoded)")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')
	parser.add_argument("--offline", help="Request to only output application load APDUs into given filename")
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	from .ecWrapper import PrivateKey
	from .comm import getDongle
	from .deployed import getDeployedSecretV1, getDeployedSecretV2
	from .hexLoader import HexLoader
	import binascii
	import sys

	args = get_argparser().parse_args()

	if (args.appName == None or len(args.appName) == 0) and args.appHash == None:
		raise Exception("Missing appName or appHash")

	if args.appName != None and len(args.appName) > 0:
		for i in range(0, len(args.appName)):
			if (sys.version_info.major == 3):
				args.appName[i] = bytes(args.appName[i],'ascii')
			if (sys.version_info.major == 2):
				args.appName[i] = bytes(args.appName[i])

	if args.appHash != None:
		if (sys.version_info.major == 3):
			args.appHash = bytes(args.appHash,'ascii')
		if (sys.version_info.major == 2):
			args.appHash = bytes(args.appHash)
		args.appHash = bytearray.fromhex(args.appHash)


	if args.targetId == None:
		args.targetId = 0x31000002
	if args.rootPrivateKey == None:
		privateKey = PrivateKey()
		publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
		print("Generated random root public key : %s" % publicKey)
		args.rootPrivateKey = privateKey.serialize()

	dongle = None
	secret = None
	if not args.offline:
		dongle = getDongle(args.apdu)

		if args.deployLegacy:
			secret = getDeployedSecretV1(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
		else:
			secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
	else:
		fileTarget = open(args.offline, "wb")
		class FileCard():
			def __init__(self, target):
				self.target = target
			def exchange(self, apdu):
				if (args.apdu):
					print(binascii.hexlify(apdu))
				apdu = binascii.hexlify(apdu)
				if sys.version_info.major == 2:
					self.target.write(str(apdu) + '\n')
				else:
					self.target.write(apdu + '\n'.encode())
				return bytearray([])
			def apduMaxDataSize(self):
				# ensure to allow for encryption of those apdu afterward
				return 240
		dongle = FileCard(fileTarget)

	loader = HexLoader(dongle, 0xe0, not(args.offline), secret)

	if args.appName != None and len(args.appName) > 0:
		for name in args.appName:
			loader.deleteApp(name)
	if args.appHash != None:
		loader.deleteAppByHash(args.appHash)