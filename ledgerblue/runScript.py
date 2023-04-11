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
	parser = argparse.ArgumentParser(description="""Read a sequence of command APDUs from a file and send them to the
device. The file must be formatted as hex, with one CAPDU per line.""")
	parser.add_argument("--fileName", help="The name of the APDU script to load")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--scp", help="Open a Secure Channel to exchange APDU", action='store_true')
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Nano S). If --elfFile is used, the targetId from the ELF file will be used instead.", type=auto_int, default=0x31100002)
	parser.add_argument("--elfFile", help="ELF file from which the target ID is fetched. Overrides '--targetId'")
	parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	import binascii
	import sys

	from .comm import getDongle
	from .deployed import getDeployedSecretV2
	from .ecWrapper import PrivateKey
	from .hexLoader import HexLoader
	from .readElfMetadata import get_target_id_from_elf

	args = get_argparser().parse_args()

	if not args.fileName:
		#raise Exception("Missing fileName")
		file = sys.stdin
	else:
		file = open(args.fileName, "r")


	class SCP:

		def __init__(self, dongle, targetId, rootPrivateKey):
			secret = getDeployedSecretV2(dongle, rootPrivateKey, targetId)
			self.loader = HexLoader(dongle, 0xe0, True, secret)

		def encryptAES(self, data):
			return self.loader.scpWrap(data)

		def decryptAES(self, data):
			return self.loader.scpUnwrap(data)

	dongle = getDongle(args.apdu)

	targetId = args.targetId

	if args.elfFile:
		targetId = auto_int(get_target_id_from_elf(args.elfFile))
  
	if args.scp:
		if args.rootPrivateKey is None:
			privateKey = PrivateKey()
			publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
			print("Generated random root public key : %s" % publicKey)
			args.rootPrivateKey = privateKey.serialize()
		scp = SCP(dongle, targetId, bytearray.fromhex(args.rootPrivateKey))

	for data in file:
		data = binascii.unhexlify(data.replace("\n", ""))
		if len(data) < 5:
			continue
		if args.scp:
			apduData = data[5:]
			apduData = scp.encryptAES(bytes(apduData))
			apdu = bytearray([data[0], data[1], data[2], data[3], len(apduData)]) + bytearray(apduData)
			result = dongle.exchange(apdu)
			result = scp.decryptAES(result)
		else:
			result = dongle.exchange(bytearray(data))
		if args.apdu:
			print("<= Clear " + str(result))

	dongle.close()
