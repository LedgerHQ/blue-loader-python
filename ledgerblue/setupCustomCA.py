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
	parser = argparse.ArgumentParser(description="Enroll a Custom CA public key onto the device.")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
	parser.add_argument("--public", help="The Custom CA public key to be enrolled (hex encoded)")
	parser.add_argument("--name", help="""The name to assign to the Custom CA (this will be displayed on screen upon
auth requests)""")
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	from .ecWrapper import PrivateKey
	from .comm import getDongle
	from .hexParser import IntelHexParser, IntelHexPrinter
	from .hexLoader import HexLoader
	from .deployed import getDeployedSecretV1, getDeployedSecretV2
	import struct
	import binascii
	import sys

	args = get_argparser().parse_args()

	if args.targetId is None:
		args.targetId = 0x31000002
	if args.rootPrivateKey is None:
		privateKey = PrivateKey()
		publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
		print("Generated random root public key : %s" % publicKey)
		args.rootPrivateKey = privateKey.serialize()
	if args.public is None:
		raise Exception("Missing public key")
	if args.name is None:
		raise Exception("Missing certificate name")

	public = bytearray.fromhex(args.public)


	dongle = getDongle(args.apdu)

	secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
	loader = HexLoader(dongle, 0xe0, True, secret)

	loader.setupCustomCA(args.name, public)
