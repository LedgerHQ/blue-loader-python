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
	parser = argparse.ArgumentParser("Run an application on the device.")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
	parser.add_argument("--appName", help="The name of the application to run")
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
	if args.appName is None:
		raise Exception("Missing appname to run")

	dongle = getDongle(args.apdu)

	loader = HexLoader(dongle, 0xe0)

	loader.runApp(args.appName)
