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
	parser = argparse.ArgumentParser(description="Request the MCU to execute its bootloader.")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int, default=0x31000002)
	parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	import binascii

	from .comm import getDongle
	from .deployed import getDeployedSecretV2
	from .ecWrapper import PrivateKey
	from .hexLoader import HexLoader

	args = get_argparser().parse_args()

	if args.rootPrivateKey is None:
		privateKey = PrivateKey()
		publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
		print("Generated random root public key : %s" % publicKey)
		args.rootPrivateKey = privateKey.serialize()

	dongle = getDongle(args.apdu)

	secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
	loader = HexLoader(dongle, 0xe0, True, secret)
	loader.exchange(0xE0, 0, 0, 0, loader.encryptAES(b'\xB0'))

	dongle.close()
