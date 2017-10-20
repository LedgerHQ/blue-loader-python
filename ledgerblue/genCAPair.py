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
	parser = argparse.ArgumentParser(description="Generate a Custom CA public-private keypair and print it to console.")
	return parser

def hexstr(bstr):
	if (sys.version_info.major == 3):
		return binascii.hexlify(bstr).decode()
	if (sys.version_info.major == 2):
		return binascii.hexlify(bstr)
	return ""

if __name__ == '__main__':
	from .ecWrapper import PrivateKey
	from .comm import getDongle
	from .hexParser import IntelHexParser, IntelHexPrinter
	from .hexLoader import HexLoader
	from .deployed import getDeployedSecretV1, getDeployedSecretV2
	import struct
	import binascii
	import sys

	get_argparser().parse_args()
	privateKey = PrivateKey()
	publicKey = hexstr(privateKey.pubkey.serialize(compressed=False))
	print("Public key : %s" % publicKey)
	print("Private key: %s" % privateKey.serialize())
