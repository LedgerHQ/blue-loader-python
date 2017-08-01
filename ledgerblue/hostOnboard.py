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
	parser = argparse.ArgumentParser(description="""
.. warning::

   Using this script undermines the security of the device. Caveat emptor.
""")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--id", help="Identity to initialize", type=auto_int)
	parser.add_argument("--pin", help="Set a PINs to backup the seed for future use")
	parser.add_argument("--prefix", help="Derivation prefix")
	parser.add_argument("--passphrase", help="Derivation passphrase")
	parser.add_argument("--words", help="Derivation phrase")
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	from .ecWrapper import PrivateKey
	from .comm import getDongle
	from .hexParser import IntelHexParser, IntelHexPrinter
	from .hexLoader import HexLoader
	import struct
	import binascii
	import sys
	import getpass
	import unicodedata

	args = get_argparser().parse_args()

	if (args.id is None) or args.id > 2:
		raise Exception("Missing identity number [0-2]")

	dongle = getDongle(args.apdu)

	def enter_if_none_and_normalize(hint, strg):
		if strg is None: # or len(string) == 0: len 0 is accepted, to specify without being bothered by a message
			strg = getpass.getpass(hint)
		if len(strg) != 0 :
			strg = unicodedata.normalize('NFKD', u''+strg)
		return strg

	if (args.id < 2):
		args.pin = enter_if_none_and_normalize("PIN: ", args.pin)
		if args.pin is None or len(args.pin) == 0:
			raise Exception("Missing PIN for persistent identity")
	elif not args.pin is None:
		raise Exception("Can't set a PIN for the temporary identity")

	args.prefix = enter_if_none_and_normalize("Derivation prefix: ", args.prefix)
	args.passphrase = enter_if_none_and_normalize("Derivation passphrase: ", args.passphrase)
	args.words = enter_if_none_and_normalize("Derivation phrase: ", args.words)

	if args.pin:
		apdudata = bytearray([len(args.pin)]) + bytearray(args.pin, 'utf8')
	else:
		apdudata = bytearray([0])

	if args.prefix:
		apdudata += bytearray([len(args.prefix)]) + bytearray(args.prefix, 'utf8')
	else:
		apdudata += bytearray([0])

	if args.passphrase:
		apdudata += bytearray([len(args.passphrase)]) + bytearray(args.passphrase, 'utf8')
	else:
		apdudata += bytearray([0])

	if args.words:
		apdudata += bytearray([len(args.words)]) + bytearray(args.words, 'utf8')
	else:
		apdudata += bytearray([0])

	apdu = bytearray([0xE0, 0xD0, args.id, 0x00, len(apdudata)]) + apdudata
	dongle.exchange(apdu, timeout=3000)
