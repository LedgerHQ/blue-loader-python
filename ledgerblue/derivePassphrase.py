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
	parser = argparse.ArgumentParser(description="Set a BIP 39 passphrase on the device.")
	parser.add_argument("--persistent", help="""Persist passphrase as secondary PIN (otherwise, it's set as a temporary
passphrase)""", action='store_true')
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	from .comm import getDongle
	import getpass
	import unicodedata
	import sys

	args = get_argparser().parse_args()

	dongle = getDongle(False)

	passphrase = getpass.getpass("Enter BIP39 passphrase : ")
	if isinstance(passphrase, bytes):
		passphrase = passphrase.decode(sys.stdin.encoding)
	if len(passphrase) != 0:
		if args.persistent:
			p1 = 0x02
		else:
			p1 = 0x01
		passphrase = unicodedata.normalize('NFKD', passphrase)
		apdu = bytearray([0xE0, 0xD0, p1, 0x00, len(passphrase)]) + bytearray(passphrase, 'utf8')
		dongle.exchange(apdu, timeout=300)
