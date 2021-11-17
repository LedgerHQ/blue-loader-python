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
import struct

def get_argparser():
	parser = argparse.ArgumentParser(description="Calculate an application hash from the application's hex file.")
	parser.add_argument("--hex", help="The application hex file to be hashed", required=True)
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--targetVersion", help="Set the chip target version")
	return parser

def auto_int(x):
	return int(x, 0)

if __name__ == '__main__':
	from .hexParser import IntelHexParser
	import hashlib

	args = get_argparser().parse_args()

	# parse
	parser = IntelHexParser(args.hex)

	# prepare data
	m = hashlib.sha256()

	if args.targetId:
		m.update(struct.pack(">I", args.targetId))

	if args.targetVersion:
		m.update(args.targetVersion)

	# consider areas are ordered by ascending address and non-overlaped
	for a in parser.getAreas():
		m.update(a.data)
	dataToSign = m.digest()

	print(dataToSign.hex())
