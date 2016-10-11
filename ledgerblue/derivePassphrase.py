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

from .comm import getDongle
import argparse
import getpass

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--persistent", help="Persist passphrase as secondary PIN", action='store_true')

args = parser.parse_args()

dongle = getDongle(False)

passphrase = getpass.getpass("Enter BIP39 passphrase : ")
if len(passphrase) != 0:
	if args.persistent:
		p1 = 0x02
	else:
		p1 = 0x01
	apdu = bytearray([0xE0, 0xD0, p1, 0x00, len(passphrase)]) + bytearray(passphrase)
	dongle.exchange(apdu, timeout=300)

