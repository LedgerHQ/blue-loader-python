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
import binascii
import argparse


def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument(
    "--key", help="Reference of the endorsement key to setup (1 or 2)", type=auto_int)
parser.add_argument(
    "--certificate", help="Certificate to store if finalizing the endorsement (hex encoded)")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')

args = parser.parse_args()

if args.key == None:
    raise Exception("Missing endorsement key reference")
if args.key != 1 and args.key != 2:
    raise Exception("Invalid endorsement key reference")

dongle = getDongle(args.apdu)
if args.certificate == None:
    apdu = bytearray([0xe0, 0xC0, args.key, 0x00, 0x00])
    response = dongle.exchange(apdu)
    print("Public key " + str(response[0:65]).encode('hex'))
    print("Certificate " + str(response[65:]).encode('hex'))
else:
    certificate = bytearray.fromhex(args.certificate)
    apdu = bytearray([0xe0, 0xC2, 0x00, 0x00, len(certificate)]) + certificate
    dongle.exchange(apdu)
    print("Endorsement setup finalized")
