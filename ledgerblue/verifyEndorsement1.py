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

from .ecWrapper import PublicKey
import hashlib
import binascii
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--key", help="The public endorsement key 1 to verify with (hex encoded)")
parser.add_argument("--codehash", help="The hash of the code associated to the endorsement request (hex encoded)")
parser.add_argument("--message", help="The message associated to the endorsement request (hex encoded)")
parser.add_argument("--signature", help="The signature to verify with (hex encoded)")

args = parser.parse_args()

if args.key == None:
	raise Exception("Missing public key")
if args.codehash == None:
	raise Exception("Missing code hash")
if args.message == None:
	raise Exception("Missing message")
if args.signature == None:
	raise Exception("Missing signature")

# prepare data
m = hashlib.sha256()
m.update(bytes(bytearray.fromhex(args.message)))
m.update(bytes(bytearray.fromhex(args.codehash)))
digest = m.digest()

publicKey = PublicKey(bytes(bytearray.fromhex(args.key)), raw=True)
signature = publicKey.ecdsa_deserialize(bytes(bytearray.fromhex(args.signature)))
if not publicKey.ecdsa_verify(bytes(digest), signature, raw=True):
	raise Exception("Endorsement not verified")

print("Endorsement verified")
