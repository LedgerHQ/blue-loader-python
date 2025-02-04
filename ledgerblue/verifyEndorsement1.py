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
    parser = argparse.ArgumentParser(
        description="Verify a message signature created with Endorsement Scheme #1."
    )
    parser.add_argument(
        "--key",
        help="The endorsement public key with which to verify the signature (hex encoded)",
        required=True,
    )
    parser.add_argument(
        "--codehash",
        help="The hash of the app associated with the endorsement request (hex encoded)",
        required=True,
    )
    parser.add_argument(
        "--message",
        help="The message associated to the endorsement request (hex encoded)",
        required=True,
    )
    parser.add_argument(
        "--signature", help="The signature to be verified (hex encoded)", required=True
    )
    return parser


if __name__ == "__main__":
    import hashlib

    from .ecWrapper import PublicKey

    args = get_argparser().parse_args()

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
