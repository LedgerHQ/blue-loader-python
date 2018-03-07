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
import binascii

from ledgerblue.comm import getDongle
from ledgerblue.deployed import getDeployedSecretV1, getDeployedSecretV2
from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.hexLoader import HexLoader


def get_argparser():
    parser = argparse.ArgumentParser(description="Delete the app with the specified name.")
    parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
    parser.add_argument("--appName", help="The name of the application to delete")
    parser.add_argument("--appHash", help="Set the application hash")
    parser.add_argument("--rootPrivateKey", help="A private key used to establish a Secure Channel (hex encoded)")
    parser.add_argument("--apdu", help="Display APDU log", action='store_true')
    parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')
    return parser


def auto_int(x):
    return int(x, 0)


if __name__ == '__main__':
    args = get_argparser().parse_args()

    if args.appName is None and args.appHash is None:
        raise Exception("Missing appName or appHash")
    if args.appName is not None and args.appHash is not None:
        raise Exception("Set either appName or appHash")

    if args.appName:
        args.appName = args.appName.encode('ascii')

    if args.appHash:
        args.appHash = binascii.unhexlify(args.appHash)

    if not args.targetId:
        args.targetId = 0x31000002

    if not args.rootPrivateKey:
        privateKey = PrivateKey()
        publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
        print("Generated random root public key : %s" % publicKey)
        args.rootPrivateKey = privateKey.serialize()

    dongle = getDongle(args.apdu)

    if args.deployLegacy:
        secret = getDeployedSecretV1(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
    else:
        secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)

    loader = HexLoader(dongle, 0xe0, True, secret)

    if args.appName:
        loader.deleteApp(args.appName)

    if args.appHash:
        loader.deleteAppByHash(args.appHash)
