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

from .comm import getDongle
from .ecWrapper import PrivateKey
from .deployed import getDeployedSecretV1, getDeployedSecretV2
from .hexLoader import HexLoader


def get_arg_parser():
    parser = argparse.ArgumentParser(description="Delete the app with the specified name.")
    parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)",
                        type=lambda n: int(n, 0), default=0x31000002)
    parser.add_argument("--appName", help="The name of the application to delete")
    parser.add_argument("--appHash", help="Set the application hash")
    parser.add_argument("--rootPrivateKey", help="A private key used to establish a Secure Channel (hex encoded)")
    parser.add_argument("--debug", help="Display APDU log", action='store_true')
    parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')
    return parser


def main():
    args = get_arg_parser().parse_args()

    if args.appName is None and args.appHash is None:
        raise Exception("Missing appName or appHash")
    if args.appName is not None and args.appHash is not None:
        raise Exception("Set either appName or appHash")

    app_name, app_hash = None, None
    if args.appName is not None:
        app_name = args.appName.encode()
    elif args.appHash is not None:
        app_hash = bytes.fromhex(args.appHash)

    if args.rootPrivateKey is None:
        private_key = PrivateKey()
        public_key = private_key.pubkey.serialize(compressed=False)
        print("Generated random root public key : {}".format(public_key.hex()))
        private_key = private_key.serialize()
    else:
        private_key = args.rootPrivateKey

    dongle = getDongle(args.debug)
    if args.deployLegacy:
        secret = getDeployedSecretV1(dongle, bytes.fromhex(private_key), args.targetId)
    else:
        secret = getDeployedSecretV2(dongle, bytes.fromhex(private_key), args.targetId)

    loader = HexLoader(dongle, 0xe0, True, secret)
    if app_name is not None:
        loader.deleteApp(app_name)
    elif app_hash is not None:
        loader.deleteAppByHash(app_hash)


if __name__ == '__main__':
    main()
