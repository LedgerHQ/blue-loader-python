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
    parser = argparse.ArgumentParser(description="Sign an application using the provided Custom CA private key.")
    parser.add_argument("--hex", help="The hex file of the application that is to be signed")
    parser.add_argument("--key", help="The private key with which to sign the app (hex encoded)")
    return parser


def auto_int(x):
    return int(x, 0)


def hexstr(bstr):
    if sys.version_info.major == 3:
        return binascii.hexlify(bstr).decode()
    if sys.version_info.major == 2:
        return binascii.hexlify(bstr)
    return ""


if __name__ == '__main__':
    from .hexParser import IntelHexParser
    from .ecWrapper import PrivateKey
    import hashlib
    import sys
    import binascii

    args = get_argparser().parse_args()

    if args.hex is None:
        raise Exception("Missing hex filename to sign")
    if args.key is None:
        raise Exception("Missing private key")

    # parse
    parser = IntelHexParser(args.hex)

    # prepare data
    m = hashlib.sha256()
    # consider areas are ordered by ascending address and non-overlaped
    for a in parser.getAreas():
        m.update(a.data)
    dataToSign = m.digest()

    MASTER_PRIVATE = bytearray.fromhex(args.key)
    testMaster = PrivateKey(bytes(MASTER_PRIVATE))
    # testMasterPublic = bytearray(testMaster.pubkey.serialize(compressed=False))

    signature = testMaster.ecdsa_sign(bytes(dataToSign), raw=True)

    # test signature before printing it
    if testMaster.pubkey.ecdsa_verify(dataToSign, signature, raw=True):
        # print("Signer's public: " + binascii.hexlify(testMasterPublic))
        print(hexstr(testMaster.ecdsa_serialize(signature)))
