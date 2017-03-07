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

from .ecWrapper import PrivateKey
from .comm import getDongle
from .hexParser import IntelHexParser, IntelHexPrinter
from .hexLoader import HexLoader
from .deployed import getDeployedSecretV1, getDeployedSecretV2
import argparse
import struct
import binascii
import sys

privateKey = PrivateKey()
publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
print("Public key : %s" % publicKey)
print("Private key: %s" % privateKey.serialize())
