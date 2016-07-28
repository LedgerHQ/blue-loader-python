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
from .hexParser import IntelHexParser
from .hexLoader import HexLoader
from .comm import getDongle
import argparse

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--targetId", help="Set the chip target ID", type=auto_int)
parser.add_argument("--fileName", help="Set the file name to load")
parser.add_argument("--bootAddr", help="Set the boot address", type=auto_int)
parser.add_argument("--apdu", help="Display APDU log", action='store_true')

args = parser.parse_args()

if args.targetId == None:
	raise Exception("Missing targetId")
if args.fileName == None:
	raise Exception("Missing fileName")

parser = IntelHexParser(args.fileName)
if args.bootAddr == None:
    args.bootAddr = parser.getBootAddr()

dongle = getDongle(args.apdu)

#relative load
loader = HexLoader(dongle, 0xe0, False, None, False)

loader.validateTargetId(args.targetId)
hash = loader.load(0xFF, 0xF0, parser.getAreas(), args.bootAddr)
loader.run(parser.getAreas(), args.bootAddr)
