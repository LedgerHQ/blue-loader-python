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

def auto_int(x):
    return int(x, 0)

def get_argparser():
    parser = argparse.ArgumentParser(description="""Load the firmware onto the MCU. The MCU must already be in
bootloader mode.""")
    parser.add_argument("--targetId", help="The device's target ID", type=auto_int)
    parser.add_argument("--fileName", help="The name of the firmware file to load")
    parser.add_argument("--bootAddr", help="The firmware's boot address", type=auto_int)
    parser.add_argument("--apdu", help="Display APDU log", action='store_true')
    parser.add_argument("--reverse", help="Load HEX file in reverse from the highest address to the lowest", action='store_true')
    parser.add_argument("--nocrc", help="Load HEX file without checking CRC of loaded sections", action='store_true')
    return parser

if __name__ == '__main__':
    from .hexParser import IntelHexParser
    from .hexLoader import HexLoader
    from .comm import getDongle

    args = get_argparser().parse_args()

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
    hash = loader.load(0xFF, 0xF0, parser, reverse=args.reverse, doCRC=(not args.nocrc))
    loader.run(args.bootAddr)
    