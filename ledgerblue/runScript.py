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

from ledgerblue.comm import getDongle
import argparse

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--fileName", help="Set the file name to load")
parser.add_argument("--apdu", help="Display APDU log", action='store_true')

args = parser.parse_args()

if args.fileName == None:
	raise Exception("Missing fileName")

dongle = getDongle(args.apdu)
file = open(args.fileName, "r")
for data in file:
	data = data.rstrip('\r\n').decode('hex')
	dongle.exchange(bytearray(data))	

