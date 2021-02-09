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
	parser = argparse.ArgumentParser("Update the firmware by using Ledger to open a Secure Channel.")
	parser.add_argument("--url", help="Websocket URL", default="wss://scriptrunner.api.live.ledger.com/update/genuine")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--perso", help="""A reference to the personalization key; this is a reference to the specific
Issuer keypair used by Ledger to sign the device's Issuer Certificate""", default="perso_11")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	return parser

def auto_int(x):
	return int(x, 0)

def hexstr(bstr):
	if (sys.version_info.major == 3):
		return binascii.hexlify(bstr).decode()
	if (sys.version_info.major == 2):
		return binascii.hexlify(bstr)
	return ""

def process(dongle, request):
	response = {}
	apdusList = []
	try:
		response['nonce'] = request['nonce']
		if (request['query'] == "exchange"):
			apdusList.append(binascii.unhexlify(request['data']))
		elif (request['query'] == "bulk"):
			for apdu in request['data']:
				apdusList.append(binascii.unhexlify(apdu))
		else:
			response['response'] = "unsupported"
	except:
		response['response'] = "parse error"

	if len(apdusList) != 0:
		try:
			for apdu in apdusList:
				response['data'] = hexstr(dongle.exchange(apdu))
			if len(response['data']) == 0:
				response['data'] = "9000"
			response['response'] = "success"
		except:
			response['response'] = "I/O" # or error, and SW in data

	return response			

if __name__ == '__main__':
	import sys
	import os
	import struct
	if sys.version_info.major == 3:
		import urllib.request as urllib2
		import urllib.parse as urlparse
	else:
		import urllib2, urllib, urlparse	
	from .comm import getDongle
	from websocket import create_connection
	import json
	import binascii
	import sys

	args = get_argparser().parse_args()
	if args.url == None:
		raise Exception("No URL specified")
	if args.perso == None:
		raise Exception("No personalization specified")
	if args.targetId == None:
		args.targetId = 0x31000002 # Ledger Blue by default

	dongle = getDongle(args.apdu)

	url = args.url
	queryParameters = {}
	queryParameters['targetId'] = args.targetId
	queryParameters['perso'] = args.perso
	if sys.version_info.major == 3:
  		queryString = urlparse.urlencode(queryParameters)
	else:
		queryString = urllib.urlencode(queryParameters)
	ws = create_connection(args.url + '?' + queryString)
	while True:
		result = json.loads(ws.recv())
		if result['query'] == 'success':
			break
		if result['query'] == 'error':
			raise Exception(result['data'] + " on " + result['uuid'] + "/" + result['session'])
		response = process(dongle, result)
		ws.send(json.dumps(response))
	ws.close()

	print("Product is genuine")
