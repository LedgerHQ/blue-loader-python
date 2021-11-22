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
import ssl

def get_argparser():
	parser = argparse.ArgumentParser("Update the firmware by using Ledger to open a Secure Channel.")
	parser.add_argument("--url", help="Server URL", default="https://hsmprod.hardwarewallet.com/hsm/process")
	parser.add_argument("--bypass-ssl-check", help="Keep going even if remote certificate verification fails", action='store_true', default=False)
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--perso", help="""A reference to the personalization key; this is a reference to the specific
Issuer keypair used by Ledger to sign the device's Issuer Certificate""", default="perso_11")
	parser.add_argument("--firmware", help="A reference to the firmware to load", required=True)
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int, default=0x31000002)
	parser.add_argument("--firmwareKey", help="A reference to the firmware key to use", required=True)
	return parser

def auto_int(x):
	return int(x, 0)

def serverQuery(request, url):
	data = request.SerializeToString()
	urll = urlparse.urlparse(args.url)
	req = urllib2.Request(args.url, data, {"Content-type": "application/octet-stream" })
	if args.bypass_ssl_check:
		res = urllib2.urlopen(req, context=ssl._create_unverified_context())
	else:
		res = urllib2.urlopen(req)
	data = res.read()
	response = Response()
	response.ParseFromString(data)
	if len(response.exception) != 0:
		raise Exception(response.exception)
	return response

if __name__ == '__main__':
	import struct
	import urllib.request as urllib2
	import urllib.parse as urlparse
	from .BlueHSMServer_pb2 import Request, Response
	from .comm import getDongle

	args = get_argparser().parse_args()

	dongle = getDongle(args.apdu)

	# Identify

	targetid = bytearray(struct.pack('>I', args.targetId))
	apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
	dongle.exchange(apdu)

	# Get nonce and ephemeral key

	request = Request()
	request.reference = "distributeFirmware11_scan"
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "persoKey"
	parameter.name = args.perso
	if args.targetId&0xF >= 0x3:
		parameter = request.remote_parameters.add()
		parameter.local = False
		parameter.alias = "scpv2"
		parameter.name = "dummy"
	request.largeStack = True

	response = serverQuery(request, args.url)

	offset = 0

	remotePublicKey = response.response[offset : offset + 65]
	offset += 65
	nonce = response.response[offset : offset + 8]
	if args.targetId&0xF >= 0x3:
		offset += 8
		masterPublicKey = response.response[offset : offset + 65]
		offset += 65
		masterPublicKeySignatureLength = response.response[offset + 1] + 2
		masterPublicKeySignature = response.response[offset : offset + masterPublicKeySignatureLength]

	# Initialize chain

	apdu = bytearray([0xe0, 0x50, 0x00, 0x00, 0x08]) + nonce
	deviceInit = dongle.exchange(apdu)
	deviceNonce = deviceInit[4 : 4 + 8]

	# Get remote certificate

	request = Request()
	request.reference = "distributeFirmware11_scan"
	request.id = response.id
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "persoKey"
	parameter.name = args.perso
	request.parameters = bytes(deviceNonce)
	request.largeStack = True

	response = serverQuery(request, args.url)

	offset = 0

	responseLength = response.response[offset + 1]
	remotePublicKeySignatureLength = responseLength + 2
	remotePublicKeySignature = response.response[offset : offset + remotePublicKeySignatureLength]

	certificate = bytearray([len(remotePublicKey)]) + remotePublicKey + bytearray([len(remotePublicKeySignature)]) + remotePublicKeySignature
	apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
	dongle.exchange(apdu)

	# Walk the chain

	index = 0
	while True:
			if index == 0:
				certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
			elif index == 1:
				certificate = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))
			else:
					break
			if len(certificate) == 0:
				break
			request = Request()
			request.reference = "distributeFirmware11_scan"
			request.id = response.id
			request.parameters = bytes(certificate)
			request.largeStack = True
			serverQuery(request, args.url)
			index += 1

	# Commit agreement and send firmware

	request = Request()
	request.reference = "distributeFirmware11_scan"
	if args.targetId&0xF >= 0x3:
		parameter = request.remote_parameters.add()
		parameter.local = False
		parameter.alias = "scpv2"
		parameter.name = "dummy"
	request.id = response.id
	request.largeStack = True

	response = serverQuery(request, args.url)
	responseData = bytearray(response.response)

	dongle.exchange(bytearray.fromhex('E053000000'))

	for i in range(100):
		if len(responseData) == 0:
			break
		if bytes(responseData[0:4]) == b"SECU":
			raise Exception("Security exception " + chr(responseData[4]))

		responseData = dongle.exchange(responseData)

		request = Request()
		request.reference = "distributeFirmware11_scan"
		request.parameters = b"\xFF" + b"\xFF" + bytes(responseData)
		request.id = response.id
		request.largeStack = True

		response = serverQuery(request, args.url)
		responseData = bytearray(response.response)


	request = Request()
	request.reference = "distributeFirmware11_scan"
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "firmware"
	parameter.name = args.firmware
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "firmwareKey"
	parameter.name = args.firmwareKey
	request.id = response.id
	request.largeStack = True

	response = serverQuery(request, args.url)
	responseData = bytearray(response.response)

	offset = 0
	while offset < len(responseData):
		apdu = responseData[offset : offset + 5 + responseData[offset + 4]]
		dongle.exchange(apdu)
		offset += 5 + responseData[offset + 4]

	dongle.close()
