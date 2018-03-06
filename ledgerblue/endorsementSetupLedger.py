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
	parser = argparse.ArgumentParser(description="""Generate an attestation keypair, using Ledger to sign the Owner
certificate.""")
	parser.add_argument("--url", help="Server URL", default="https://hsmprod.hardwarewallet.com/hsm/process")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--perso", help="""A reference to the personalization key; this is a reference to the specific
Issuer keypair used by Ledger to sign the device's Issuer Certificate""", default="perso_11")
	parser.add_argument("--endorsement", help="""A reference to the endorsement key to use; this is a reference to the
specific Owner keypair to be used by Ledger to sign the Owner Certificate""", default="attest_1")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--key", help="Which endorsement scheme to use (1 or 2)", type=auto_int)
	return parser

def auto_int(x):
	return int(x, 0)

def serverQuery(request, url):
	data = request.SerializeToString()
	urll = urlparse.urlparse(args.url)
	req = urllib2.Request(args.url, data, {"Content-type": "application/octet-stream" })
	res = urllib2.urlopen(req)
	data = res.read()
	response = Response()
	response.ParseFromString(data)
	if len(response.exception) != 0:
		raise Exception(response.exception)
	return response

if __name__ == '__main__':
	import sys
	import os
	import struct
	if sys.version_info.major == 3:
		import urllib.request as urllib2
		import urllib.parse as urlparse
	else:
		import urllib2, urlparse
	from .BlueHSMServer_pb2 import Request, Response, Parameter
	from .comm import getDongle

	args = get_argparser().parse_args()

	if args.url == None:
		raise Exception("No URL specified")
	if args.perso == None:
		raise Exception("No personalization specified")
	if args.endorsement == None:
		raise Exception("No endorsement specified")
	if args.key != 1 and args.key != 2:
			raise Exception("Invalid endorsement scheme number")
	if args.targetId == None:
		args.targetId = 0x31000002 # Ledger Blue by default

	dongle = getDongle(args.apdu)

	# Identify

	targetid = bytearray(struct.pack('>I', args.targetId))
	apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
	dongle.exchange(apdu)

	# Get nonce and ephemeral key

	request = Request()
	request.reference = "signEndorsement"
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "persoKey"
	parameter.name = args.perso

	response = serverQuery(request, args.url)

	offset = 0

	remotePublicKey = response.response[offset : offset + 65]
	offset += 65
	nonce = response.response[offset : offset + 8]

	# Initialize chain

	apdu = bytearray([0xe0, 0x50, 0x00, 0x00, 0x08]) + nonce
	deviceInit = dongle.exchange(apdu)
	deviceNonce = deviceInit[4 : 4 + 8]

	# Get remote certificate

	request = Request()
	request.reference = "signEndorsement"
	request.id = response.id
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "persoKey"
	parameter.name = args.perso
	request.parameters = bytes(deviceNonce)

	response = serverQuery(request, args.url)

	offset = 0

	if sys.version_info.major == 2:
		responseLength = ord(response.response[offset + 1])
	else:
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
			request.reference = "signEndorsement"
			request.id = response.id
			request.parameters = bytes(certificate)
			serverQuery(request, args.url)
			index += 1

	# Commit agreement

	request = Request()
	request.reference = "signEndorsement"
	request.id = response.id
	response = serverQuery(request, args.url)

	# Send endorsement request

	apdu = bytearray([0xe0, 0xC0, args.key, 0x00, 0x00])
	endorsementData = dongle.exchange(apdu)

	request = Request()
	request.reference = "signEndorsement"
	parameter = request.remote_parameters.add()
	parameter.local = False
	parameter.alias = "endorsementKey"
	parameter.name = args.endorsement
	request.parameters = bytes(endorsementData)
	request.id = response.id
	response = serverQuery(request, args.url)
	certificate = bytearray(response.response)

	# Commit endorsement certificate

	apdu = bytearray([0xe0, 0xC2, 0x00, 0x00, len(certificate)]) + certificate
	dongle.exchange(apdu)
	print("Endorsement setup finalized")
