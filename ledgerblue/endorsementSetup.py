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
	parser = argparse.ArgumentParser(description="""Generate an attestation keypair, using the provided Owner private
key to sign the Owner Certificate.""")
	parser.add_argument("--key", help="Which endorsement scheme to use (1 or 2)", type=auto_int)
	parser.add_argument("--certificate", help="""Optional certificate to store if finalizing the endorsement (hex
encoded), if no private key is specified""")
	parser.add_argument("--privateKey", help="""Optional private key to use to create a test certificate (hex encoded),
if no certificate is specified""")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--issuerKey", help="Issuer key (hex encoded, default is batch 1)")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	return parser

def auto_int(x):
		return int(x, 0)

def hexstr(bstr):
	if (sys.version_info.major == 3):
		return binascii.hexlify(bstr).decode()
	if (sys.version_info.major == 2):
		return binascii.hexlify(bstr)
	return ""

def getDeployedSecretV2(dongle, masterPrivate, targetid, issuerKey):
		testMaster = PrivateKey(bytes(masterPrivate))
		testMasterPublic = bytearray(testMaster.pubkey.serialize(compressed=False))
		targetid = bytearray(struct.pack('>I', targetid))

		# identify
		apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
		dongle.exchange(apdu)

		# walk the chain
		nonce = os.urandom(8)
		apdu = bytearray([0xe0, 0x50, 0x00, 0x00]) + bytearray([len(nonce)]) + nonce
		auth_info = dongle.exchange(apdu)
		batch_signer_serial = auth_info[0:4]
		deviceNonce = auth_info[4:12]

		# if not found, get another pair
		#if cardKey != testMasterPublic:
		#	   raise Exception("Invalid batch public key")

		dataToSign = bytes(bytearray([0x01]) + testMasterPublic)
		signature = testMaster.ecdsa_sign(bytes(dataToSign))
		signature = testMaster.ecdsa_serialize(signature)
		certificate = bytearray([len(testMasterPublic)]) + testMasterPublic + bytearray([len(signature)]) + signature
		apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
		dongle.exchange(apdu)

		# provide the ephemeral certificate
		ephemeralPrivate = PrivateKey()
		ephemeralPublic = bytearray(ephemeralPrivate.pubkey.serialize(compressed=False))
		dataToSign = bytes(bytearray([0x11]) + nonce + deviceNonce + ephemeralPublic)
		signature = testMaster.ecdsa_sign(bytes(dataToSign))
		signature = testMaster.ecdsa_serialize(signature)
		certificate = bytearray([len(ephemeralPublic)]) + ephemeralPublic + bytearray([len(signature)]) + signature
		apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
		dongle.exchange(apdu)

		# walk the device certificates to retrieve the public key to use for authentication
		index = 0
		last_pub_key = PublicKey(binascii.unhexlify(issuerKey), raw=True)
		device_pub_key = None
		while True:
				if index == 0:
						certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
				elif index == 1:
						certificate = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))
				else:
						break
				if len(certificate) == 0:
						break
				offset = 1
				certificateHeader = certificate[offset : offset + certificate[offset-1]]
				offset += certificate[offset-1] + 1
				certificatePublicKey = certificate[offset : offset + certificate[offset-1]]
				offset += certificate[offset-1] + 1
				certificateSignatureArray = certificate[offset : offset + certificate[offset-1]]
				certificateSignature = last_pub_key.ecdsa_deserialize(bytes(certificateSignatureArray))
				# first cert contains a header field which holds the certificate's public key role
				if index == 0:
						certificateSignedData = bytearray([0x02]) + certificateHeader + certificatePublicKey
						# Could check if the device certificate is signed by the issuer public key
				# ephemeral key certificate
				else:
						certificateSignedData = bytearray([0x12]) + deviceNonce + nonce + certificatePublicKey
				if not last_pub_key.ecdsa_verify(bytes(certificateSignedData), certificateSignature):
						return None
				last_pub_key = PublicKey(bytes(certificatePublicKey), raw=True)
				if index == 0:
					device_pub_key = last_pub_key
				index = index + 1

		return device_pub_key

if __name__ == '__main__':
	from .comm import getDongle
	from .ecWrapper import PrivateKey, PublicKey
	import hashlib
	import struct
	import os
	import sys
	import binascii

	args = get_argparser().parse_args()

	if args.key == None:
			raise Exception("Missing endorsement scheme number")
	if args.key != 1 and args.key != 2:
			raise Exception("Invalid endorsement scheme number")
	if args.targetId == None:
			args.targetId = 0x31000002
	if args.issuerKey == None:
			args.issuerKey = "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609"
	if (args.privateKey != None) and (args.certificate != None):
		raise Exception("Cannot specify both certificate and privateKey")

	privateKey = PrivateKey()
	publicKey = str(privateKey.pubkey.serialize(compressed=False))
	args.rootPrivateKey = privateKey.serialize()

	dongle = getDongle(args.apdu)
	publicKey = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId, args.issuerKey)

	if args.certificate == None:
			apdu = bytearray([0xe0, 0xC0, args.key, 0x00, 0x00])
			response = dongle.exchange(apdu)
			print("Public key " + hexstr(response[0:65]))
			m = hashlib.sha256()
			m.update(bytes(b"\xff")) # Endorsement role
			m.update(bytes(response[0:65]))
			digest = m.digest()
			signature = publicKey.ecdsa_deserialize(bytes(response[65:]))
			if not publicKey.ecdsa_verify(bytes(digest), signature, raw=True):
				raise Exception("Issuer certificate not verified")
			if args.privateKey != None:
				privateKey = PrivateKey(bytes(args.privateKey.decode('hex')))
				dataToSign = bytes(bytearray([0xfe]) + response[0:65])
				signature = privateKey.ecdsa_sign(bytes(dataToSign))
				args.certificate = hexstr(privateKey.ecdsa_serialize(signature))

	if args.certificate != None:
			certificate = bytearray.fromhex(args.certificate)
			apdu = bytearray([0xe0, 0xC2, 0x00, 0x00, len(certificate)]) + certificate
			dongle.exchange(apdu)
			print("Endorsement setup finalized")
