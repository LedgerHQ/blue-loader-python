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
	parser = argparse.ArgumentParser(description="""Use attestation to determine if the device is a genuine Ledger
device.""")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--issuerKey", help="Issuer key (hex encoded, default is batch 1)")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	return parser

def auto_int(x):
	return int(x, 0)

def getDeployedSecretV2(dongle, masterPrivate, targetId, issuerKey):
		testMaster = PrivateKey(bytes(masterPrivate))
		testMasterPublic = bytearray(testMaster.pubkey.serialize(compressed=False))
		targetid = bytearray(struct.pack('>I', targetId))

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
		devicePublicKey = None
		while True:
				if index == 0:
						certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
				elif index == 1:
						certificate = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))
				else:
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
						devicePublicKey = certificatePublicKey
						certificateSignedData = bytearray([0x02]) + certificateHeader + certificatePublicKey
						# Could check if the device certificate is signed by the issuer public key
				# ephemeral key certificate
				else:
						certificateSignedData = bytearray([0x12]) + deviceNonce + nonce + certificatePublicKey
				if not last_pub_key.ecdsa_verify(bytes(certificateSignedData), certificateSignature):
						return None
				last_pub_key = PublicKey(bytes(certificatePublicKey), raw=True)
				index = index + 1

		# Commit device ECDH channel
		dongle.exchange(bytearray.fromhex('E053000000'))
		secret = last_pub_key.ecdh(binascii.unhexlify(ephemeralPrivate.serialize()))
		if targetId&0xF == 0x2:
			return secret[0:16]
		elif targetId&0xF == 0x3:
			ret = {}
			ret['ecdh_secret'] = secret
			ret['devicePublicKey'] = devicePublicKey
		return ret

if __name__ == '__main__':
	from .ecWrapper import PrivateKey, PublicKey
	from .comm import getDongle
	from .commException import CommException
	from .hexLoader import HexLoader
	import struct
	import os
	import binascii

	args = get_argparser().parse_args()

	if args.targetId == None:
			args.targetId = 0x31000002

	if args.issuerKey == None:
			args.issuerKey = "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609"

	privateKey = PrivateKey()
	publicKey = str(privateKey.pubkey.serialize(compressed=False))
	args.rootPrivateKey = privateKey.serialize()

	genuine = False
	ui = False
	customCA = False

	dongle = getDongle(args.apdu)
	version = None

	secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId, args.issuerKey)
	if secret != None:
			try:
				loader = HexLoader(dongle, 0xe0, True, secret)
				version = loader.getVersion()
				genuine = True
				apps = loader.listApp()
				while len(apps) != 0:
					for app in apps:
						if (app['flags'] & 0x08):
							ui = True
						if (app['flags'] & 0x400):
							customCA = True
					apps = loader.listApp(False)
			except:
				genuine = False			
	if genuine:
		if ui:
			print ("WARNING : Product is genuine but has a UI application loaded")
		if customCA:
			print ("WARNING : Product is genuine but has a Custom CA loaded")
		if not ui and not customCA:
			print ("Product is genuine")
		print ("SE Version " + version['osVersion'])
		print ("MCU Version " + version['mcuVersion'])
		if 'mcuHash' in version:
			print ("MCU Hash " + binascii.hexlify(version['mcuHash']).decode('ascii'))
	else:
		print ("Product is NOT genuine")
