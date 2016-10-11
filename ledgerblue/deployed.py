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

from .ecWrapper import PrivateKey, PublicKey
import os
import sys
import struct
from .hexParser import IntelHexParser
from .hexLoader import HexLoader
import binascii

def getDeployedSecretV1(dongle, masterPrivate, targetid):
	testMaster = PrivateKey(bytes(masterPrivate))
	testMasterPublic = bytearray(testMaster.pubkey.serialize(compressed=False))
	targetid = bytearray(struct.pack('>I', targetid))

	# identify
	apdu = bytearray([0xe0, 0x04, 0x00, 0x00]) + bytearray([len(targetid)]) + targetid
	dongle.exchange(apdu)

	# walk the chain 
	batch_info = bytearray(dongle.exchange(bytearray.fromhex('E050000000')))
	cardKey = batch_info[5:5 + batch_info[4]]

	# if not found, get another pair
	#if cardKey != testMasterPublic:
	#	raise Exception("Invalid batch public key")

	# provide the ephemeral certificate
	ephemeralPrivate = PrivateKey()
	ephemeralPublic = bytearray(ephemeralPrivate.pubkey.serialize(compressed=False))
	print("Using ephemeral key %s" %binascii.hexlify(ephemeralPublic))
	signature = testMaster.ecdsa_sign(bytes(ephemeralPublic))
	signature = testMaster.ecdsa_serialize(signature)
	certificate = bytearray([len(ephemeralPublic)]) + ephemeralPublic + bytearray([len(signature)]) + signature
	apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
	dongle.exchange(apdu)

	# walk the device certificates to retrieve the public key to use for authentication
	index = 0
	last_pub_key = PublicKey(bytes(testMasterPublic), raw=True)
	while True:
		certificate = bytearray(dongle.exchange(bytearray.fromhex('E052000000')))
		if len(certificate) == 0:
			break
		certificatePublic = certificate[1 : 1 + certificate[0]]
		certificateSignature = last_pub_key.ecdsa_deserialize(bytes(certificate[2 + certificate[0] :]))		
		if not last_pub_key.ecdsa_verify(bytes(certificatePublic), certificateSignature):
			if index == 0:
				# Not an error if loading from user key
				print("Broken certificate chain - loading from user key")
			else:
				raise Exception("Broken certificate chain")
		last_pub_key = PublicKey(bytes(certificatePublic), raw=True)
		index = index + 1

	# Commit device ECDH channel
	dongle.exchange(bytearray.fromhex('E053000000'))
	secret = last_pub_key.ecdh(bytes(ephemeralPrivate.serialize().decode('hex')))
	return secret[0:16]

def getDeployedSecretV2(dongle, masterPrivate, targetid):
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
	#	raise Exception("Invalid batch public key")

	print("Using test master key %s " % binascii.hexlify(testMasterPublic))
	dataToSign = bytes(bytearray([0x01]) + testMasterPublic)
	signature = testMaster.ecdsa_sign(bytes(dataToSign))
	signature = testMaster.ecdsa_serialize(signature)
	certificate = bytearray([len(testMasterPublic)]) + testMasterPublic + bytearray([len(signature)]) + signature
	apdu = bytearray([0xE0, 0x51, 0x00, 0x00]) + bytearray([len(certificate)]) + certificate
	dongle.exchange(apdu)
	
	# provide the ephemeral certificate
	ephemeralPrivate = PrivateKey()
	ephemeralPublic = bytearray(ephemeralPrivate.pubkey.serialize(compressed=False))
	print("Using ephemeral key %s" %binascii.hexlify(ephemeralPublic))
	dataToSign = bytes(bytearray([0x11]) + nonce + deviceNonce + ephemeralPublic)
	signature = testMaster.ecdsa_sign(bytes(dataToSign))
	signature = testMaster.ecdsa_serialize(signature)
	certificate = bytearray([len(ephemeralPublic)]) + ephemeralPublic + bytearray([len(signature)]) + signature
	apdu = bytearray([0xE0, 0x51, 0x80, 0x00]) + bytearray([len(certificate)]) + certificate
	dongle.exchange(apdu)

	# walk the device certificates to retrieve the public key to use for authentication
	index = 0
	last_pub_key = PublicKey(bytes(testMasterPublic), raw=True)
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
			if index == 0:
				# Not an error if loading from user key
				print("Broken certificate chain - loading from user key")
			else:
				raise Exception("Broken certificate chain")
		last_pub_key = PublicKey(bytes(certificatePublicKey), raw=True)
		index = index + 1

	# Commit device ECDH channel
	dongle.exchange(bytearray.fromhex('E053000000'))
	secret = last_pub_key.ecdh(binascii.unhexlify(ephemeralPrivate.serialize()))
	return secret[0:16]
