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

DEFAULT_ALIGNMENT = 1024
PAGE_ALIGNMENT = 64

import argparse

def get_argparser():
	parser = argparse.ArgumentParser(description="Load an app onto the device from a hex file.")
	parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
	parser.add_argument("--fileName", help="The application hex file to be loaded onto the device")
	parser.add_argument("--icon", help="The icon content to use (hex encoded)")
	parser.add_argument("--curve", help="""A curve on which BIP 32 derivation is locked ("secp256k1", "prime256r1", or
"ed25519"), can be repeated""", action='append')
	parser.add_argument("--path", help="""A BIP 32 path to which derivation is locked (format decimal a'/b'/c), can be
repeated""", action='append')
	parser.add_argument("--appName", help="The name to give the application after loading it")
	parser.add_argument("--signature", help="A signature of the application (hex encoded)")
	parser.add_argument("--signApp", help="Sign application with provided signPrivateKey", action='store_true')
	parser.add_argument("--appFlags", help="The application flags", type=auto_int)
	parser.add_argument("--bootAddr", help="The application's boot address", type=auto_int)
	parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
	parser.add_argument("--signPrivateKey", help="Set the private key used to sign the loaded app")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--deployLegacy", help="Use legacy deployment API", action='store_true')
	parser.add_argument("--apilevel", help="Use given API level when interacting with the device", type=auto_int)
	parser.add_argument("--delete", help="Delete the app with the same name before loading the provided one", action='store_true')
	parser.add_argument("--params", help="Store icon and install parameters in a parameter section before the code", action='store_true')
	parser.add_argument("--tlv", help="Use install parameters for all variable length parameters", action='store_true')
	parser.add_argument("--dataSize", help="The code section's size in the provided hex file (to separate data from code, if not provided the whole allocated NVRAM section for the application will remain readonly.", type=auto_int)
	parser.add_argument("--appVersion", help="The application version (as a string)")
	parser.add_argument("--offline", help="Request to only output application load APDUs", action="store_true")
	parser.add_argument("--installparamsSize", help="The loaded install parameters section size (when parameters are already included within the .hex file.", type=auto_int)
	parser.add_argument("--tlvraw", help="Add a custom install param with the hextag:hexvalue encoding", action='append')
	parser.add_argument("--dep", help="Add a dependency over an appname[:appversion]", action='append')
	return parser

def auto_int(x):
	return int(x, 0)

def parse_bip32_path(path, apilevel):
		import struct
		if len(path) == 0:
				return b""
		result = b""
		elements = path.split('/')
		if apilevel >= 5:
			result = result + struct.pack('>B', len(elements))
		for pathElement in elements:
				element = pathElement.split('\'')
				if len(element) == 1:
						result = result + struct.pack(">I", int(element[0]))
				else:
						result = result + struct.pack(">I", 0x80000000 | int(element[0]))
		return result

def string_to_bytes(x):
	import sys
	if sys.version_info.major == 3:
		return bytes(x, 'ascii')
	else:
		return bytes(x)


if __name__ == '__main__':
	from .ecWrapper import PrivateKey
	from .comm import getDongle
	from .hexParser import IntelHexParser, IntelHexPrinter
	from .hexLoader import HexLoader
	from .hexLoader import *
	from .deployed import getDeployedSecretV1, getDeployedSecretV2
	import struct
	import binascii
	import sys

	args = get_argparser().parse_args()

	if args.apilevel == None:
		args.apilevel = 5
	if args.targetId == None:
		args.targetId = 0x31000002
	if args.fileName == None:
		raise Exception("Missing fileName")
	if args.appName == None:
		raise Exception("Missing appName")
	if args.appFlags == None:
		args.appFlags = 0
	if args.rootPrivateKey == None:
		privateKey = PrivateKey()
		publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
		print("Generated random root public key : %s" % publicKey)
		args.rootPrivateKey = privateKey.serialize()

	args.appName = string_to_bytes(args.appName)

	parser = IntelHexParser(args.fileName)
	if args.bootAddr == None:
		args.bootAddr = parser.getBootAddr()

	path = b""
	curveMask = 0xff
	if args.curve != None:
		curveMask = 0x00
		for curve in args.curve:
			if curve == 'secp256k1':
				curveMask |= 0x01
			elif curve == 'prime256r1':
				curveMask |= 0x02
			elif curve == 'ed25519':
				curveMask |= 0x04
			else:
				raise Exception("Unknown curve " + curve)

	if args.apilevel >= 5:
		path += struct.pack('>B',curveMask)
		if args.path != None:
			for item in args.path:
				if len(item) != 0:
					path += parse_bip32_path(item, args.apilevel)
	else:
		if args.curve != None:
			print("Curve not supported using this API level, ignoring")
		if args.path != None:
			if len(args.path) > 1:
				print("Multiple path levels not supported using this API level, ignoring")
			else:
				path = parse_bip32_path(args.path[0], args.apilevel)

	if not args.icon is None:
		args.icon = bytearray.fromhex(args.icon)
	
	signature = None
	if not args.signature is None:
		signature = bytearray.fromhex(args.signature)
	
	#prepend app's data with the icon content (could also add other various install parameters)
	printer = IntelHexPrinter(parser)

	# Use of Nested Encryption Key within the SCP protocol is mandartory for upgrades
	cleardata_block_len=None
	if args.appFlags & 2:
		# Not true for scp < 3
		# if signature is None:
		# 	raise BaseException('Upgrades must be signed')

		# ensure data can be decoded with code decryption key without troubles.
		cleardata_block_len = 16

	dongle = None
	secret = None
	if not args.offline:
		dongle = getDongle(args.apdu)

		if args.deployLegacy:
			secret = getDeployedSecretV1(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
		else:
			secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)

	loader = HexLoader(dongle, 0xe0, not(args.offline), secret, cleardata_block_len=cleardata_block_len)

	#tlv mode does not support explicit by name removal, would require a list app before to identify the hash to be removed
	if (not (args.appFlags & 2)) and args.delete:
			loader.deleteApp(args.appName)

	if (args.tlv):
		#if code length is not provided, then consider the whole provided hex file is the code and no data section is split
		code_length = printer.maxAddr() - printer.minAddr()
		if not args.dataSize is None:
			code_length -= args.dataSize
		else:
			args.dataSize = 0

		installparams = b""

		# express dependency
		if (args.dep):
			for dep in args.dep:
				appname = dep
				appversion = None
				# split if version is specified
				if (dep.find(":") != -1):
					(appname,appversion) = dep.split(":")
				depvalue = encodelv(string_to_bytes(appname))
				if(appversion):
					depvalue += encodelv(string_to_bytes(appversion))
				installparams += encodetlv(BOLOS_TAG_DEPENDENCY, depvalue)

		#add raw install parameters as requested
		if (args.tlvraw):
			for tlvraw in args.tlvraw:
				(hextag,hexvalue) = tlvraw.split(":")
				installparams += encodetlv(int(hextag, 16), binascii.unhexlify(hexvalue))

		if (not (args.appFlags & 2)) and ( args.installparamsSize is None or args.installparamsSize == 0 ):
			#build install parameters
			#mandatory app name
			installparams += encodetlv(BOLOS_TAG_APPNAME, args.appName)
			if not args.appVersion is None:
				installparams += encodetlv(BOLOS_TAG_APPVERSION, string_to_bytes(args.appVersion))
			if not args.icon is None:
				installparams += encodetlv(BOLOS_TAG_ICON, bytes(args.icon))
			if len(path) > 0:
				installparams += encodetlv(BOLOS_TAG_DERIVEPATH, path)

			# append install parameters to the loaded file
			param_start = printer.maxAddr()+(PAGE_ALIGNMENT-(args.dataSize%PAGE_ALIGNMENT))%PAGE_ALIGNMENT
			# only append install param section when not an upgrade as it has already been computed in the encrypted and signed chunk
			printer.addArea(param_start, installparams)
			paramsSize = len(installparams)
		else:
			paramsSize = args.installparamsSize
			# split code and install params in the code
			code_length -= args.installparamsSize
		# create app
		#ensure the boot address is an offset
		if args.bootAddr > printer.minAddr():
			args.bootAddr -= printer.minAddr()
		loader.createApp(code_length, args.dataSize, paramsSize, args.appFlags, args.bootAddr|1)
	elif (args.params):
		paramsSectionContent = []
		if not args.icon is None:
			paramsSectionContent = args.icon
		#take care of aligning the parameters sections to avoid possible invalid dereference of aligned words in the program nvram.
		#also use the default MPU alignment
		param_start = printer.minAddr()-len(paramsSectionContent)-(DEFAULT_ALIGNMENT-(len(paramsSectionContent)%DEFAULT_ALIGNMENT))
		printer.addArea(param_start, paramsSectionContent)
		# account for added regions (install parameters, icon ...)
		appLength = printer.maxAddr() - printer.minAddr()
		loader.createAppNoInstallParams(args.appFlags, appLength, args.appName, None, path, 0, len(paramsSectionContent), args.appVersion)
	else:
		# account for added regions (install parameters, icon ...)
		appLength = printer.maxAddr() - printer.minAddr()
		loader.createAppNoInstallParams(args.appFlags, appLength, args.appName, args.icon, path, None, None, args.appVersion)


	hash = loader.load(0x0, 0xF0, printer)

	print("Application full hash : " + hash)

	if (signature == None and args.signApp):
		masterPrivate = PrivateKey(bytes(bytearray.fromhex(args.signPrivateKey)))
		signature = masterPrivate.ecdsa_serialize(masterPrivate.ecdsa_sign(bytes(binascii.unhexlify(hash)), raw=True))
		print("Application signature: " + str(binascii.hexlify(signature)))

	if (args.tlv):
		loader.commit(signature)
	else:
		loader.run(args.bootAddr-printer.minAddr(), signature)
