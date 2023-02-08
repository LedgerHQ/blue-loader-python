"""
*******************************************************************************
*   Ledger Blue
*   (c) 2022 Ledger
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

# NDEF URI ID STRINGS

class UnknownUriHeader(Exception):
	pass

URI_ID_DICT = dict([
	(0, ""),
	(0x01, "http://www."),
	(0x02, "https://www."),
	(0x03, "http://"),
	(0x04, "https://"),
	(0x05, "tel:"),
	(0x06, "mailto:"),
	(0x07, "ftp://anonymous:anonymous@"),
	(0x08, "ftp://ftp."),
	(0x09, "ftps://"),
	(0x0A, "sftp://"),
	(0x0B, "smb://"),
	(0x0C, "nfs://"),
	(0x0D, "ftp://"),
	(0x0E, "dav://"),
	(0x0F, "news:"),
	(0x10, "telnet://"),
	(0x11, "imap:"),
	(0x12, "rtsp://"),
	(0x13, "urn:"),
	(0x14, "pop:"),
	(0x15, "sip:"),
	(0x16, "sips:"),
	(0x17, "tftp:"),
	(0x18, "btspp://"),
	(0x19, "btl2cap://"),
	(0x1A, "btgoep://"),
	(0x1B, "tcpobex://"),
	(0x1C, "irdaobex://"),
	(0x1D, "file://"),
	(0x1E, "urn:epc:id:"),
	(0x1F, "urn:epc:tag"),
	(0x20, "urn:epc:pat:"),
	(0x21, "urn:epc:raw:"),
	(0x22, "urn:epc:"),
	(0x23, "urn:nfc:")
])

def get_argparser():
	parser = argparse.ArgumentParser(description="""
.. warning::

   Using this script undermines the security of the device. Caveat emptor.
""")
	parser.add_argument("--apdu", help="Display APDU log", action='store_true')
	parser.add_argument("--erase", help="Erase tag content", action='store_true')
	parser.add_argument("--text", help="String to program in nfc tag")
	parser.add_argument("--uri", help="Set uri to program in nfc tag")
	parser.add_argument("--info", help="Set uri information to program innfc tag")
	parser.add_argument("--activate", help="Activate NFC, only available in FTM", action='store_true')
	return parser

if __name__ == '__main__':
	from .comm import getDongle

	args = get_argparser().parse_args()

	dongle = getDongle(args.apdu)

	if args.erase:
		apdu = bytearray([0xE0, 0x18, 0x00, 0x00, 0x00])
	if args.text:
		p1 = 0x01
		uriIdKey = 0xFF #not applicable
		text_length = len(args.text)
		sub_text_length = 0
		apdu = bytearray([0xE0, 0x18, p1, uriIdKey, 2+len(args.text)])
		apdu.append(text_length)
		for c in args.text:
			apdu.append(ord(c))
		apdu.append(sub_text_length)
	if args.uri:
		uriIdKey = None
		uriIdValue = None
		p1 = 0x02
		for k, v in URI_ID_DICT.items():
			if v in args.uri:
				if v != "":
					uriIdKey = k
					uriIdValue = v
					break
		if uriIdKey:
			print(uriIdKey, uriIdValue)
		else:
			raise UnknownUriHeader
		text = args.uri.replace(v, "")
		text_length = len(text)
		sub_text_length = 0
		apdu = bytearray([0xE0, 0x18, p1, k, 2+len(text)])
		apdu.append(text_length)
		for c in text:
			apdu.append(ord(c))
		if args.info:
			sub_text_length = len(args.info)
			apdu.append(sub_text_length)
			apdu[4] = apdu[4] + sub_text_length
			for c in args.info:
				apdu.append(ord(c))
		else:
			apdu.append(sub_text_length)
	if args.activate:
		apdu = bytearray([0xE0, 0x18, 0x03, 0x00, 0x00])
	dongle.exchange(apdu)
	dongle.close()
