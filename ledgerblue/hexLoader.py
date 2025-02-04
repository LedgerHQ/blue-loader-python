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

from Cryptodome.Cipher import AES
import sys
import struct
import hashlib
import binascii
from .ecWrapper import PrivateKey
from ecpy.curves import Curve
import os

LOAD_SEGMENT_CHUNK_HEADER_LENGTH = 3
MIN_PADDING_LENGTH = 1
SCP_MAC_LENGTH = 0xE

BOLOS_TAG_APPNAME = 0x01
BOLOS_TAG_APPVERSION = 0x02
BOLOS_TAG_ICON = 0x03
BOLOS_TAG_DERIVEPATH = 0x04
BOLOS_TAG_DATASIZE = 0x05
BOLOS_TAG_DEPENDENCY = 0x06


def string_to_bytes(x):
    return bytes(x, "ascii")


def encodelv(v):
    l = len(v)
    s = b""
    if l < 128:
        s += struct.pack(">B", l)
    elif l < 256:
        s += struct.pack(">B", 0x81)
        s += struct.pack(">B", l)
    elif l < 65536:
        s += struct.pack(">B", 0x82)
        s += struct.pack(">H", l)
    else:
        raise Exception("Unimplemented LV encoding")
    s += v
    return s


def encodetlv(t, v):
    l = len(v)
    s = struct.pack(">B", t)
    if l < 128:
        s += struct.pack(">B", l)
    elif l < 256:
        s += struct.pack(">B", 0x81)
        s += struct.pack(">B", l)
    elif l < 65536:
        s += struct.pack(">B", 0x82)
        s += struct.pack(">H", l)
    else:
        raise Exception("Unimplemented TLV encoding")
    s += v
    return s


def str2bool(v):
    if v is not None:
        return v.lower() in ("yes", "true", "t", "1")
    return False


SCP_DEBUG = str2bool(os.getenv("SCP_DEBUG"))


class HexLoader:
    def scp_derive_key(self, ecdh_secret, keyindex):
        if self.scpv3:
            mac_block = b"\x01" * 16
            cipher = AES.new(ecdh_secret, AES.MODE_ECB)
            mac_key = cipher.encrypt(mac_block)
            enc_block = b"\x02" * 16
            cipher = AES.new(ecdh_secret, AES.MODE_ECB)
            enc_key = cipher.encrypt(enc_block)
            return mac_key + enc_key
        retry = 0
        # di = sha256(i || retrycounter || ecdh secret)
        while True:
            sha256 = hashlib.new("sha256")
            sha256.update(struct.pack(">IB", keyindex, retry))
            sha256.update(ecdh_secret)

            # compare di with order
            CURVE_SECP256K1 = Curve.get_curve("secp256k1")
            if int.from_bytes(sha256.digest(), "big") < CURVE_SECP256K1.order:
                break
            # regenerate a new di satisfying order upper bound
            retry += 1

        # Pi = di*G
        privkey = PrivateKey(bytes(sha256.digest()))
        pubkey = bytearray(privkey.pubkey.serialize(compressed=False))
        # ki = sha256(Pi)
        sha256 = hashlib.new("sha256")
        sha256.update(pubkey)
        # print ("Key " + str (keyindex) + ": " + sha256.hexdigest())
        return sha256.digest()

    def __init__(
        self,
        card,
        cla=0xF0,
        secure=False,
        mutauth_result=None,
        relative=True,
        cleardata_block_len=None,
        scpv3=False,
    ):
        self.card = card
        self.cla = cla
        self.secure = secure
        self.createappParams = None
        self.createpackParams = None
        self.scpv3 = scpv3

        # legacy unsecure SCP (pre nanos-1.4, pre blue-2.1)
        self.max_mtu = 0xFE
        if not self.card is None:
            self.max_mtu = min(self.max_mtu, self.card.apduMaxDataSize())
        self.scpVersion = 2
        self.key = mutauth_result
        self.iv = b"\x00" * 16
        self.relative = relative

        # store the aligned block len to be transported if requested
        self.cleardata_block_len = cleardata_block_len
        if not (self.cleardata_block_len is None):
            if not self.card is None:
                self.cleardata_block_len = min(
                    self.cleardata_block_len, self.card.apduMaxDataSize()
                )

        if scpv3 == True:
            self.scp_enc_key = self.scp_derive_key(mutauth_result, 0)
            self.scpVersion = 3
            self.max_mtu = 0xFE
            if not self.card is None:
                self.max_mtu = min(self.max_mtu, self.card.apduMaxDataSize() & 0xF0)
            return

        # try:
        if type(mutauth_result) is dict and "ecdh_secret" in mutauth_result:
            self.scp_enc_key = self.scp_derive_key(mutauth_result["ecdh_secret"], 0)[
                0:16
            ]
            self.scp_enc_iv = b"\x00" * 16
            self.scp_mac_key = self.scp_derive_key(mutauth_result["ecdh_secret"], 1)[
                0:16
            ]
            self.scp_mac_iv = b"\x00" * 16
            self.scpVersion = 3
            self.max_mtu = 0xFE
            if not self.card is None:
                self.max_mtu = min(self.max_mtu, self.card.apduMaxDataSize() & 0xF0)

    def crc16(self, data):
        TABLE_CRC16_CCITT = [
            0x0000,
            0x1021,
            0x2042,
            0x3063,
            0x4084,
            0x50A5,
            0x60C6,
            0x70E7,
            0x8108,
            0x9129,
            0xA14A,
            0xB16B,
            0xC18C,
            0xD1AD,
            0xE1CE,
            0xF1EF,
            0x1231,
            0x0210,
            0x3273,
            0x2252,
            0x52B5,
            0x4294,
            0x72F7,
            0x62D6,
            0x9339,
            0x8318,
            0xB37B,
            0xA35A,
            0xD3BD,
            0xC39C,
            0xF3FF,
            0xE3DE,
            0x2462,
            0x3443,
            0x0420,
            0x1401,
            0x64E6,
            0x74C7,
            0x44A4,
            0x5485,
            0xA56A,
            0xB54B,
            0x8528,
            0x9509,
            0xE5EE,
            0xF5CF,
            0xC5AC,
            0xD58D,
            0x3653,
            0x2672,
            0x1611,
            0x0630,
            0x76D7,
            0x66F6,
            0x5695,
            0x46B4,
            0xB75B,
            0xA77A,
            0x9719,
            0x8738,
            0xF7DF,
            0xE7FE,
            0xD79D,
            0xC7BC,
            0x48C4,
            0x58E5,
            0x6886,
            0x78A7,
            0x0840,
            0x1861,
            0x2802,
            0x3823,
            0xC9CC,
            0xD9ED,
            0xE98E,
            0xF9AF,
            0x8948,
            0x9969,
            0xA90A,
            0xB92B,
            0x5AF5,
            0x4AD4,
            0x7AB7,
            0x6A96,
            0x1A71,
            0x0A50,
            0x3A33,
            0x2A12,
            0xDBFD,
            0xCBDC,
            0xFBBF,
            0xEB9E,
            0x9B79,
            0x8B58,
            0xBB3B,
            0xAB1A,
            0x6CA6,
            0x7C87,
            0x4CE4,
            0x5CC5,
            0x2C22,
            0x3C03,
            0x0C60,
            0x1C41,
            0xEDAE,
            0xFD8F,
            0xCDEC,
            0xDDCD,
            0xAD2A,
            0xBD0B,
            0x8D68,
            0x9D49,
            0x7E97,
            0x6EB6,
            0x5ED5,
            0x4EF4,
            0x3E13,
            0x2E32,
            0x1E51,
            0x0E70,
            0xFF9F,
            0xEFBE,
            0xDFDD,
            0xCFFC,
            0xBF1B,
            0xAF3A,
            0x9F59,
            0x8F78,
            0x9188,
            0x81A9,
            0xB1CA,
            0xA1EB,
            0xD10C,
            0xC12D,
            0xF14E,
            0xE16F,
            0x1080,
            0x00A1,
            0x30C2,
            0x20E3,
            0x5004,
            0x4025,
            0x7046,
            0x6067,
            0x83B9,
            0x9398,
            0xA3FB,
            0xB3DA,
            0xC33D,
            0xD31C,
            0xE37F,
            0xF35E,
            0x02B1,
            0x1290,
            0x22F3,
            0x32D2,
            0x4235,
            0x5214,
            0x6277,
            0x7256,
            0xB5EA,
            0xA5CB,
            0x95A8,
            0x8589,
            0xF56E,
            0xE54F,
            0xD52C,
            0xC50D,
            0x34E2,
            0x24C3,
            0x14A0,
            0x0481,
            0x7466,
            0x6447,
            0x5424,
            0x4405,
            0xA7DB,
            0xB7FA,
            0x8799,
            0x97B8,
            0xE75F,
            0xF77E,
            0xC71D,
            0xD73C,
            0x26D3,
            0x36F2,
            0x0691,
            0x16B0,
            0x6657,
            0x7676,
            0x4615,
            0x5634,
            0xD94C,
            0xC96D,
            0xF90E,
            0xE92F,
            0x99C8,
            0x89E9,
            0xB98A,
            0xA9AB,
            0x5844,
            0x4865,
            0x7806,
            0x6827,
            0x18C0,
            0x08E1,
            0x3882,
            0x28A3,
            0xCB7D,
            0xDB5C,
            0xEB3F,
            0xFB1E,
            0x8BF9,
            0x9BD8,
            0xABBB,
            0xBB9A,
            0x4A75,
            0x5A54,
            0x6A37,
            0x7A16,
            0x0AF1,
            0x1AD0,
            0x2AB3,
            0x3A92,
            0xFD2E,
            0xED0F,
            0xDD6C,
            0xCD4D,
            0xBDAA,
            0xAD8B,
            0x9DE8,
            0x8DC9,
            0x7C26,
            0x6C07,
            0x5C64,
            0x4C45,
            0x3CA2,
            0x2C83,
            0x1CE0,
            0x0CC1,
            0xEF1F,
            0xFF3E,
            0xCF5D,
            0xDF7C,
            0xAF9B,
            0xBFBA,
            0x8FD9,
            0x9FF8,
            0x6E17,
            0x7E36,
            0x4E55,
            0x5E74,
            0x2E93,
            0x3EB2,
            0x0ED1,
            0x1EF0,
        ]
        crc = 0xFFFF
        for i in range(0, len(data)):
            b = data[i] & 0xFF
            b = (b ^ ((crc >> 8) & 0xFF)) & 0xFF
            crc = (TABLE_CRC16_CCITT[b] ^ (crc << 8)) & 0xFFFF
        return crc

    def exchange(self, cla, ins, p1, p2, data):
        # wrap
        data = self.scpWrap(data)
        apdu = bytearray([cla, ins, p1, p2, len(data)]) + bytearray(data)
        if self.card == None:
            print("%s" % binascii.hexlify(apdu))
        else:
            # unwrap after exchanged
            return self.scpUnwrap(bytes(self.card.exchange(apdu)))

    def scpWrap(self, data):
        if not self.secure or data is None or len(data) == 0:
            return data
        if self.scpv3 == True:
            cipher = AES.new(self.scp_enc_key, mode=AES.MODE_SIV)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encryptedData = tag + ciphertext
            return encryptedData

        if self.scpVersion == 3:
            if SCP_DEBUG:
                print(binascii.hexlify(data))
            # ENC
            paddedData = data + b"\x80"
            while (len(paddedData) % 16) != 0:
                paddedData += b"\x00"
            if SCP_DEBUG:
                print(binascii.hexlify(paddedData))
            cipher = AES.new(self.scp_enc_key, AES.MODE_CBC, self.scp_enc_iv)
            encryptedData = cipher.encrypt(paddedData)
            self.scp_enc_iv = encryptedData[-16:]
            if SCP_DEBUG:
                print(binascii.hexlify(encryptedData))
            # MAC
            cipher = AES.new(self.scp_mac_key, AES.MODE_CBC, self.scp_mac_iv)
            macData = cipher.encrypt(encryptedData)
            self.scp_mac_iv = macData[-16:]

            # only append part of the mac
            encryptedData += self.scp_mac_iv[-SCP_MAC_LENGTH:]
            if SCP_DEBUG:
                print(binascii.hexlify(encryptedData))
        else:
            paddedData = data + b"\x80"
            while (len(paddedData) % 16) != 0:
                paddedData += b"\x00"
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            if SCP_DEBUG:
                print("wrap_old: " + binascii.hexlify(paddedData))
            encryptedData = cipher.encrypt(paddedData)
            self.iv = encryptedData[-16:]

        # print (">>")
        return encryptedData

    def scpUnwrap(self, data):
        if not self.secure or data is None or len(data) == 0 or len(data) == 2:
            return data
        if self.scpv3 == True:
            cipher = AES.new(self.scp_enc_key, mode=AES.MODE_SIV)
            tag = data[:16]
            decryptedData = cipher.decrypt_and_verify(data[16:], tag)
            return decryptedData

        padding_char = 0x80

        if self.scpVersion == 3:
            if SCP_DEBUG:
                print(binascii.hexlify(data))
            # MAC
            cipher = AES.new(self.scp_mac_key, AES.MODE_CBC, self.scp_mac_iv)
            macData = cipher.encrypt(bytes(data[0:-SCP_MAC_LENGTH]))
            self.scp_mac_iv = macData[-16:]
            if self.scp_mac_iv[-SCP_MAC_LENGTH:] != data[-SCP_MAC_LENGTH:]:
                raise BaseException("Invalid SCP MAC")
            # consume mac
            data = data[0:-SCP_MAC_LENGTH]

            if SCP_DEBUG:
                print(binascii.hexlify(data))
            # ENC
            cipher = AES.new(self.scp_enc_key, AES.MODE_CBC, self.scp_enc_iv)
            self.scp_enc_iv = bytes(data[-16:])
            data = cipher.decrypt(bytes(data))
            l = len(data) - 1
            while data[l] != padding_char:
                l -= 1
                if l == -1:
                    raise BaseException("Invalid SCP ENC padding")
            data = data[0:l]
            decryptedData = data

            if SCP_DEBUG:
                print(binascii.hexlify(data))
        else:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decryptedData = cipher.decrypt(data)
            if SCP_DEBUG:
                print("unwrap_old: " + binascii.hexlify(decryptedData))
            l = len(decryptedData) - 1
            while decryptedData[l] != padding_char:
                l -= 1
                if l == -1:
                    raise BaseException("Invalid SCP ENC padding")
            decryptedData = decryptedData[0:l]
            self.iv = data[-16:]

        # print ("<<")
        return decryptedData

    def selectSegment(self, baseAddress):
        data = b"\x05" + struct.pack(">I", baseAddress)
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def loadSegmentChunk(self, offset, chunk):
        data = b"\x06" + struct.pack(">H", offset) + chunk
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def flushSegment(self):
        data = b"\x07"
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def crcSegment(self, offsetSegment, lengthSegment, crcExpected):
        data = (
            b"\x08"
            + struct.pack(">H", offsetSegment)
            + struct.pack(">I", lengthSegment)
            + struct.pack(">H", crcExpected)
        )
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def validateTargetId(self, targetId):
        data = struct.pack(">I", targetId)
        self.exchange(self.cla, 0x04, 0x00, 0x00, data)

    def boot(self, bootadr, signature=None):
        # Force jump into Thumb mode
        bootadr |= 1
        data = b"\x09" + struct.pack(">I", bootadr)
        if signature != None:
            data += struct.pack(">B", len(signature)) + signature
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def commit(self, signature=None):
        data = b"\x09"
        if signature != None:
            data += struct.pack(">B", len(signature)) + signature
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def createAppNoInstallParams(
        self,
        appflags,
        applength,
        appname,
        icon=None,
        path=None,
        iconOffset=None,
        iconSize=None,
        appversion=None,
    ):
        data = (
            b"\x0b"
            + struct.pack(">I", applength)
            + struct.pack(">I", appflags)
            + struct.pack(">B", len(appname))
            + appname
        )
        if iconOffset is None:
            if not (icon is None):
                data += struct.pack(">B", len(icon)) + icon
            else:
                data += b"\x00"

        if not (path is None):
            data += struct.pack(">B", len(path)) + path
        else:
            data += b"\x00"

        if not iconOffset is None:
            data += struct.pack(">I", iconOffset) + struct.pack(">H", iconSize)

        if not appversion is None:
            data += struct.pack(">B", len(appversion)) + appversion

        # in previous version, appparams are not part of the application hash yet
        self.createappParams = None  # data[1:]
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def createApp(
        self,
        code_length,
        api_level=0,
        data_length=0,
        install_params_length=0,
        flags=0,
        bootOffset=1,
    ):
        # keep the create app parameters to be included in the load app hash
        # maintain compatibility with SDKs not handling API level
        if api_level != -1:
            self.createappParams = struct.pack(
                ">BIIIII",
                api_level,
                code_length,
                data_length,
                install_params_length,
                flags,
                bootOffset,
            )
        else:
            self.createappParams = struct.pack(
                ">IIIII",
                code_length,
                data_length,
                install_params_length,
                flags,
                bootOffset,
            )
        data = b"\x0b" + self.createappParams
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def deleteApp(self, appname):
        data = b"\x0c" + struct.pack(">B", len(appname)) + appname
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def deleteAppByHash(self, appfullhash):
        if len(appfullhash) != 32:
            raise BaseException("Invalid hash format, sha256 expected")
        data = b"\x15" + appfullhash
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def createPack(self, language, code_length):
        # keep the create pack parameters to be included in the load app hash
        self.createpackParams = struct.pack(">I", code_length)
        data = self.createpackParams
        self.language = language
        self.exchange(self.cla, 0x30, language, 0x00, data)

    def loadPackSegmentChunk(self, offset, chunk):
        data = struct.pack(">I", offset) + chunk
        # print(f"Inside loadPackSegmentChunk, offset={offset}, len(chunk)={len(chunk)}")
        self.exchange(self.cla, 0x31, self.language, 0x00, data)

    def commitPack(self, signature=None):
        if signature != None:
            data = struct.pack(">B", len(signature)) + signature
        else:
            data = b""
        self.exchange(self.cla, 0x32, self.language, 0x00, data)

    def deletePack(self, language):
        self.language = language
        self.exchange(self.cla, 0x33, language, 0x00, b"")

    def listPacks(self, restart=True):
        language_id_name = ["English", "Français", "Español"]
        if restart:
            response = self.exchange(self.cla, 0x34, 0x00, 0x00, b"")
        else:
            response = self.exchange(self.cla, 0x34, 0x01, 0x00, b"")
        result = []
        offset = 0
        if len(response) > 0:
            if response[0] != 0x01:
                raise Exception(f"Unsupported version format {response[0]}!")
            offset += 1
            while offset != len(response):
                item = {}
                # skip the current entry's size
                offset += 1
                # skip len of Language ID
                offset += 1
                language_id = response[offset]
                if language_id >= len(language_id_name):
                    language_name = "Unknown"
                else:
                    language_name = language_id_name[language_id]
                item["Language ID"] = f"{language_id} ({language_name})"
                offset += 1
                offset += 1
                item["size"] = (
                    (response[offset] << 24)
                    | (response[offset + 1] << 16)
                    | (response[offset + 2] << 8)
                    | response[offset + 3]
                )
                offset += 4
                item["Version"] = response[
                    offset + 1 : offset + 1 + response[offset]
                ].decode("utf-8")
                offset += 1 + response[offset]
                result.append(item)
        return result

    def getVersion(self):
        data = b"\x10"
        response = self.exchange(self.cla, 0x00, 0x00, 0x00, data)
        result = {}
        offset = 0
        result["targetId"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        result["osVersion"] = response[
            offset + 1 : offset + 1 + response[offset]
        ].decode("utf-8")
        offset += 1 + response[offset]
        offset += 1
        result["flags"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        result["mcuVersion"] = response[
            offset + 1 : offset + 1 + response[offset] - 1
        ].decode("utf-8")
        offset += 1 + response[offset]
        if offset < len(response):
            result["mcuHash"] = response[offset : offset + 32]
        return result

    def listApp(self, restart=True):
        if self.secure:
            if restart:
                data = b"\x0e"
            else:
                data = b"\x0f"
            response = self.exchange(self.cla, 0x00, 0x00, 0x00, data)
        else:
            if restart:
                response = self.exchange(self.cla, 0xDE, 0x00, 0x00, b"")
            else:
                response = self.exchange(self.cla, 0xDF, 0x00, 0x00, b"")

        # print binascii.hexlify(response[0])
        result = []
        offset = 0
        if len(response) > 0:
            if response[0] != 0x01:
                # support old format
                while offset != len(response):
                    item = {}
                    offset += 1
                    item["name"] = response[
                        offset + 1 : offset + 1 + response[offset]
                    ].decode("utf-8")
                    offset += 1 + response[offset]
                    item["flags"] = (
                        (response[offset] << 24)
                        | (response[offset + 1] << 16)
                        | (response[offset + 2] << 8)
                        | response[offset + 3]
                    )
                    offset += 4
                    item["hash"] = response[offset : offset + 32]
                    offset += 32
                    result.append(item)
            else:
                offset += 1
                while offset != len(response):
                    item = {}
                    # skip the current entry's size
                    offset += 1
                    item["flags"] = (
                        (response[offset] << 24)
                        | (response[offset + 1] << 16)
                        | (response[offset + 2] << 8)
                        | response[offset + 3]
                    )
                    offset += 4
                    item["hash_code_data"] = response[offset : offset + 32]
                    offset += 32
                    item["hash"] = response[offset : offset + 32]
                    offset += 32
                    item["name"] = response[
                        offset + 1 : offset + 1 + response[offset]
                    ].decode("utf-8")
                    offset += 1 + response[offset]
                    result.append(item)
        return result

    def getMemInfo(self):
        response = self.exchange(self.cla, 0x00, 0x00, 0x00, b"\x11")
        item = {}
        offset = 0
        item["systemSize"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        item["applicationsSize"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        item["freeSize"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        item["usedAppSlots"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        offset += 4
        item["totalAppSlots"] = (
            (response[offset] << 24)
            | (response[offset + 1] << 16)
            | (response[offset + 2] << 8)
            | response[offset + 3]
        )
        return item

    def load(
        self,
        erase_u8,
        max_length_per_apdu,
        hexFile,
        reverse=False,
        doCRC=True,
        targetId=None,
        targetVersion=None,
    ):
        if max_length_per_apdu > self.max_mtu:
            max_length_per_apdu = self.max_mtu
        initialAddress = 0
        if self.relative:
            initialAddress = hexFile.minAddr()
        sha256 = hashlib.new("sha256")
        # stat by hashing the create app params to ensure complete app signature
        if targetId != None and (targetId & 0xF) > 3:
            if targetVersion == None:
                print("Target version is not set, application hash will not match!")
                targetVersion = ""
            # encore targetId U4LE, and version string bytes
            if not self.createpackParams:
                sha256.update(
                    struct.pack(">I", targetId) + string_to_bytes(targetVersion)
                )
        if self.createappParams:
            sha256.update(self.createappParams)
        areas = hexFile.getAreas()
        if reverse:
            areas = reversed(hexFile.getAreas())
        for area in areas:
            startAddress = area.getStart() - initialAddress
            data = area.getData()
            if not self.createpackParams:
                self.selectSegment(startAddress)
            if len(data) == 0:
                continue
            if len(data) > 0x10000:
                raise Exception("Invalid data size for loader")
            crc = self.crc16(bytearray(data))
            offset = 0
            length = len(data)
            if reverse:
                offset = length
            while length > 0:
                if (
                    length
                    > max_length_per_apdu
                    - LOAD_SEGMENT_CHUNK_HEADER_LENGTH
                    - MIN_PADDING_LENGTH
                    - SCP_MAC_LENGTH
                ):
                    chunkLen = (
                        max_length_per_apdu
                        - LOAD_SEGMENT_CHUNK_HEADER_LENGTH
                        - MIN_PADDING_LENGTH
                        - SCP_MAC_LENGTH
                    )
                    if (chunkLen % 16) != 0:
                        chunkLen -= chunkLen % 16
                else:
                    chunkLen = length

                if self.cleardata_block_len and chunkLen % self.cleardata_block_len:
                    if chunkLen < self.cleardata_block_len:
                        raise Exception(
                            "Cannot transport not block aligned data with fixed block len"
                        )
                    chunkLen -= chunkLen % self.cleardata_block_len
                # pad with 00's when not complete block and performing NENC
                if reverse:
                    chunk = data[offset - chunkLen : offset]
                    if self.createpackParams:
                        self.loadPackSegmentChunk(offset - chunkLen, bytes(chunk))
                    else:
                        self.loadSegmentChunk(offset - chunkLen, bytes(chunk))
                else:
                    chunk = data[offset : offset + chunkLen]
                    sha256.update(chunk)
                    if self.createpackParams:
                        self.loadPackSegmentChunk(offset, bytes(chunk))
                    else:
                        self.loadSegmentChunk(offset, bytes(chunk))
                if reverse:
                    offset -= chunkLen
                else:
                    offset += chunkLen
                length -= chunkLen
            if not self.createpackParams:
                self.flushSegment()
            if doCRC:
                self.crcSegment(0, len(data), crc)
        return sha256.hexdigest()

    def run(self, bootoffset=1, signature=None):
        self.boot(bootoffset, signature)

    def resetCustomCA(self):
        data = b"\x13"
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def setupCustomCA(self, name, public):
        data = (
            b"\x12"
            + struct.pack(">B", len(name))
            + name.encode()
            + struct.pack(">B", len(public))
            + public
        )
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def runApp(self, name):
        data = name
        self.exchange(self.cla, 0xD8, 0x00, 0x00, data)

    def recoverConfirmID(self, tag, ciphertext):
        data = b"\xd4"
        data += struct.pack(">B", len(tag + ciphertext)) + tag + ciphertext
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverSetCA(self, name, key):
        data = (
            b"\xd2"
            + struct.pack(">B", len(name))
            + name.encode()
            + struct.pack(">B", len(key))
            + key
        )
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverDeleteCA(self, name, key):
        data = (
            b"\xd3"
            + struct.pack(">B", len(name))
            + name.encode()
            + struct.pack(">B", len(key))
            + key
        )
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverValidateCertificate(self, version, role, name, key, sign, last=False):
        if last == True:
            p1 = b"\x80"
        else:
            p1 = b"\x00"
        data = b"\xd5" + p1
        data += version
        data += role
        data += struct.pack(">B", len(name)) + name.encode()
        data += struct.pack(">B", len(key)) + key + struct.pack(">B", len(sign)) + sign
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverMutualAuth(self):
        data = b"\xd6"
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverValidateHash(self, tag, ciphertext):
        data = b"\xd7" + struct.pack(">B", 48) + tag + ciphertext
        return self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverGetShare(self, value="shares"):
        if value == "commitments":
            p1 = b"\x01"
        elif value == "point":
            p1 = b"\x10"
        else:
            p1 = b"\x00"
        data = b"\xd8" + p1
        return self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverValidateCommit(self, p1, commits, tag=None, ciphertext=None):
        data = b"\xd9"
        if p1 == 0x2:
            data += b"\x02" + struct.pack(">B", len(commits)) + commits
        elif p1 == 0x3:
            data += b"\x03" + struct.pack(">B", 48) + tag + ciphertext
        elif p1 == 0x4:
            data += b"\x04" + struct.pack(">B", len(commits)) + commits
        else:
            data += b"\x00"
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverRestoreSeed(self, tag, ciphertext, words_number):
        data = b"\xda"
        if words_number == 12:
            p1 = b"\x0c"
        elif words_number == 18:
            p1 = b"\x12"
        else:
            p1 = b"\x00"
        data += p1 + struct.pack(">B", len(tag + ciphertext)) + tag + ciphertext
        self.exchange(self.cla, 0x00, 0x00, 0x00, data)

    def recoverDeleteBackup(self, tag, ciphertext):
        data = b"\xdb" + struct.pack(">B", len(tag + ciphertext)) + tag + ciphertext
        return self.exchange(self.cla, 0x00, 0x00, 0x00, data)
