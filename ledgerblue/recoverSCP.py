from Cryptodome.Cipher import AES
from ledgerblue.ecWrapper import PrivateKey
from ecpy.curves import Curve
import hashlib
import struct


def decrypt_certificate(encrypted_certificate, key):
    tag = encrypted_certificate[:16]
    ciphertext = encrypted_certificate[16:]
    aes_siv = AES.new(key, mode=AES.MODE_SIV)
    certificate = aes_siv.decrypt_and_verify(ciphertext, tag)
    return certificate


def extract_from_certificate(certificate):
    offset = 1
    certificate_header = certificate[offset: offset + certificate[offset - 1]]
    offset += certificate[offset - 1] + 1
    certificate_public_key = certificate[offset: offset + certificate[offset - 1]]
    offset += certificate[offset - 1] + 1
    certificate_signature_array = certificate[offset: offset + certificate[offset - 1]]
    return certificate_header, certificate_public_key, certificate_signature_array


def scp_derive_key(ecdh_secret, keyindex, scpv3=False):
    if scpv3:
        mac_block = b'\x01' * 16
        cipher = AES.new(ecdh_secret, AES.MODE_ECB)
        mac_key = cipher.encrypt(mac_block)
        enc_block = b'\x02' * 16
        cipher = AES.new(ecdh_secret, AES.MODE_ECB)
        enc_key = cipher.encrypt(enc_block)
        return mac_key + enc_key
    retry = 0
    # di = sha256(i || retrycounter || ecdh secret)
    while True:
        sha256 = hashlib.new('sha256')
        sha256.update(struct.pack(">IB", keyindex, retry))
        sha256.update(ecdh_secret)

        # compare di with order
        CURVE_SECP256K1 = Curve.get_curve('secp256k1')
        if int.from_bytes(sha256.digest(), 'big') < CURVE_SECP256K1.order:
            break
        # regenerate a new di satisfying order upper bound
        retry += 1

    # Pi = di*G
    privkey = PrivateKey(bytes(sha256.digest()))
    pubkey = bytearray(privkey.pubkey.serialize(compressed=False))
    # ki = sha256(Pi)
    sha256 = hashlib.new('sha256')
    sha256.update(pubkey)
    return sha256.digest()

