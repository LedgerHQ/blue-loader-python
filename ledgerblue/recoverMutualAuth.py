from ledgerblue.ecWrapper import PublicKey, PrivateKey
from ledgerblue.hexLoader import HexLoader
from ledgerblue.recoverSCP import scp_derive_key, extract_from_certificate, decrypt_certificate
import binascii
import struct
import os

CERT_ROLE_SIGNER = 0x1
CERT_ROLE_SIGNER_EPHEMERAL = 0x11
CERT_ROLE_DEVICE = 0x2
CERT_ROLE_DEVICE_EPHEMERAL = 0x12
CERT_ROLE_RECOVER_ORCHESTRATOR = 0x05
CERT_ROLE_RECOVER_ORCHESTRATOR_EPHEMERAL = 0x15

CERT_ROLE_RECOVER_PROVIDER = 0x4
CERT_ROLE_RECOVER_PROVIDER_EPHEMERAL = 0x14
CERT_FORMAT_VERSION = 0x01


def SCPv3(dongle, issuer_public_key, target_id, ca_private_key=None, signer_private_key=None,
          user_mode=False):
    if not user_mode:
        ca_sk = PrivateKey(bytes(ca_private_key))
    target = bytearray(struct.pack('>I', target_id))
    scpv3 = 0x02

    apdu = bytearray([0xe0, 0x04, scpv3, 0x00]) + bytearray([len(target)]) + target
    dongle.exchange(apdu)

    # Initialize authentication
    nonce = os.urandom(8)
    apdu = bytearray([0xe0, 0x50, 0x00, 0x00]) + bytearray([len(nonce)]) + nonce

    auth_info = dongle.exchange(apdu)
    device_nonce = auth_info[4:12]

    if user_mode:
        role = CERT_ROLE_SIGNER
        ephemeral_role = CERT_ROLE_SIGNER_EPHEMERAL
    else:
        role = CERT_ROLE_RECOVER_ORCHESTRATOR
        ephemeral_role = CERT_ROLE_RECOVER_ORCHESTRATOR_EPHEMERAL

    # Validate signer static certificate
    certificate_id = 0x00
    if signer_private_key is not None:
        signer_sk = PrivateKey(bytes(signer_private_key))
        signer_pk = bytearray(signer_sk.pubkey.serialize(compressed=False))
        data_to_sign = bytes(bytearray([role]) + signer_pk)
        if user_mode:
            signature = signer_sk.ecdsa_sign(bytes(data_to_sign))
            signature = signer_sk.ecdsa_serialize(signature)
        else:
            signature = ca_sk.ecdsa_sign(bytes(data_to_sign))
            signature = ca_sk.ecdsa_serialize(signature)
            certificate_id = 0x01
        certificate = bytearray([len(signer_pk)]) + signer_pk + bytearray([len(signature)]) + signature
        apdu = bytearray([0xE0, 0x51, 0x00, certificate_id]) + bytearray([len(certificate)]) + certificate

        dongle.exchange(apdu)

    # Validate signer ephemeral certificate
    ephemeral_private = PrivateKey()
    ephemeral_public = bytearray(ephemeral_private.pubkey.serialize(compressed=False))
    data_to_sign = bytes(bytearray([ephemeral_role]) + nonce + device_nonce + ephemeral_public)
    signature = signer_sk.ecdsa_sign(bytes(data_to_sign))
    signature = signer_sk.ecdsa_serialize(signature)
    certificate = bytearray([len(ephemeral_public)]) + ephemeral_public + bytearray([len(signature)]) + signature
    apdu = bytearray([0xE0, 0x51, 0x80, certificate_id]) + bytearray([len(certificate)]) + certificate

    dongle.exchange(apdu)

    # Get device certificates
    issuer_pk = PublicKey(bytes(issuer_public_key), raw=True)

    encrypted_certificate_static = dongle.exchange(bytearray.fromhex('E052000000'))

    # First extract the device ephemeral public key from the device ephemeral certificate
    certificate_ephemeral = bytearray(dongle.exchange(bytearray.fromhex('E052800000')))

    certificate_header, certificate_public_key, certificate_signature_array = \
        extract_from_certificate(certificate_ephemeral)

    # Check the certificate's header
    if not certificate_header == bytearray():
        raise Exception("Device ephemeral certificate: error format")

    # Decrypt the device static certificate
    # Compute the shared key
    pub_key = PublicKey(bytes(certificate_public_key), raw=True)
    secret = pub_key.ecdh(binascii.unhexlify(ephemeral_private.serialize()), True)
    key = scp_derive_key(secret, 0, True)

    certificate_static = decrypt_certificate(encrypted_certificate_static, key)

    # Decrypt the signature from the ephemeral certificate
    certificate_signature_array = decrypt_certificate(certificate_signature_array, key)

    # Verify the device static certificate
    certificate_static_header, certificate_static_public_key, certificate_static_signature_array = \
        extract_from_certificate(certificate_static)
    certificate_signature = issuer_pk.ecdsa_deserialize(bytes(certificate_static_signature_array))
    certificate_signed_data = bytearray([CERT_ROLE_DEVICE]) + certificate_static_header + certificate_static_public_key

    if not issuer_pk.ecdsa_verify(bytes(certificate_signed_data), certificate_signature):
        raise Exception("Device certificate not verified")

    # Verify the device ephemeral certificate
    device_pub_key = PublicKey(bytes(certificate_static_public_key), raw=True)
    certificate_signature = device_pub_key.ecdsa_deserialize(bytes(certificate_signature_array))
    certificate_signed_data = bytearray([CERT_ROLE_DEVICE_EPHEMERAL]) + device_nonce + nonce + certificate_public_key

    if not device_pub_key.ecdsa_verify(bytes(certificate_signed_data), certificate_signature):
        raise Exception("Device ephemeral certificate not verified")

    dongle.exchange(bytearray.fromhex('E053000000'))

    return secret, certificate_public_key


def recoverValidate(loader, caKey, name, staticPrivateKey):
    caPrivateKey = PrivateKey(bytes(caKey))

    providerPrivateKey = PrivateKey(bytes(staticPrivateKey))
    providerPublicKey = bytearray(providerPrivateKey.pubkey.serialize(compressed=False))

    # Validate provider's static certificate
    role = bytearray([CERT_ROLE_RECOVER_PROVIDER])
    version = bytearray([CERT_FORMAT_VERSION])
    dataToSign = bytes(version + role + struct.pack('>B', len(name)) + name.encode() +
                       struct.pack('>B', len(providerPublicKey)) + providerPublicKey)
    signature = caPrivateKey.ecdsa_sign(bytes(dataToSign))
    signature = caPrivateKey.ecdsa_serialize(signature)

    loader.recoverValidateCertificate(bytes(version), bytes(role), name, providerPublicKey, signature)

    # Validate provider's ephemeral certificate
    ephemeralPrivate = PrivateKey()
    ephemeralPublic = bytearray(ephemeralPrivate.pubkey.serialize(compressed=False))
    role = bytearray([CERT_ROLE_RECOVER_PROVIDER_EPHEMERAL])
    dataToSign = bytes(version + role + struct.pack('>B', len(name)) + name.encode() +
                       struct.pack('>B', len(ephemeralPublic)) + ephemeralPublic)
    signature = providerPrivateKey.ecdsa_sign(bytes(dataToSign))
    signature = providerPrivateKey.ecdsa_serialize(signature)

    loader.recoverValidateCertificate(bytes(version), bytes(role), name, ephemeralPublic, signature, True)

    return ephemeralPrivate, ephemeralPublic


def recoverMutualAuth(privateKey, devicePublicKey):

    # Compute the shared key
    pk = PublicKey(devicePublicKey, raw=True)
    secret = pk.ecdh(binascii.unhexlify(privateKey.serialize()), True)
    sharedKey = scp_derive_key(secret, 0, True)

    return sharedKey

