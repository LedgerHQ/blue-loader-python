from ledgerblue.ecWrapper import PrivateKey
from ledgerblue.comm import getDongle
from ledgerblue.hexLoader import HexLoader
from ledgerblue.recoverMutualAuth import SCPv3
import binascii
import argparse


def get_argparser():
    parser = argparse.ArgumentParser(description="Set a custom Certificate Authority to backup/restore a seed.")
    parser.add_argument("--targetId", help="The device's target ID (default is Nano X)", type=auto_int)
    parser.add_argument("--name", help="The certificate name", required=True)
    parser.add_argument("--issuerPublicKey", help="The public key of the Issuer (used to verify the certificate of "
                                                  "the device)")
    parser.add_argument("--rootPrivateKey", help="The private key of the Signer used to establish a secure channel "
                                                 "(otherwise a random one will be generated)")
    parser.add_argument("--caPublicKey", help="The Custom CA's public key to be enrolled (hex encoded)", required=True)
    return parser


def auto_int(x):
    return int(x, 0)


if __name__ == '__main__':

    args = get_argparser().parse_args()

    if args.targetId is None:
        args.targetId = 0x33000004
    if args.name is None:
        raise Exception("Missing certificate's name")
    if args.issuerPublicKey is None:
        args.issuerPublicKey = '0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f81805' \
                               '7224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609'
    if args.rootPrivateKey is None:
        privateKey = PrivateKey()
        publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
        print("Generated random root public key : %s" % publicKey)
        args.rootPrivateKey = privateKey.serialize()
    if args.caPublicKey is None:
        raise Exception("Missing CA's public key")

    publicKey = bytearray.fromhex(args.caPublicKey)
    dongle = getDongle(True)

    # Execute secure channel protocol (new version)
    secret, devicePublicKey = SCPv3(dongle, bytearray.fromhex(args.issuerPublicKey), args.targetId,
                                    None, bytearray.fromhex(args.rootPrivateKey),
                                    user_mode=True)
    loader = HexLoader(dongle, 0xe0, True, secret, scpv3=True)

    # Load the Certificate Authority's public key
    loader.recoverSetCA(args.name, publicKey)
