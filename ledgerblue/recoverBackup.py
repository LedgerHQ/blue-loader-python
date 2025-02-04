from ledgerblue.comm import getDongle
from ledgerblue.hexLoader import HexLoader
from ledgerblue.recoverMutualAuth import recoverMutualAuth, SCPv3, recoverValidate
from ledgerblue.recoverUtil import Recover
from hashlib import sha256
from Crypto.Cipher import AES
import binascii
import argparse
import json
import gnupg
import os


def get_argparser():
    parser = argparse.ArgumentParser(description="Backup 3 shares of a seed.")
    parser.add_argument(
        "--targetId", help="The device's target ID (default is Nano X)", type=auto_int
    )
    parser.add_argument(
        "--rootPrivateKey", help="The private key of the Certificate Authority"
    )
    parser.add_argument(
        "--issuerPublicKey",
        help="The public key of the Issuer (used to verify the certificate of "
        "the device)",
    )
    parser.add_argument(
        "--numberOfWords",
        help="The number of words in the mnemonic (default is 24 words)",
        type=auto_int,
    )
    parser.add_argument(
        "-c",
        "--configuration",
        help="Configuration file",
        default=None,
        required=True,
        action="store",
    )
    parser.add_argument(
        "--gpg",
        help="Encrypt the backup data. Enter the email address associated to your gpg key",
        default=None,
        action="store",
    )
    return parser


def auto_int(x):
    return int(x, 0)


def decode_bytes(my_bytes):
    return my_bytes.decode("utf-8")


if __name__ == "__main__":
    args = get_argparser().parse_args()

    # Read the configuration file
    try:
        with open(args.configuration, "r") as file:
            conf = json.load(file)
    except Exception as err:
        print(err)
        exit()

    if args.targetId is None:
        args.targetId = 0x33000004
    if args.rootPrivateKey is None:
        raise Exception("Missing Certificate Authority private key")
    if args.issuerPublicKey is None:
        args.issuerPublicKey = (
            "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f81805"
            "7224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609"
        )
    if args.numberOfWords is None:
        # Default is 24 words
        args.numberOfWords = 24
    if not args.gpg:
        print("Your backup is going to be saved unencrypted !")
    else:
        home = os.path.join(os.environ["HOME"], ".gnupg")
        gpg = gnupg.GPG(gnupghome=home)

    dongle = getDongle(True)

    orchestratorPrivateKey = conf["orchestrator"]["key"]

    # Execute device-orchestrator secure channel protocol
    secret, devicePublicKey = SCPv3(
        dongle,
        bytearray.fromhex(args.issuerPublicKey),
        args.targetId,
        bytearray.fromhex(args.rootPrivateKey),
        bytearray.fromhex(orchestratorPrivateKey),
    )
    loader = HexLoader(dongle, 0xE0, True, secret, scpv3=True)

    # Initialize the session with the info from the configuration file
    recoverSession = Recover(conf)
    confirmed = False

    for provider in conf["providers"]:
        backup_data = dict()
        delete_data = dict()
        name = provider["name"]
        privateKey = provider["key"]

        # Execute device-provider mutual authentication
        providerSk, providerPk = recoverValidate(
            loader,
            bytearray.fromhex(args.rootPrivateKey),
            name,
            bytearray.fromhex(privateKey),
        )
        loader.recoverMutualAuth()
        sharedKey = recoverMutualAuth(providerSk, devicePublicKey)
        recoverSession.sharedKey = sharedKey

        # Send the user identity to the device
        if not confirmed:
            dataIdv = recoverSession.recoverPrepareDataIdv()
            cipher = AES.new(sharedKey, AES.MODE_SIV)
            ciphertext, tag = cipher.encrypt_and_digest(dataIdv)
            loader.recoverConfirmID(tag, ciphertext)
            confirmed = True

        dataHash = recoverSession.recoverPrepareDataHash(providerPk)
        cipher = AES.new(sharedKey, AES.MODE_SIV)
        ciphertext, tag = cipher.encrypt_and_digest(dataHash)

        # Validate backup data hash (device and backup provider agree on the same backup data)
        response = loader.recoverValidateHash(tag, ciphertext)

        # Get the share value and the number of words of the mnemonic (can be 12, 18 or 24)
        # The share is encrypted with the device-provider shared key
        resp = loader.recoverGetShare(value="shares")
        encryptedData = resp[: len(resp) - 1]
        numberOfWords = resp[len(resp) - 1]
        share, idx, deletePublicKey, commitHash = (
            recoverSession.recoverBackupProviderDecrypt(encryptedData)
        )

        # Get the commitments to the coefficients used to calculate the share
        commitments = loader.recoverGetShare(value="commitments")

        # Get the VSS point
        commitmentPoint = loader.recoverGetShare(value="point")

        h = sha256()
        h.update(commitments)
        calculatedCommitHash = h.digest()

        # Hashes of the commitments match on both side
        if not (commitHash == calculatedCommitHash):
            raise Exception("Hashes of the commitments don't match")

        # Verify whether the share is consistent
        result, shareCommit = recoverSession.recoverVerifyCommitments(
            share, idx, commitments, commitmentPoint
        )
        if result:
            # Do the backup
            backup_data[name] = dict()
            backup_data[name]["share"] = decode_bytes(binascii.hexlify(share))
            backup_data[name]["index"] = decode_bytes(
                binascii.hexlify(idx.to_bytes(4, "little"))
            )
            backup_data[name]["commitments"] = decode_bytes(
                binascii.hexlify(commitments)
            )
            backup_data[name]["share_commit"] = decode_bytes(
                binascii.hexlify(shareCommit)
            )
            backup_data[name]["hash"] = decode_bytes(binascii.hexlify(commitHash))
            backup_data[name]["point"] = decode_bytes(binascii.hexlify(commitmentPoint))
            backup_data[name]["words_number"] = numberOfWords
            delete_data[name] = dict()
            delete_data[name]["public_key"] = decode_bytes(
                binascii.hexlify(deletePublicKey)
            )
        else:
            raise Exception("Share's commitments not verified")

        # Validate the share's commitment
        recoverSession.recoverValidateShareCommit(loader, shareCommit)

        # Store the backup (it is up to the user to store it in a safe location)
        for name in backup_data:
            try:
                if args.gpg:
                    with open(name + ".json.gpg", "w") as file:
                        encode_backup_data = json.dumps(
                            backup_data, indent=4, sort_keys=True
                        ).encode("utf-8")
                        encrypted_backup = gpg.encrypt(
                            encode_backup_data, recipients=[args.gpg]
                        )
                        file.write(str(encrypted_backup))
                    with open("Delete" + name + ".json.gpg", "w") as file:
                        encode_delete_data = json.dumps(delete_data, indent=4).encode(
                            "utf-8"
                        )
                        encrypted_data = gpg.encrypt(
                            encode_delete_data, recipients=[args.gpg]
                        )
                        file.write(str(encrypted_data))
                else:
                    with open(name + ".json", "w") as file:
                        json.dump(backup_data, file, indent=4, sort_keys=True)
                    with open("Delete" + name + ".json", "w") as file:
                        json.dump(delete_data, file, indent=4)
            except Exception as err:
                print(err)
                exit()
