from ecpy.curves import Curve, Point
from Crypto.Cipher import AES
from ledgerblue.ecWrapper import PublicKey
from ledgerblue.vss import PedersenVSS
from hashlib import sha256
import os

FIRST_NAME_TAG = 0x20
NAME_TAG = 0x21
DATE_OF_BIRTH_TAG = 0x22
PLACE_OF_BIRTH_TAG = 0x23
BACKUP_FLOW = 0x01
RESTORE_FLOW = 0x10
DELETE_FLOW = 0x11


class Recover:
    def __init__(self, conf):
        self.sharedKey = bytes()
        self.backupId = bytearray.fromhex(conf['backup_info']['backup_id'])
        self.backupName = conf['backup_info']['backup_name']
        user = conf['user_info']
        self.firstName = user['first_name']
        self.lastName = user['last_name']
        self.birthDate = user['birth']
        self.birthPlace = user['city']
        self.userInfo = self.firstName + self.lastName + self.birthDate + self.birthPlace
        self.f_tag = FIRST_NAME_TAG
        self.n_tag = NAME_TAG
        self.d_tag = DATE_OF_BIRTH_TAG
        self.c_tag = PLACE_OF_BIRTH_TAG
        self.VSS = PedersenVSS(Curve.get_curve("secp384r1"))

    def recoverRestoreSeed(self, loader, share, wordsNumber):
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        ciphertext, tag = cipher.encrypt_and_digest(share)
        loader.recoverRestoreSeed(tag, ciphertext, wordsNumber)

    def recoverValidateCommit(self, loader, commits, shareCommit):
        dataToHash = bytes(commits + shareCommit)
        h = sha256()
        h.update(dataToHash)
        dataHash = h.digest()
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        ciphertext, tag = cipher.encrypt_and_digest(dataHash)
        loader.recoverValidateCommit(0x2, commits)
        loader.recoverValidateCommit(0x4, shareCommit)
        loader.recoverValidateCommit(0x3, None, tag, ciphertext)

    def recoverShareCommit(self, point, share):
        Q = Point(int.from_bytes(point[:self.VSS.domain_len], 'big'),
                  int.from_bytes(point[self.VSS.domain_len:2 * self.VSS.domain_len], 'big'), self.VSS.curve)
        P = self.VSS.pedersen_share_commit(Q, share)
        return bytearray(P.x.to_bytes(self.VSS.domain_len, 'big') + P.y.to_bytes(self.VSS.domain_len, 'big'))

    def recoverValidateShareCommit(self, loader, shareCommit):
        dataToHash = bytes(shareCommit)
        h = sha256()
        h.update(dataToHash)
        dataHash = h.digest()
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        ciphertext, tag = cipher.encrypt_and_digest(dataHash)
        loader.recoverValidateCommit(0x4, shareCommit)
        loader.recoverValidateCommit(0x3, None, tag, ciphertext)

    def recoverVerifyCommitments(self, share, idx, commitments, point):
        point_len = 2 * self.VSS.domain_len
        commitsPoints = [Point(int.from_bytes(commitments[i * point_len:i * point_len + self.VSS.domain_len], 'big'),
                                int.from_bytes(commitments[i * point_len + self.VSS.domain_len: i * point_len + 2 * self.VSS.domain_len],
                                               'big'), self.VSS.curve) for i in range(2)]
        Q = Point(int.from_bytes(point[:self.VSS.domain_len], 'big'),
                  int.from_bytes(point[self.VSS.domain_len:2 * self.VSS.domain_len], 'big'), self.VSS.curve)
        result, shareCommitPoint = self.VSS.pedersen_verify_commit(Q, share, idx, commitsPoints)
        shareCommit = bytearray(shareCommitPoint.x.to_bytes(self.VSS.domain_len, 'big') + shareCommitPoint.y.to_bytes(self.VSS.domain_len, 'big'))
        return result, shareCommit

    def recoverPrepareDataHash(self, publicKey):
        backupDataToHash = bytes(self.backupName.encode() + self.userInfo.encode())
        h1 = sha256()
        h1.update(backupDataToHash)
        backupDataHash = h1.digest()
        dataToHash = bytes(publicKey + self.backupId + backupDataHash)
        h2 = sha256()
        h2.update(dataToHash)
        dataHash = h2.digest()

        return dataHash

    def recoverBackupProviderDecrypt(self, encryptedData):
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        plaintext = cipher.decrypt_and_verify(encryptedData[16:], encryptedData[:16])

        share = plaintext[:96]
        idx = int.from_bytes(plaintext[96:100], 'little')
        deletePublicKey = plaintext[100:165]
        commitHash = plaintext[165:]

        return share, idx, deletePublicKey, commitHash

    def recoverDeleteBackup(self, loader, backupPublicKey):
        nonce = os.urandom(16)
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        ciphertext, tag = cipher.encrypt_and_digest(nonce)
        encryptedSignature = loader.recoverDeleteBackup(tag, ciphertext)
        cipher = AES.new(self.sharedKey, AES.MODE_SIV)
        signature = cipher.decrypt_and_verify(encryptedSignature[16:], encryptedSignature[:16])
        verifyKey = PublicKey(bytes(backupPublicKey), raw=True)
        signature = verifyKey.ecdsa_deserialize(signature)
        if not verifyKey.ecdsa_verify(nonce, signature):
            raise Exception("Invalid signature")

