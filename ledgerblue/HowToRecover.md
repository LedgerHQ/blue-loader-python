## Set up

1. Install `gnupg` to have the ability to encrypt the backup files with OpenPGP:

```shell
apt-get install gnupg
```

2. Generate a key pair:

```shell
gpg --gen-key
```
and follow instructions.

3. Verify the key:

```shell
gpg --list-keys
```

4. Set the level of trust

```shell
gpg --edit-key <KEY_ID>
gpg > trust
```

and set to the maximum level (5).

5. Install ledgerblue in a virtual environment (see the [installation instructions](../README.md#installation))

## I. Set a custom Certificate Authority

The Recover feature requires a Certificate Authority (CA). The certificate authority signs the public key of each different entity, which allow them to establish a secure channel with the device.

To implement your own backup provider, you are your own Certificate Authority and so you need to load your public key on the device to make it recognize the signatures that you will create.

Note that applications installation from Ledger Live will fail if a custom Certificate Authority is set. That is the regular behavior, so it is mandatory to delete the custom Certificate Authority after the backup or the restore.

The script `recoverSetCA` is used to set a Certificate Authority from a user's public key. The device must be in [recovery mode](#recovery-mode).

### Arguments

- `--name` (mandatory): the name of the Certificate Authority.

- `--issuerPublicKey` (optional): the public key of the Issuer. The Issuer is the Ledger HSM that had attested and had provided a certificate to the device. The value of the Issuer public key is set in the script.

- `--rootPrivateKey` (optional): the private key of the Signer used to establish the secure channel. If not set, a random key is used.

- `--caPublicKey` (mandatory): the public key of the Certificate Authority.

- `--targetId` (optional): the identifier of the target device (see [target IDs table](#target-ids)).

  The identifier for the Nano X is used by default.

### Usage

1. Generate a pair of CA keys. The keys should be generated over the curve `Secp256k1` and the user is responsible for the generation of a secure pair of keys.

The following pair of keys will be used as an example of Certificate Authority's keys:

```shell
Public key : 040c09e45d01494ede4bb0d814e593a964ef9324cd48f7389b9fbf242348274fda4543c204f5913b06647fc829653a5abf6d321b91f5842c9742022bf7120dff38
Private key: 0d990d0c41d955a5c63c0e647f7b82a1b383bf645d140f5edffbb79786323d43
```
The private key value must be kept for later backup or restore.

2. Execute the script **recoverSetCA.py** script with the mandatory arguments `--name`, `--caPublicKey`:

If `--issuerPublicKey` is not specified, the default value for production devices is: `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609`

If `--targetId` is not specified, the default value is `0x3300004` (Nano X).

If `--rootPrivateKey` is not specified, a random key is generated.

```shell
python3 -m ledgerblue.recoverSetCA --name "Recover test CA" --caPublicKey 040c09e45d01494ede4bb0d814e593a964ef9324cd48f7389b9fbf242348274fda4543c204f5913b06647fc829653a5abf6d321b91f5842c9742022bf7120dff38
```

3. Reboot the device.

## II. Backup

The script `recoverBackup` is used to perform a backup of a Ledger device seed through 3 shares. Each share is saved in a file along with the commitments, it is up to the user to provide a key to encrypt the backup files.

### Arguments

- `--rootPrivateKey` (mandatory): the private key of the Certificate Authority. This is used to sign the certificates of the involved entities, except the device.

- `--configuration (-c)` (mandatory): the configuration file that contains the information needed to do the backup, namely the user identity, the backup id, the backup name and the keys of the involved entities.

- `--issuerPublicKey` (optional): the public key of the Issuer. The Issuer is the Ledger HSM that had attested and had provided a certificate to the device. The value of the Issuer public key is set in the script.

- `--targetId`(optional): the identifier of the target device (see [target IDs table](#target-ids)).

  The identifier for the Nano X is used by default.

- `--numberOfWords`(optional): the number of words in the mnemonic phrase.

  The default value is 24.

- `--gpg` (optional): the email address corresponding to the gpg key to use. If this argument is not set, the shares backup files are not encrypted.

### Requirements

The script is executed with the device showing the dashboard, **after** a custom CA is set. See [the Backup steps](#backup-steps)

### Usage

1. Create and edit the **conf.json** file with the required fields

```json
{
    "user_info":
    {
        "first_name": "John",
        "last_name": "Doe",
        "birth": "12 January 1980",
        "city": "PARIS"
    },
    "backup_info":
    {
        "backup_id": "70d087ee73844c739b009db405113af8",
        "backup_name": "Ledger wallet backup"
    },
    "orchestrator":
    {
        "key": ""
    },
    "providers": [
        {
            "name" : "Backup_1",
            "key" : ""
        },
        {
            "name" : "Backup_2",
            "key" : ""
        },
        {
            "name" : "Backup_3",
            "key" : ""
        }
    ]
}
```

The backup ID must be a `version 4 UUID` without the dash `-`.

The 'key' values must be private keys generated over the curve `SECP256K1`.

2. Execute the **recoverBackup.py** script with the mandatory arguments `--rootPrivateKey` and `--configuration (-c)`.

   If `--issuerPublicKey` is not specified, the default value for production devices is: `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609`

   If `--targetId` is not specified, the default value is `0x3300004` (Nano X).

   If `--numberOfWords` is not specified, the default value is `24`.

   If `--gpg` is not specified, the backup data are saved unencrypted in three json files. The extension of each file is `.json.gpg` if `--gpg` is set, otherwise the extension is `.json`.

Example of usage with the root private key `0x0d990d0c41d955a5c63c0e647f7b82a1b383bf645d140f5edffbb79786323d43` (the corresponding public key must have been set beforehand with `recoverSetCA.py`):

```shell
python3 -m ledgerblue.recoverBackup --rootPrivateKey 0d990d0c41d955a5c63c0e647f7b82a1b383bf645d140f5edffbb79786323d43 -c conf.json --gpg john.doe@mail.com
```
Six `gpg` files are created at the end of the operation: `Backup_1.json.gpg`, `Backup_2.json.gpg`, `Backup_3.json.gpg`, `DeleteBackup_1.json.gpg`, `DeleteBackup_2.gpg`, `DeleteBackup_3.gpg`. Note that the names of the files match the names in `conf.json`.

`Backup_1.json.gpg`, `Backup_2.json.gpg`, and `Backup_3.json.gpg` contain the shares along with the commitments values while `DeleteBackup_1.json.gpg`, `DeleteBackup_2.json.gpg`, and `DeleteBackup_3.json.gpg` contain a public key which is used to delete each backup. The backup deletion is relevant only for Recover from Coincover.

Each `Backup_1.json.gpg`, `Backup_2.json.gpg`, and `Backup_3.json.gpg` file contain the following fields:

- **commitments**: the commitments to the secret which are verified during a restore.
- **hash**: the hash of various data including an ephemeral public key, the backup ID and the backup data.
- **index**: the index of the share in little endian form.
- **point**: the auxiliary point used in the VSS scheme.
- **share**: one share of the secret.
- **share_commit**: the commitment to the share which is verified during a restore.
- **words_number**: the number of words of the mnemonic phrase.

One can verify the content of the backup files by decrypting them:

```shell
gpg --output Backup_1.json --decrypt Backup_1.json.gpg
```

which generates the following json file (with the values):

```json
{
    "Backup 1": {
        "commitments": "",
        "hash": "",
        "index": "",
        "point": "",
        "public_key": "",
        "share": "",
        "share_commit": "",
        "words_number": 24
    }
}
```

After the verification, the backup files should remain encrypted.

## III. Restore

The `recoverRestore.py` script is used to restore a seed on a non-initialized Ledger device given the corresponding shares. The configuration file and the backup data saved during the backup must be used.

### Arguments

- `--rootPrivateKey` (mandatory): the private key of the Certificate Authority. This is used to sign the certificates of the involved entities, except the device.

- `--configuration (-c)` (mandatory): the configuration file that contains the information need to do the restore, namely the user identity, the backup id, the backup name and the keys of the involved entities.

- `--select (-s)` (mandatory): the files where the backup data have been saved: either with a `.gpg` extension if encrypted of with `.json` extension if not.

- `--issuerPublicKey` (optional): the public key of the Issuer. The Issuer is the Ledger HSM that had attested and had provided a certificate to the device. The value of the Issuer public key is set in the script.

- `--targetId` (optional): the identifier of the target device (see [target IDs table](#target-ids)).

  The identifier for the Nano X is used by default.

- `--numberOfWords` (optional): the number of words in the mnemonic phrase.

  The default value is 24.

- `--gpg` (optional): the email address corresponding to the gpg key to use.

### Requirements

The script must be executed with the device showing `Log in to Ledger Recover on Ledger Live`:

1. Select `Restore` then `Restore using Ledger Recover` mode on a **non-initialized** device
2. Enter and confirm the PIN

To cancel the restore (before the execution of the script) and select another way of initializing the device:
1. Press the right button until the `cancel` screen is reached
2. Press both buttons to cancel

The script is executed **after** a custom CA is set. See [the Restore steps](#restore-steps)

### Usage

1. Edit the **conf.json** file with the required fields

2. Execute the **recoverRestore.py** script with the mandatory arguments `--rootPrivateKey`, `--configuration (-c)`, `--select (-s)`.

   The `-s` argument corresponds to the json files generated by the `recoverBackup.py` script.

   If `--issuerPublicKey` is not specified, the default value is `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609`

   If `--targetId` is not specified, the default value is `0x33000004` (Nano X).

   If `--numberOfWords` is not specified, the default value is `24` .

Example of usage with the root private key `0x0d990d0c41d955a5c63c0e647f7b82a1b383bf645d140f5edffbb79786323d43` (the corresponding public key must have been set beforehand with `recoverSetCA.py`):

```shell
python3 -m ledgerblue.recoverRestore --rootPrivateKey 0d990d0c41d955a5c63c0e647f7b82a1b383bf645d140f5edffbb79786323d43 -c conf.json -s "Backup_1.json.gpg" "Backup_2.json.gpg" --gpg john.doe@mail.com
```

## IV. Delete the custom Certificate Authority

The script `recoverDeleteCA` is used to delete the Certificate Authority set by the user. The device must be in [recovery mode](#recovery-mode). It is mandatory to delete the custom CA to be able to use the device with Ledger Live.

### Arguments

- `--name` (mandatory): the name of the Certificate Authority.

- `--issuerPublicKey` (optional): the public key of the Issuer. The Issuer is the Ledger HSM that had attested and had provided a certificate to the device. The value of the Issuer public key is set in the script.

- `--rootPrivateKey` (optional): the private key of the Signer used to establish the secure channel. If not set, a random key is used.

- `--caPublicKey` (mandatory): the public of the Certificate Authority.

- `--targetId` (optional): the identifier of the target device (see [target IDs table](#target-ids)).

  The identifier for the Nano X is used by default.

### Usage

1. Execute the script **recoverDeleteCA.py** script with the mandatory arguments `--name`, `--caPublicKey`:

If `--issuerPublicKey` is not specified, the default value for production devices is: `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609`

If `--targetId` is not specified, the default value is `0x3300004` (Nano X).

If `--rootPrivateKey` is not specified, a random key is generated.

```shell
python3 -m ledgerblue.recoverDeleteCA --name "Recover test CA" --caPublicKey 040c09e45d01494ede4bb0d814e593a964ef9324cd48f7389b9fbf242348274fda4543c204f5913b06647fc829653a5abf6d321b91f5842c9742022bf7120dff38
```

2. Reboot the device.

## Target IDs

| Device name   | Target ID    | Recover compatible versions |
|---------------|--------------|-----------------------------|
| `Nano X`      | `0x33000004` | \>= 2.2.1                   |
| `Nano S Plus` | `0x33100004` | No compatible version yet   |

## Recovery mode

The steps are as follows:

1. Press and hold down the left button of your Ledger device.
2. Connect the device to your computer using a USB cable while holding down the left button. You can also use Android and a USB OTG cable kit.
3. Keep holding the left button down until the Boot menu appears.
4. Use the right button to navigate to Recovery mode.
5. Press both buttons simultaneously to enable Recovery mode.
6. If you have set a PIN before, enter the PIN.

## Summary

### Backup steps
To do a **backup** of your seed, you have to:

1. Generate a pair of Certificate Authority keys
2. Put the device in recovery mode
3. Set the custom Certificate Authority
4. Reboot the device (to leave the recovery mode)
5. Do the backup operation
6. Put the device in recovery mode
7. Delete the custom Certificate Authority
8. Reboot the device (to leave the recovery mode)

### Restore steps
To do a **restore** of your seed, you have to:

1. Select the `Restore using Ledger Recover` mode on the device and enter the PIN (it is mandatory to have a PIN to set the custom Certificate Authority)
2. Generate a pair of Certificate Authority keys
3. Put the device in recovery mode
4. Set the custom Certificate Authority
5. Reboot the device (to leave the recovery mode)
6. Do the restore operation
7. Put the device in recovery mode
8. Delete the custom Certificate Authority
9. Reboot the device (to leave the recovery mode)

   
