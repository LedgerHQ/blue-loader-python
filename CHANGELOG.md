# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.56] - 2026-04-08

### Added

- Add `debugApp` script to capture app PRINTF output over USB CDC
- Scan until Ledger CDC port appears (connection & disconnection) and add timestamp
- Enable BLS12-377 and ZIP32 derivations in parameters installation
- Add support for Apex BLE
- Add `actionlint` CI linting
- USB environment variable to select specific port

### Changed

- Rename `distributeFirmware11_scan` into `distributeFirmware`
- Bump protobuf version to match ledgerctl
- Replace deploy job with reusable workflow
- Apply `ruff` formatting and linting across codebase
- Push to Artifactory Python registry in CI
- Remove useless push to `test.pypi.org`
- Update `upload-artifact` action (v3 deprecated)

### Fixed

- Fix issue when a LP has a `.hex` with several areas
- Fix PCSC reader detection
- Fix support for PCSC smartcard readers
- Fix APDU through BLE
- Fix AES init with IV
- Reduce specific CI permission to the targeted job

## [0.1.55] - 2025-07-30

### Changed

- Supported Python versions: dropped 3.6, 3.7 and 3.8, added 3.11, 3.12 and 3.13

### Fixed

- Fix issue when a LP has a `.hex` with several areas

## [0.1.54] - 2024-05-21

### Fixed

- Fix missing import in `loadApp.py`

## [0.1.53] - 2024-05-06

### Added

- Add detailed descriptions for some error codes to ease debug

### Changed

- Raise `CommException` with response data
- Shutdown socket before closing

## [0.1.52] - 2024-04-25

### Fixed

- `loadApp.py`: Fix return code

## [0.1.51] - 2024-04-23

### Changed

- Making the main function of `loadApp.py` callable

## [0.1.50] - 2024-04-03

### Fixed

- Align protobuf dependency versions with Ledgerwallet
- Fix `appName` parameter encoding in `runApp`
- Fix indentation on `runApp`

## [0.1.49] - 2024-03-26

### Added

- Add Europa service UUID
- Implement the backup deletion flow
- Add `--bypass-ssl-check` for `updateFirmware2` command
- Automatic deployment in CI
- Generate & deploy doc in the CI

### Changed

- Delete unused constants/import
- Replace NFC polling mechanism with a simple transceive operation
- Remove `nfcTagUpdate.py` script
- Update udev rule for hidraw USB access
- Update & document the generation of Sphinx documentation
- Refactor `recoverPrepareDataIdv`
- Encrypt backup data with provider's key

### Fixed

- Allow local install even when no tag or SCM tool is present
- Fix list of valid sections
- Do not force `response=True` on `write_gatt_char()` calls

## [0.1.48] - 2023-07-25

### Added

- Add Recover's scripts and instructions
- HexLoader: Add language packs functions
- Add `createpackParams` as an attribute of `HexLoader`

### Changed

- Set `long_description_content_type` to markdown

## [0.1.47] - 2023-04-20

### Added

- Add `BleComm.py` script with `BleScanner` class for device scanning and selection
- Add `BleDevice` class with open/close/exchange methods
- Add `DongleBLE` class in `comm.py`, integrate `BleDevice` from `BleComm.py`
- Add Nano X support (add Nano X service UUID)

### Changed

- Use BLE write cmd characteristic to speed up transfer time

## [0.1.46] - 2023-04-11

### Added

- Add `readElfMetadata` tool and integrate it to `runScript`

### Changed

- Enable `--rootPrivateKey` usage
- Set NFC APDU max size to 255 (as USB HID transport)

### Fixed

- Fix `runScript` SCP APDU formatting

## [0.1.45] - 2023-02-28

### Added

- Add NFC support in `comm.py`
- Add new script `nfcTagUpdate.py` to update NFC tag content
- Add `nfcpy` dependency

### Fixed

- Fix pyscard version for setuptools v67

## [0.1.44] - 2023-01-25

### Changed

- `createapp`: set invalid API level (legacy) to -1
- `loadApp.py`: Remove `apilevel` parameter

## [0.1.43] - 2022-10-07

### Added

- SDK API level handling in load script
- Add public endorsement endpoint

## [0.1.41] - 2021-11-22

### Fixed

- Hotfix adding a close function to `FileCard` class

## [0.1.40] - 2021-11-22

### Fixed

- Fixed assertion error
- Fix `apdugen` wrong return type

## [0.1.39] - 2021-11-17

### Changed

- Remove `ctx` and `flags` parameters
- Script params: use keyword arguments for `argparse`
- Remove redundant parentheses and semicolons
- Replace `hexstr()` with `bytes.hex()`
- Remove legacy code specific to Python 2
- Remove unused imports
- Add missing import

## [0.1.38] - 2021-09-13

### Changed

- Rename `prime256r1` to `secp256r1`

## [0.1.37] - 2021-09-13

### Added

- Argument to bypass SSL check of remote certificate when running remote install script

## [0.1.36] - 2021-09-02

### Added

- Add argument to bypass SSL check of remote certificate when endorsing a device
- Add link to Speculos in documentation
- Add note on developer Nano X units

### Changed

- Update Ledger URLs

### Fixed

- Test for `AttributeError` when reading `secp256k1.HAS_ECDH`

## [0.1.34] - 2020-10-30

### Fixed

- Fix BLS-12 381 G1 derivation

## [0.1.33] - 2020-10-30

### Added

- Add BLS-12 381 G1 derivation

## [0.1.32] - 2020-09-03

### Added

- Add RFC6979 support for deterministic signatures
- Handle GET RESPONSE

### Fixed

- Raise exception when needed

## [0.1.31] - 2019-11-15

### Added

- SLIP-0021 support when loading an application on 1.6 firmware

## [0.1.30] - 2019-09-25

### Fixed

- Delete socket on close for better serialization of `DongleServer` object

## [0.1.29] - 2019-09-24

### Added

- Add support for more device statuses
- Add `apduMaxDataSize` method to the `commTCP` `DongleServer` class
- Update README with macOS installation instructions

### Changed

- More generic error messages

## [0.1.28] - 2019-08-31

### Fixed

- Change sig type from `bytearray` to `bytes` to match `secp256k1`

## [0.1.27] - 2019-07-15

### Changed

- Update `updateFirmware` to use `distributeFirmware11_scan`

## [0.1.26] - 2019-07-08

### Changed

- U2F Python 3 compatibility
- Working `endorsementSetup` on Python 3

## [0.1.25] - 2019-06-08

### Added

- Add common backend support for genuine check & management

## [0.1.24] - 2019-05-27

### Added

- Add TCP proxy support
- Add Nano X to README

## [0.1.23] - 2019-02-17

### Changed

- Improve Python 3 compatibility
- Support additional Status Words

## [0.1.22] - 2019-01-14

### Changed

- Accept the generic status `61xx`
- Standardize tab and space mix to 4 spaces for Python 3 compatibility

### Fixed

- Fix missing `targetVersion` and Python 2 incompatibility
- Add a `lib_dependency` error message

## [0.1.21] - 2018-10-14

### Added

- Add support of SCP4 version for application hash computation

### Fixed

- Python 3 fixes
- Fix Python 3 invalid encoding in `targetVersion`

## [0.1.20] - 2018-09-04

### Added

- Add Blue 2.1 target ID

### Fixed

- Fix genuine check for newer firmware versions
- Fix Blue 2.1 compatibility for `updateFirmware`

## [0.1.19] - 2018-07-13

### Fixed

- Fix ECPy dependency version
- Fix SCP on Blue 2.1

## [0.1.18] - 2018-06-29

### Changed

- Always generate canonical signature on sign
- Replace `pycrypto` with `pycryptodomex`

### Fixed

- Python 3 compatibility additional fix

## [0.1.17] - 2018-03-29

### Added

- New script `getMemInfo` and new `hexloader` method `getMemInfo`
- New argument `signPrivateKey` in `loadApp` to decorrelate signature from SCP opening
- Add `runScript` debug support
- Nano S 1.4 support
- Add `.gitignore`

### Changed

- Cleanup Python 3 support
- Better interface filter, macOS portability

### Fixed

- Fix custom CA handling
- Fix py2 compatibility for `setupCustomCA`
- Friendlier errors for `0x6985`, `0x6a84` and `0x6a85`
- Fix typo on `getDeployedSecretV1`

## [0.1.16] - 2017-10-20

### Fixed

- Fix invalid exit condition
- Python 3 fixes

## [0.1.15] - 2017-08-01

### Added

- Added documentation
- Fixed CSS override issue for docs

## [0.1.14] - 2017-08-01

### Added

- Added documentation

## [0.1.13] - 2017-03-07

### Added

- Add `runApp.py` for specific firmware

## [0.1.12] - 2017-02-28

### Added

- Add scripts related to Nano S 1.3

## [0.1.11] - 2017-01-30

### Added

- Additional Attestation / Endorsement related APIs
- Merge HSM logic

## [0.1.10] - 2017-01-25

### Fixed

- Fix `derivePassphrase` for Python 2

## [0.1.9] - 2017-01-22

### Added

- Add endorsement APIs
- Add public key tweak for endorsement validation
- Compatibility with Blue firmware 2.0 (production release)

### Changed

- Speedup
- Encode correctly the passphrase in UTF8 NFKD
- Force to recompile `secp256k1` for recent pip
- Update libudev package
- Update README

### Fixed

- Fix indent errors and print function for Python 3 builds

## [0.1.8] - 2016-10-13

### Added

- Add passphrase derivation utility
- Add genuine device check script
- Support Secure Channel outgoing data
- Add Pillow dependency

### Changed

- Python 3 port with keeping Python 2 compliance
- Add received data in `CommException` object

## [0.1.7] - 2016-09-02

### Changed

- Optional `libsecp256k1` dependency, default to pure Python cryptographic API to help Windows users

### Fixed

- Fix timeout from 7 hours to expected 20 seconds

## [0.1.6] - 2016-08-12

### Fixed

- Fix PyPI update

## [0.1.5] - 2016-08-12

### Added

- Support locking on curve and multiple paths (API level 5)

## [0.1.4] - 2016-07-28

### Fixed

- Fix copy/paste error
- Mention Nano S in documentation

## [0.1.3] - 2016-07-28

### Added

- Add application signature & validation scripts
- Add standalone MCU load support
- Add SCP support
- Add locked down application path, icon, signature support
- Add boot address support, hex printer
- Nano S vendor ID support

## [0.1.2] - 2016-05-20

### Added

- Support 1.1 deployed logic
- Add experimental desktop BLE support

### Fixed

- Fix MCU firmware loading
- Fix string/number concatenation in error messages

## [0.1.1] - 2016-04-12

### Added

- Initial import
