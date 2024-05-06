# Ledgerblue - Python tools for Ledger devices

This package contains Python tools to communicate with Ledger devices and manage applications life cycle.

## Installation

It is recommended to install this package in a [Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) in your native environment (not a Docker image) to avoid hidapi issues.

```
python3 -m venv ledger
source ledger/bin/activate
pip install ledgerblue
```

## Supported devices

At the moment these tools work for all ledger devices, but only for special Nano X developer units which are not available to the general public.
The Recover scripts, will work with Nano X starting from a specific version.

Please check [Ledger Developer Portal](https://developers.ledger.com/docs/nano-app/introduction/) to see how to debug your application on a Nano X simulator using [Speculos](https://github.com/LedgerHQ/speculos)

## Installation pre-requisites


  * libudev-dev
  * libusb-1.0-0-dev
  * python-dev (python >= 3.6)

This package can optionally work with [libsecp256k1](https://github.com/ludbb/secp256k1-py) Python bindings compiled with ECDH support. If you wish to enable libsecp256k1 bindings, make sure to install libsecp256k1 as follows:

```
SECP_BUNDLED_EXPERIMENTAL=1 pip --no-cache-dir install --no-binary secp256k1 secp256k1
```

To install the custom secp256k1 package on MacOS, you previously need to run:
```
brew install libtool
```
Which would end up installing glibtool and glibtoolize utilities required for the build process.

## Giving permissions on udev

When running on Linux, make sure the following rules have been added to `/etc/udev/rules.d/`:

```
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"

KERNEL=="hidraw*", ATTRS{idVendor}=="2c97", MODE="0660" OWNER="<UNIX username>"
```

## Target ID

Use the following Target IDs (--targetId option) when running commands directly:


| Device name      | Firmware Version                   | Target ID    |
|------------------|------------------------------------|--------------|
| `Flex`           | all                                | `0x33300004` |
| `Stax`           | all                                | `0x33200004` |
| `Nano S Plus`    | all                                | `0x33100004` |
| `Nano X`         | (**developer units only**)         | `0x33000004` |
| `Nano S`         | <= 1.3.1                           | `0x31100002` |
| `Nano S`         | 1.4.x                              | `0x31100003` |
| `Nano S`         | \>= 1.5.x                          | `0x31100004` |
| `Ledger Blue`    | <= 2.0                             | `0x31000002` |
| `Ledger Blue`    | 2.1.x                              | `0x31000004` |
| `Ledger Blue v2` | 2.1.x                              | `0x31010004` |


## Ledgerblue documentation

You can generate the Ledgerblue documentation locally.

Firstly, make sure you have [pip installed](https://pip.pypa.io/en/stable/installing/) and `make`
installed.

Then, install the documentation dependencies:

```bash
# from the top of the Git repository
pip install .[doc]
```

Finally, generate the documentation:

```bash
# from the top of the Git repository
(cd doc/ && make html)
```

The documentation will be generated into the `doc/build/` directory.
