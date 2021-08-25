# Python tools for Ledger Blue, Nano S and Nano X

This package contains Python tools to communicate with Ledger Blue, Nano S and Nano X and manage applications life cycle.

It is recommended to install this package in a [Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) in your native environment (not a Docker image) to avoid hidapi issues.

```
virtualenv ledger
source ledger/bin/activate
pip install ledgerblue
```

## Supported devices 

At the moment these tools work for all Nano S and Blue devices, but only for special Nano X developer units which are not available to the general public.

Please check [Ledger Developer Portal](https://developers.ledger.com/docs/nano-app/introduction/) to see how to debug your application on a Nano X simulator using [Speculos](https://github.com/LedgerHQ/speculos)

## Installation pre-requisites


  * libudev-dev
  * libusb-1.0-0-dev
  * python-dev (python 2.7)
  * virtualenv

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
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0000", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0001", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0004", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
```

## Target ID

Use the following Target IDs (--targetId option) when running commands directly:

  * 0x31100002 on Nano S with firmware <= 1.3.1
  * 0x31100003 on Nano S with firmware 1.4.x
  * 0x31100004 on Nano S with firmware 1.5.x
  * 0x31000002 on Blue with firmware <= 2.0
  * 0x31000004 on Blue with firmware 2.1.x
  * 0x31010004 on Blue v2 with firmware 2.1.x
  * 0x33000004 on Nano X with firmware 1.x (**developer units only**)
