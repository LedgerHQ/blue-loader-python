# Python tools for Ledger Blue and Nano S

This package contains Python tools to communicate with Ledger Blue and Nano S and manage applications life cycle 

It is recommended to install this package in a [Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) in your native environment (not a Docker image) to avoid hidapi issues. 

```
virtualenv ledger
source ledger/bin/activate
pip install ledgerblue
```

## Installation pre-requisites


  * libudev
  * libusb-1.0-0-dev 
  * python-dev (python 2.7)
  * virtualenv

This package can optionally work with [libsecp256k1](https://github.com/ludbb/secp256k1-py) Python bindings compiled with ECDH support. If you wish to enable libsecp256k1 bindings, make sure to install libsecp256k1 as follows

```
SECP_BUNDLED_EXPERIMENTAL=1 pip --no-cache-dir install secp256k1
``` 

## Giving permissions on udev 

When running on Linux, make sure the following rules have been added to /etc/udev/rules.d/

```
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0000", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", ATTRS{idProduct}=="0001", MODE="0660", TAG+="uaccess", TAG+="udev-acl" OWNER="<UNIX username>"

```

## Target ID

Use the following Target IDs (--targetId option) when running commands directly 

  * 0x31100002 on Nano S
  * 0x31000002 on Blue 

