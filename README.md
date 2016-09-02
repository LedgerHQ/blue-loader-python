# Python tools for Ledger Blue and Nano S

This package contains Python tools to communicate with Ledger Blue and Nano S and manage applications life cycle 

It is recommended to install this package in a [Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) in your native environment (not a Docker image) to avoid hidapi issues. 

```
virtualenv ledger
source ledger/bin/activate
pip install ledgerblue
```

This package can optionally work with [libsecp256k1](https://github.com/ludbb/secp256k1-py) Python bindings compiled with ECDH support. If you wish to enable libsecp256k1 bindings, make sure to install libsecp256k1 as follows

```
SECP_BUNDLED_EXPERIMENTAL=1 pip --no-cache-dir install secp256k1
``` 

