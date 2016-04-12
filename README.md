# Python tools for Ledger Blue

This package contains Python tools to communicate with Ledger Blue and manage applications life cycle 

The life cycle management requires [libsecp256k1](https://github.com/ludbb/secp256k1-py) Python bindings compiled with ECDH support. It is recommended to install this package in a [Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) in your native environment (not a Docker image) through 

```
virtualenv ledger
source ledger/bin/activate
SECP_BUNDLED_EXPERIMENTAL=1 pip install secp256k1
pip install git+https://github.com/LedgerHQ/blue-loader-python.git 
```

