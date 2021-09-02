#from distribute_setup import use_setuptools
#use_setuptools()

from setuptools import setup, find_packages
from os.path import dirname, join
import os

here = dirname(__file__)
setup(
    name='ledgerblue',
    version='0.1.36',
    author='Ledger',
    author_email='hello@ledger.fr',
    description='Python library to communicate with Ledger Blue/Nano S',
    long_description=open(join(here, 'README.md')).read(),
    url='https://github.com/LedgerHQ/blue-loader-python',
    packages=find_packages(),
    install_requires=['hidapi>=0.7.99', 'protobuf>=2.6.1', 'pycryptodomex>=3.6.1', 'future', 'ecpy>=0.9.0', 'pillow>=3.4.0', 'python-u2flib-host>=3.0.2', 'websocket_client>=0.56.0'],
    extras_require = {
	'smartcard': [ 'python-pyscard>=1.6.12-4build1' ]
    },
    include_package_data=True,
    zip_safe=False,
    classifiers=[
	'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
	'Operating System :: MacOS :: MacOS X'
    ]
)

