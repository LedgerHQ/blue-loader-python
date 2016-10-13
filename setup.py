#from distribute_setup import use_setuptools
#use_setuptools()

from setuptools import setup, find_packages
from os.path import dirname, join
import os

here = dirname(__file__)
setup(
    name='ledgerblue',
    version='0.1.8',
    author='Ledger',
    author_email='hello@ledger.fr',
    description='Python library to communicate with Ledger Blue/Nano S',
    long_description=open(join(here, 'README.md')).read(),
    url='https://github.com/LedgerHQ/blue-loader-python',
    packages=find_packages(),
    install_requires=['hidapi>=0.7.99', 'pycrypto>=2.6.1', 'future', 'ecpy>=0.8.1', 'pillow>=3.4.0'],
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

