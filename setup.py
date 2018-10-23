from os.path import join, dirname

from setuptools import setup, find_packages

setup(name='sonm_pynode',
      version='0.0.4',
      description='wrapper for AES-encrypted REST API provided by SONM Node',
      author='sshaman1101',
      long_description=open(join(dirname(__file__), 'README')).read(),
      url='https://github.com/abefimov/sonm-pynode',
      packages=['sonm_pynode'],
      install_requires=[
          'Crypto',
          'cytoolz==0.9.0.1',
          'ecdsa==0.13',
          'eth-hash==0.2.0',
          'eth-keyfile==0.5.1',
          'eth-keys==0.2.0b3',
          'eth-typing==2.0.0',
          'eth-utils==1.3.0b0',
          'pycryptodome==3.6.6',
          'toolz==0.9.0']
      )
