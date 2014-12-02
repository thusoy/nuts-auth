#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from os import path
import sys

install_requires = [
    'itsdangerous',
    'msgpack-python',
    'pysha3',
]

if sys.version_info < (3, 4, 0):
    install_requires.append('enum34')

setup(
    name='nuts',
    version='1.0.0',
    author='Tarjei Husøy',
    author_email='pypi@thusoy.com',
    url='https://github.com/thusoy/nuts-auth',
    description='An authenticated datagram protocol. That might fly in space.',
    install_requires=install_requires,
    packages=find_packages(),
    zip_safe=False,
)
