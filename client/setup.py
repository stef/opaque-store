#!/usr/bin/env python

# SPDX-FileCopyrightText: 2024, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os
#from distutils.core import setup, Extension
from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name = 'opaquestore',
      version = '0.3.0',
      description = 'Simple Online secret-storage based on the OPAQUE protocol',
       license = "GPLv3",
       author = 'Stefan Marsiske',
      author_email = 'opaque@ctrlc.hu',
      url = 'https://github.com/stef/opaque-store/',
       long_description=read('README.md'),
       long_description_content_type="text/markdown",
      packages = ['opaquestore'],
      install_requires = ("pysodium", "SecureString", "opaque","zxcvbn-python", 'pyoprf'),
       classifiers = ["Development Status :: 4 - Beta",
                      "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
                      "Topic :: Security :: Cryptography",
                      "Topic :: Security",
                   ],
       entry_points = {
           'console_scripts': [
              'opaquestore = opaquestore.client:main'
           ],
       },
)
