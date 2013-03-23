#!/usr/bin/env python

from setuptools import setup, find_packages
import txboxdotnet
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.txt')).read()
except IOError: readme = ''

setup(

	name = 'txboxdotnet', # just trying to mimic tx* naming convention
	version = txboxdotnet.__version__,
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = [
		'boxdotnet', 'box', 'box.net', 'box.com', 'twisted'
		'async', 'api', 'rest', 'json', 'storage', 'storage provider', 'file hosting' ],
	url = 'https://github.com/mk-fg/txboxdotnet',

	description = 'Twisted-based async interface for Box (box.net) API v2.0',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: Plugins',
		'Framework :: Twisted',
		'Intended Audience :: Developers',
		'Intended Audience :: Information Technology',
		'License :: OSI Approved',
		'Operating System :: OS Independent',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Internet',
		'Topic :: System :: Archiving',
		'Topic :: System :: Filesystems' ],

	install_requires = ['Twisted >= 12.2.0'],

	packages = find_packages(),
	include_package_data = True,
	package_data = {'': ['README.txt']},
	exclude_package_data = {'': ['README.*']} )
