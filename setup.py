# coding=utf-8

# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2012, Spanish National Research Council
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Setuptools script which defines an entry point which can be used for Keystone
filter later.
"""

from setuptools import setup


setup(
    name='keystone_ldap_ro',
    version='2012.3-1',
    description='Keystone LDAP auth module for Keystone (grizzly).',
    long_description=("TBD"),
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 5 - Production/Stable',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        ],
    keywords='',
    author='Spanish National Research Council',
    author_email='aloga@ifca.unican.es',
    url='https://github.com/IFCA/keystone-ldap-ro',
    license='Apache License, Version 2.0',
    include_package_data=True,
    packages=['keystone_ldap_ro'],
    zip_safe=False,
    install_requires=[
        'setuptools',
        ],
    entry_points='''
[paste.filter_factory]
ldap_ro = keystone_ldap_ro:LDAPAuthROMiddleware.factory
''',
)
