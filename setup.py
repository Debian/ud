# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along along
# with this program; if not, write to the
#
#   Free Software Foundation, Inc.
#   51 Franklin Street - Fifth Floor
#   Boston MA  02110-1301
#   USA
#
# Copyright (C) 2013 Luca Filipozzi <lfilipoz@debian.org>

from distutils.core import setup

setup(
    name = 'ud',
    version = '1.0',
    description = 'a reimplementation of Debian\'s userdir-ldap, leveraging the Django framework',
    author = 'Luca Filipozzi',
    author_email = 'lfilipoz@debian.org',
    url = 'https://github.com/LucaFilipozzi/ud',
    package_dir = {'ud': 'src'},
    packages = ['ud', 'ud.common', 'ud.common.management', 'ud.common.management.commands'],
    package_data = {'ud.common.management.commands': ['templates/*']},
    data_files = [('/etc/ud', ['src/echelon.yaml', 'src/fingerd.yaml', 'src/generate.yaml', 'src/interactive.yaml', 'src/mailgate.yaml'])],
    scripts = ['src/ud'],
)
