# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Copyright (C) 2013 Luca Filipozzi <lfilipoz@debian.org>

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from common.models import Host, Group, User
from mako.template import Template
from mako.lookup import TemplateLookup

import errno
import grp
import optparse
import os
import tarfile
import time

from StringIO import StringIO

class Command(BaseCommand):
    help = 'Generates, on a host-by-host basis, the set of files to be replicated.'

    def handle(self, *args, **options):
        self.options = options
        template_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'templates'))
        self.marshall_data()
        self.render_output()

    def marshall_data(self):

        def recurse(gids, hostname):
            _gids = set()
            for gid in gids:
                if '@' in gid:
                    if not gid.endswith(hostname):
                        continue
                    gid = gid.split('@')[0]
                _gids.add(gid)
                if gid in _gid2group:
                    _gids |= recurse(_gid2group[gid].subGroup, hostname)
            return _gids

        self.hosts = Host.objects.all()
        self.groups = Group.objects.all()
        self.users = User.objects.all()

        _gid2group = dict()
        _gidNumber2gid = dict()
        for group in self.groups:
            group.hid2users = dict()
            _gid2group[group.gid] = group
            _gidNumber2gid[group.gidNumber] = group.gid

        for host in self.hosts:
            host.users = set()
            host.groups = set()

        # pass 1: find all users in allowedGroups (or subgroup there of)
        for user in self.users:
            if user.gidNumber <= 100:
                user.gid = grp.getgrgid(user.gidNumber)[0]
            elif _gidNumber2gid.has_key(user.gidNumber):
                user.gid = _gidNumber2gid[user.gidNumber]
            else:
                continue
            user.hid2gids = dict()
            for host in self.hosts:
                host_gids = set(host.allowedGroups) | set(['adm'])
                user_gids = set([user.gid]) | recurse(user.supplementaryGid, host.hostname)
                if user_gids & host_gids or user.is_allowed_by_hostacl(host.hostname):
                    if user.is_not_retired() and user.has_active_password():
                        user.hid2gids[host.hid] = user_gids
                        host.users.add(user)

        # pass 2: ensure that for each user found, all his groups are included
        for host in self.hosts:
            for user in host.users:
                for gid in user.hid2gids[host.hid]:
                    if gid in _gid2group:
                        group = _gid2group[gid]
                        group.hid2users.setdefault(host.hid, set()).add(user)
                        host.groups.add(group)

    def render_output(self):
        template_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
        output_directory = settings.CACHE_DIR
        for host in self.hosts:
            try:
                os.makedirs(os.path.join(output_directory, host.hostname))
            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise
        r = TemplateLookup(directories=[template_directory], encoding_errors='ignore', output_encoding='utf-8')
        for template in ['group.tdb', 'passwd.tdb', 'shadow.tdb']:
            t = r.get_template(template)
            for host in self.hosts:
                with open(os.path.join(output_directory, host.hostname, template), 'w') as f:
                    f.write(t.render(host=host))
        for host in self.hosts:
            tf = tarfile.open(name=os.path.join(output_directory, host.hostname, 'ssh-keys.tar.gz'), mode='w:gz')
            for user in host.users:
                to = tarfile.TarInfo(name=user.uid)
                contents = '\n'.join(user.sshRSAAuthKey) + '\n'
                to.uid = 0
                to.gid = 65534
                to.uname = user.uid
                to.gname = user.gid
                to.mode  = 0400
                to.mtime = int(time.time())
                to.size = len(contents)
                tf.addfile(to, StringIO(contents))
            tf.close()

# vim: set ts=4 sw=4 et ai si sta:
