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
from common.models import Host, Group, User
from mako.template import Template
from mako.lookup import TemplateLookup

import errno
import optparse
import os

class Command(BaseCommand):
    help = 'generate - blah blah' # TODO
    option_list = BaseCommand.option_list + (
        optparse.make_option('--console',
            action='store_true',
            default=False,
            help='send output to console'
        ),
        optparse.make_option('--dryrun',
            action='store_true',
            default=False,
            help='do not commit changes'
        ),
    )

    def handle(self, *args, **options):
        self.options = options
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
            user.gid = _gidNumber2gid.get(user.gidNumber)
            user.hid2gids = dict()
            for host in self.hosts:
                host_gids = set(host.allowedGroups) | set(['adm'])
                user_gids = set([user.gid]) | recurse(user.supplementaryGid, host.hostname)
                user.hid2gids[host.hid] = user_gids
                if user_gids & host_gids or user.is_allowed_by_hostacl(host.hostname):
                    if user.is_not_retired() and user.has_active_password():
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
        template_directory = '/home/lfilipoz/dev/ud/common/templates' # FIXME
        output_directory = '/tmp/ud' # FIXME
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


# vim: set ts=4 sw=4 et ai si sta:
