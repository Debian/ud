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
from common.models import Host, User

import optparse

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
        # marshall data
        users = User.objects.all()
        hosts = Host.objects.all()
        for host in hosts:
            host.users = []
            host_allowedGroups_set = set(host.allowedGroups)
            for user in users:
                user.hosts = []
                if host_allowedGroups_set & set(user.supplementaryGid):
                    host.users.append(user)
                    user.hosts.append(host)
        # generate output
        for host in hosts:
            self.stdout.write('%s: %s\n' % (host.hostname, ', '.join([x.uid for x in host.users])))
        # NOTE that host.users and user.hosts is not permanent and is scoped to this function only

# vim: set ts=4 sw=4 et ai si sta:
