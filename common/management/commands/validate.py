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

import optparse

class Command(BaseCommand):
    help = 'validate - blah blah' # TODO
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
        users = User.objects.all()
        for user in users:
            try:
                user.validate()
                print 'ack:%s' % (user.uid)
            except Exception as err:
                print 'nak:%s:%s' % (user.uid, ','.join(err.messages))


# vim: set ts=4 sw=4 et ai si sta:
