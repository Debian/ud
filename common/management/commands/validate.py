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
from django.core.exceptions import ValidationError
from common.models import Host, Group, User

import optparse

class Command(BaseCommand):
    help = 'validate - blah blah' # TODO
    option_list = BaseCommand.option_list + (
        optparse.make_option('--quiet',
            action='store_true',
            default=False,
            help='enable quiet output'
        ),
        optparse.make_option('--verbose',
            action='store_true',
            default=False,
            help='enable verbose output'
        ),
    )

    def handle(self, *args, **options):
        self.options = options
        if args:
            for uid in args:
                user = User.objects.get(uid__exact=uid)
                self.validate_user(user)
        else:
            users = User.objects.all()
            for user in users:
                self.validate_user(user)

    def validate_user(self, user):
        try:
            user.validate()
            if self.options['verbose']:
                print 'ack:%s' % (user.uid)
        except ValidationError as err:
            if self.options['quiet']:
                print 'nak:%s' % (user.uid)
            else:
                for message in err.messages:
                    print 'nak:%s:%s' % (user.uid, message)


# vim: set ts=4 sw=4 et ai si sta:
