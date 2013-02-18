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
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from common.models import Host, Group, User

import optparse

class Command(BaseCommand):
    args = '[uid uid ...]'
    help = 'Validates all or specified users against validation rules.'

    def handle(self, *args, **options):
        self.options = options
        self.error = False
        if args:
            for uid in args:
                try:
                    user = User.objects.get(uid__exact=uid)
                    self.validate_user(user)
                except ObjectDoesNotExist:
                    self.error = True
                    if self.options['verbosity'] > '0':
                        self.stdout.write('nak:%s:uid does not exist\n' % (uid))
        else:
            users = User.objects.all()
            for user in users:
                self.validate_user(user)
        if self.error:
            raise CommandError('validation errors detected')

    def validate_user(self, user):
        try:
            user.validate()
            if self.options['verbosity'] == '2':
                self.stdout.write('ack:%s\n' % (user.uid))
        except ValidationError as err:
            self.error = True
            if self.options['verbosity'] == '0':
                self.stdout.write('nak:%s\n' % (user.uid))
            else:
                for message in err.messages:
                    self.stdout.write('nak:%s:%s\n' % (user.uid, message))
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
