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
from ldapdb.models.fields import CharField, IntegerField, ListField
from common.models import User

import optparse
import os

from _handler import Handler

class Command(BaseCommand):
    args = '<uid>'
    help = 'Provides an interactive attribute editor.'

    def handle(self, *args, **options):
        if os.geteuid() != 0:
            raise CommandError('must be run as root')
        if len(args) != 1:
            raise CommandError('specify one uid as argument')
        user = User.objects.get(uid=args[0])
        if not user:
            raise CommandError('user not found')
        Handler(self.stdout, user).cmdloop()


# vim: set ts=4 sw=4 et ai si sta:
