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
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from common.models import User

import getpass
import ldap
import optparse
import os

from _handler import Handler

class Command(BaseCommand):
    args = '[uid]'
    help = 'Provides an interactive attribute editor.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('-D', '--binddn',
            action='store',
            default='',
            help='specify bind dn'
        ),
        optparse.make_option('-w', '--password',
            action='store',
            default='',
            help='specify password'
        ),
    )

    def handle(self, *args, **options):
        logged_in_uid = ''
        looked_up_uid = ''
        if len(args) == 0:
            # if a uid is not specified as a command line argument,
            # use the local user's username as the looked_up_uid
            # since this is probably being run on a debian machine
            looked_up_uid = getpass.getuser()
        elif len(args) == 1:
            # if a uid is specified on the command line, use that
            looked_up_uid = args[0]
        else:
            raise CommandError('must specify at most one uid as argument')
        if not options['binddn']:
            # if a binddn is not specified as a command line option,
            # use the value for looked_up_uid as determined above
            options['binddn'] = looked_up_uid
        if options['binddn'].endswith(User.base_dn):
            settings.DATABASES['ldap']['USER'] = options['binddn']
            logged_in_uid = options['binddn'].split(',')[0].split('=')[0]
        else:
            # unlike ldapsearch and friends, allow the user to be
            # lazy and specify just the uid rather than the full dn,
            # or even to not specify the uid (see above getuser())
            settings.DATABASES['ldap']['USER'] = 'uid=%s,%s' % (options['binddn'], User.base_dn)
            logged_in_uid = options['binddn']
        if not options['password']:
            try:
                options['password'] = getpass.getpass()
            except EOFError:
                self.stdout.write('\n')
                return
        if not options['password']:
            raise CommandError('must specify password')
        settings.DATABASES['ldap']['PASSWORD'] = options['password']
        try:
            logged_in_user = User.objects.get(uid=logged_in_uid)
            looked_up_user = User.objects.get(uid=looked_up_uid)
            if logged_in_user.dn is looked_up_user.dn or 'adm' in logged_in_user.supplementaryGid:
                Handler(self.stdout, looked_up_user).cmdloop() # TODO pass logged_in_user, too
            else:
                # LDAP acls provide the 'real' protection but let's
                # dump out early rather than launching the Handler
                raise CommandError('insufficient privileges')
        except ObjectDoesNotExist:
            raise CommandError('user not found')
        except ldap.INVALID_CREDENTIALS:
            raise CommandError('invalid credentials')
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
