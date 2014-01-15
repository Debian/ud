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

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from common.models import Host, LdapUser as User

import getpass
import ldap
import optparse
import os

from _handler import Handler
from _utilities import load_configuration_file

class Command(BaseCommand):
    args = '<hid>'
    help = 'Provides an interactive attribute editor for Host entries.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('-D', '--binddn',
            action='store',
            default='',
            help='specify bind dn'
        ),
        optparse.make_option('-w', '--passwd',
            action='store',
            default='',
            help='specify passwd'
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/interactive.yaml',
            help='specify configuration file'
        ),  
    )

    def handle(self, *args, **options):
        logged_in_uid = ''
        lookup_up_hid = ''

        if len(args) == 1:
            lookup_up_hid = args[0]
        else:
            raise CommandError('must specify at most one hid as argument')

        try:
            load_configuration_file(options['config'])
        except Exception as err:
            raise CommandError(err)

        if not options['binddn']:
            options['binddn'] = getpass.getuser()
        if options['binddn'].endswith(User.base_dn):
            settings.DATABASES['ldap']['USER'] = options['binddn']
            logged_in_uid = options['binddn'].split(',')[0].split('=')[0]
        else:
            settings.DATABASES['ldap']['USER'] = 'uid=%s,%s' % (options['binddn'], User.base_dn)
            logged_in_uid = options['binddn']

        if not options['passwd']:
            try:
                options['passwd'] = getpass.getpass()
            except EOFError:
                self.stdout.write('\n')
                return
        if not options['passwd']:
            raise CommandError('must specify password')
        settings.DATABASES['ldap']['PASSWORD'] = options['passwd']

        try:
            logged_in_user = User.objects.get(uid=logged_in_uid)
            lookup_up_host = Host.objects.get(hid=lookup_up_hid)
            if 'adm' in logged_in_user.supplementaryGid:
                Handler(self.stdout, lookup_up_host, logged_in_user).cmdloop()
            else:
                raise CommandError('insufficient privileges')
        except ObjectDoesNotExist:
            raise CommandError('host not found')
        except ldap.INVALID_CREDENTIALS:
            raise CommandError('invalid credentials')
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
