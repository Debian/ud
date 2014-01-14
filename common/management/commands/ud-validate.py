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

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.management.base import BaseCommand, CommandError
from common.models import Host, Group, LdapUser as User

import getpass
import optparse
import ldap

from _utilities import load_configuration_file

# TODO check unicode handling
class Command(BaseCommand):
    args = '[uid uid ...]'
    help = 'Validates all or specified users against validation rules.'
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
        self.options = options

        logged_in_uid = ''

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
            self.error = False
            if args:
                for looked_up_uid in args:
                    try:
                        looked_up_user = User.objects.get(uid__exact=looked_up_uid)
                        self.validate_user(looked_up_user)
                    except ObjectDoesNotExist:
                        self.error = True
                        if options['verbosity'] > '0':
                            self.stdout.write('nak:%s:uid does not exist\n' % (uid))
            else:
                looked_up_users = User.objects.all()
                for looked_up_user in looked_up_users:
                    self.validate_user(looked_up_user)
            if self.error:
                raise CommandError('validation errors detected')
        except ObjectDoesNotExist:
            raise CommandError('user not found')
        except ldap.INVALID_CREDENTIALS:
            raise CommandError('invalid credentials')
        except Exception as err:
            raise CommandError(err)

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
