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
from django.core.management.base import BaseCommand, CommandError
from common.models import User

import optparse
import email
import sys
import time
import yaml

from _utilities import verify_message, get_user_from_fingerprint, get_user_from_headers

class Command(BaseCommand):
    help = 'Watches for email activity from Debian Developers.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('--dryrun',
            action='store_true',
            default=False,
            help='do not commit changes'
        ),
        optparse.make_option('--config',
            action='store',
            default='',
            help='specify configuration file'
        ),
    )

    def handle(self, *args, **options):
        self.options = options
        try:
            if self.options['config']:
                config = yaml.load(open(self.options['config']))
                if config.has_key('UD_USERNAME'):
                    if config['UD_USERNAME'].endswith(User.base_dn):
                        settings.DATABASES['ldap']['USER'] = config['UD_USERNAME']
                    else:
                        settings.DATABASES['ldap']['USER'] = 'uid=%s,%s' % (config['UD_USERNAME'], User.base_dn)
                else:
                    raise CommandError('config must have UD_USERNAME parameter')
                if config.has_key('UD_PASSWORD'):
                    settings.DATABASES['ldap']['PASSWORD'] = config['UD_PASSWORD']
                else:
                    raise CommandError('config must have UD_PASSWORD parameter')
            else:
                raise CommandError('must specify --config file')
            message = email.message_from_file(sys.stdin)
            user = None
            key = ''
            val = '[%s]' % ( time.strftime("%a, %d %b %Y %H:%M:%S",time.gmtime(time.time())) )
            if not key: # determine user from signature
                try:
                    (fingerprint, ignore) = verify_message(message)
                    user = get_user_from_fingerprint(fingerprint)
                    key = 'activityPGP'
                    val += ' "%s" ' % (fingerprint)
                except:
                    pass
            if not key: # determine user from headers
                try:
                    user = get_user_from_headers(message)
                    key = 'activityFrom'
                    val += ' "%s" ' % (message.get('From'))
                except:
                    pass
            if user:
                val += ' "%s" "%s"' % (message.get('X-Mailing-List'), message.get('Message-ID'))
                if self.options['dryrun']:
                    sys.stdout.write('%s: %s\n' % (key, val))
                else:
                    user.update(key, val)
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
