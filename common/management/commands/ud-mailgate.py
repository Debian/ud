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
from django.conf import settings
from common.models import User

import optparse
import email
import email.mime.text
import email.utils
import smtplib
import sys

import cStringIO

from _handler import Handler
from _utilities import load_configuration_file, verify_message, get_user_from_fingerprint

class Command(BaseCommand):
    help = 'Processes commands received in GPG-signed emails.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('--console',
            action='store_true',
            default=False,
            help='send reply to stdout'
        ),
        optparse.make_option('--dryrun',
            action='store_true',
            default=False,
            help='do not commit changes'
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/mailgate.yaml',
            help='specify configuration file'
        ),
    )

    def handle(self, *args, **options):
        self.options = options
        try:
            load_configuration_file(self.options['config'])
            if settings.config.has_key('username'):
                if settings.config['username'].endswith(User.base_dn):
                    settings.DATABASES['ldap']['USER'] = settings.config['username']
                else:
                    settings.DATABASES['ldap']['USER'] = 'uid=%s,%s' % (settings.config['username'], User.base_dn)
            else:
                raise CommandError('configuration file must specify username parameter')
            if settings.config.has_key('password'):
                settings.DATABASES['ldap']['PASSWORD'] = settings.config['password']
            else:
                raise CommandError('configuration file must specify password parameter')
            message = email.message_from_file(sys.stdin)
            (fingerprint, commands) = verify_message(message)
            user = get_user_from_fingerprint(fingerprint)
            fd = cStringIO.StringIO()
            handler = Handler(fd, user, user)
            for command in commands:
                if command == '-- ':
                    break
                fd.write('> %s\n' % (command))
                handler.onecmd(command)
            if self.options['dryrun']:
                fd.write('==> dryrun: no changes saved')
            else:
                if handler.has_errors:
                    fd.write('==> errors: no changes saved')
                else:
                    user.save()
            self.generate_reply(message, fd.getvalue())
        except Exception as err:
            raise CommandError(err)

    def generate_reply(self, message, result):
        from_mailaddr = 'ud@db.debian.org'
        if message.get('Reply-To'):
            to = message.get('Reply-To')
            (to_realname,to_mailaddr) = email.utils.parseaddr(to)
        elif message.get('From'):
            to = message.get('From')
            (to_realname,to_mailaddr) = email.utils.parseaddr(to)
        msg = email.mime.text.MIMEText(result)
        msg['From'] = from_mailaddr
        msg['To'] = to
        msg['Subject'] = 'ud-mailgate processing results'
        if self.options['console']:
            self.stdout.write(msg.as_string() + '\n')
        else:
            s = smtplib.SMTP('localhost')
            s.sendmail(from_mailaddr, to_mailaddr, msg.as_string())
            s.quit()


# vim: set ts=4 sw=4 et ai si sta:
