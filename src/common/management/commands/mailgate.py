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
# Copyright (C) 2013-2014 Luca Filipozzi <lfilipoz@debian.org>
# Copyright (C) 2013 Oliver Berger <obergix@debian.org>
# Copyright (C) 2014 Martin Zobel-Helas <zobel@debian.org>

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext as _
from common.models import DebianUser, ReplayCache

import base64
import email
import email.utils
import hashlib
import io
import optparse
import smtplib
import sys
import time

import StringIO

from datetime import datetime, timedelta
from email.encoders import encode_7or8bit
from email.generator import Generator
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import make_msgid
from email.utils import formatdate

from _handler import Handler
from _utilities import load_configuration_file, verify_message, get_user_from_fingerprint, encrypt_result

class Command(BaseCommand):
    help = _('Processes commands received in GPG-signed emails.')
    option_list = BaseCommand.option_list + (
        optparse.make_option('--console',
            action='store_true',
            default=False,
            help=_('send reply to stdout')
        ),
        optparse.make_option('--dryrun',
            action='store_true',
            default=False,
            help=_('do not commit changes')
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/mailgate.yaml',
            help=_('specify configuration file')
        ),
    )

    def handle(self, *args, **options):
        self.options = options
        try:
            load_configuration_file(self.options['config'])
            if settings.config.has_key('username'):
                if settings.config['username'].endswith(DebianUser.base_dn):
                    settings.DATABASES['ldap']['USER'] = settings.config['username']
                else:
                    settings.DATABASES['ldap']['USER'] = 'uid=%s,%s' % (settings.config['username'], DebianUser.base_dn)
            else:
                raise CommandError(_('configuration file must specify username parameter'))
            if settings.config.has_key('password'):
                settings.DATABASES['ldap']['PASSWORD'] = settings.config['password']
            else:
                raise CommandError(_('configuration file must specify password parameter'))
            message = email.message_from_file(sys.stdin)
            result = self.process_message(message)
            self.generate_reply(message, result)
        except Exception as err:
            raise CommandError(err)

    def process_message(self, message):
        (fingerprint, content, timestamp) = verify_message(message)
        self.check_replay_cache(fingerprint, content, timestamp)
        user = get_user_from_fingerprint(fingerprint)
        fd = io.StringIO()
        fd.write(u'\n===== start of processing =====\n')
        handler = Handler(fd, user, user)
        for command in content.splitlines():
            if command == '-- ':
                break
            fd.write(u'> %s\n' % (command))
            handler.onecmd(command)
        if self.options['dryrun']:
            fd.write(u'==> dryrun: no changes saved\n')
        else:
            if handler.has_errors:
                fd.write(u'==> errors: no changes saved\n')
            else:
                user.save()
        fd.write(u'===== end of processing =====\n')
        return encrypt_result(fd.getvalue().encode('utf-8'), fingerprint)

    def check_replay_cache(self, fingerprint, content, timestamp):
        digest = base64.b64encode(hashlib.sha512(content + timestamp.strftime('%Y%m%dT%H%M%S%f%z')).digest())
        for entry in ReplayCache.objects.filter(fingerprint=fingerprint):
            if entry.timestamp < datetime.now() - timedelta(days=7):
                entry.delete() # delete stale entries
        if timestamp < datetime.now() - timedelta(days=4):
            raise Exception('too far in the past')
        if timestamp > datetime.now() + timedelta(days=3):
            raise Exception('too far in the future')
        if ReplayCache.objects.filter(fingerprint=fingerprint, digest=digest):
            raise Exception('already seen!!')
        ReplayCache(fingerprint=fingerprint, timestamp=timestamp, digest=digest).save()

    def generate_reply(self, message, result):
        try:
            from_mailaddr = 'ud@db.debian.org'
            if message.get('Reply-To'):
                to = message.get('Reply-To')
                (to_realname,to_mailaddr) = email.utils.parseaddr(to)
            elif message.get('From'):
                to = message.get('From')
                (to_realname,to_mailaddr) = email.utils.parseaddr(to)
            msg = MIMEMultipart('encrypted', protocol='application/pgp-encrypted')
            msg['From'] = from_mailaddr
            msg['To'] = to
            msg['Subject'] = 'ud mailgate processing results'
            msg['Message-Id'] = make_msgid()
            msg['In-Reply-To'] = message['Message-Id']
            msg['Date'] = formatdate(localtime=True)
            msg['Content-Disposition'] = 'inline'
            part1 = MIMEApplication(_data='Version: 1\n', _subtype='pgp-encrypted', _encoder=encode_7or8bit)
            part1['Content-Disposition'] = 'attachment'
            msg.attach(part1)
            part2 = MIMEApplication(_data=result, _subtype='octet-stream', _encoder=encode_7or8bit)
            part2['Content-Disposition'] = 'inline; filename="msg.asc"'
            msg.attach(part2)
            fd = StringIO.StringIO()
            g = Generator(fd, mangle_from_=False)
            g.flatten(msg)
            if self.options['console']:
                self.stdout.write(fd.getvalue() + '\n')
            else:
                s = smtplib.SMTP('localhost')
                s.sendmail(from_mailaddr, to_mailaddr, fd.getvalue())
                s.quit()
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
