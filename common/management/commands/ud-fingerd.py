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
from common.models import LdapUser as User

import daemon
import io
import optparse
import yaml

import SocketServer

from _utilities import load_configuration_file

class FingerServer(SocketServer.TCPServer):
    allow_reuse_address = True

class FingerHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        try:
            fd = io.StringIO(encoding='utf-8')
            uid = self.rfile.readline(512).strip()
            if uid.endswith('/key'):
                uid = uid[:-4]
                user = User.objects.get(uid=uid)
                if user:
                    asc = user.key
                    if asc:
                        fd.write(user.dn + '\n')
                        fd.write(asc)
                    else:
                        raise Exception('public key for "%s" not found at db.debian.org\n' % (uid))
                else:
                    raise Exception('ldap entry for "%s" not found at db.debian.org\n' % (uid))
            else:
                user = User.objects.get(uid=uid)
                if user:
                    fd.write(u'%s\n' % (user.dn))
                    fd.write(u'First name: %s\n' % (user.cn))
                    if user.mn:
                        fd.write(u'Middle name: %s\n' % (user.mn))
                    fd.write(u'Last name: %s\n' % (user.sn))
                    fd.write(u'Email: %s\n' % (user.emailAddress))
                    if user.labeledURI:
                        fd.write(u'URL: %s\n' % (user.labeledURI))
                    if user.ircNick:
                        fd.write(u'IRC nickname: %s\n' % (user.ircNick))
                    if user.icqUin:
                        fd.write(u'ICQ UIN: %s\n' % (user.icqUin))
                    if user.jabberJID:
                        fd.write(u'Jabber ID: %s\n' % (user.jabberJID))
                    if user.keyFingerPrint:
                        fd.write(u'Fingerprint: %s\n' % (user.keyFingerPrint))
                        fd.write(u'Key block: finger %s/key@db.debian.org\n' % (user.uid))
                else:
                    raise Exception('ldap entry for "%s" not found at db.debian.org\n' % (uid))
            self.wfile.write(fd.getvalue().encode('utf-8'))
        except Exception as err:
            self.wfile.write(err)

class Command(BaseCommand):
    help = 'Provides a finger daemon.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('--foreground',
            action='store_true',
            default=False,
            help='run in the foreground'
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/fingerd.yaml',
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
            server = FingerServer(('', 79), FingerHandler)
            if self.options['foreground']:
                server.serve_forever()
            else:
                with daemon.DaemonContext(): # TODO drop root
                    server.serve_forever()
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
