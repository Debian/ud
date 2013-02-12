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
from common.models import User

import daemon
import optparse
import SocketServer

class FingerServer(SocketServer.TCPServer):
    allow_reuse_address = True

class FingerHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        try:
            uid = self.rfile.readline(512).strip()
            if uid.endswith('/key'):
                uid = uid[:-4]
                user = User.objects.get(uid=uid)
                if user:
                    asc = user.key
                    if asc:
                        self.wfile.write(user.dn + '\n')
                        self.wfile.write(asc)
                    else:
                        raise Exception('public key for "%s" not found at db.debian.org\n' % (uid))
                else:
                    raise Exception('ldap entry for "%s" not found at db.debian.org\n' % (uid))
            else:
                user = User.objects.get(uid=uid)
                if user:
                    self.wfile.write('%s\n' % (user.dn))
                    self.wfile.write('First name: %s\n' % (user.cn))
                    if user.mn:
                        self.wfile.write('Middle name: %s\n' % (user.mn))
                    self.wfile.write('Last name: %s\n' % (user.sn))
                    self.wfile.write('Email: %s\n' % (user.emailAddress))
                    if user.labeledURI:
                        self.wfile.write('URL: %s\n' % (user.labeledURI))
                    if user.ircNick:
                        self.wfile.write('IRC nickname: %s\n' % (user.ircNick))
                    if user.icqUin:
                        self.wfile.write('ICQ UIN: %s\n' % (user.icqUin))
                    if user.jabberJID:
                        self.wfile.write('Jabber ID: %s\n' % (user.jabberJID))
                    if user.keyFingerPrint:
                        self.wfile.write('Fingerprint: %s\n' % (user.keyFingerPrint))
                        self.wfile.write('Key block: finger %s/key@db.debian.org\n' % (user.uid))
                else:
                    raise Exception('ldap entry for "%s" not found at db.debian.org\n' % (uid))
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
    )

    def handle(self, *args, **options):
        server = FingerServer(('', 79), FingerHandler)
        if options['foreground']:
            server.serve_forever()
        else:
            with daemon.DaemonContext(): # TODO drop root
                server.serve_forever()

# vim: set ts=4 sw=4 et ai si sta:
