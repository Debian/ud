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
from common.models import DebianUser

import daemon
import grp
import io
import optparse
import pwd
import sys
import yaml

import SocketServer

from _utilities import load_configuration_file

class GenericHandler(object):
    def handle(self, uid):
        try:
            fd = io.StringIO()
            if uid.endswith('/key'):
                uid = uid[:-4]
                try:
                    user = DebianUser.objects.get(uid=uid)
                except:
                    raise Exception('ldap entry for "%s" not found at db.debian.org' % (uid))
                key = user.key
                if key:
                    fd.write(u'%s\n' %(user.dn))
                    fd.write(u'%s\n' %(key))
                else:
                    raise Exception('public key for "%s" not found at db.debian.org' % (uid))
            else:
                try:
                    user = DebianUser.objects.get(uid=uid)
                except:
                    raise Exception('ldap entry for "%s" not found at db.debian.org' % (uid))
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
            return fd.getvalue()
        except Exception as err:
            return u'%s\n' % (err)

class FingerHandler(SocketServer.StreamRequestHandler, GenericHandler):
    def handle(self):
        try:
            uid = self.rfile.readline(512).strip()
            self.wfile.write(GenericHandler.handle(self, uid).encode('utf-8'))
        except Exception as err:
            self.wfile.write(err)

class FingerServer(SocketServer.TCPServer):
    allow_reuse_address = True

class Command(BaseCommand):
    help = _('Provides a finger daemon.')
    option_list = BaseCommand.option_list + (
        optparse.make_option('--inetd',
            action='store_true',
            default=False,
            help=_('run from inetd')
        ),  
        optparse.make_option('--foreground',
            action='store_true',
            default=False,
            help=_('run in the foreground')
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/fingerd.yaml',
            help=_('specify configuration file')
        ),
    )

    def handle(self, *args, **options):
        self.options = options
        try:
            load_configuration_file(self.options['config'])
            if self.options['inetd']:
                try:
                    handler = GenericHandler()
                    uid = sys.stdin.readline(512).strip()
                    sys.stdout.write(handler.handle(uid).encode('utf-8'))
                except Exception as err:
                    sys.stdout.write(u'error has occured\n'.encode('utf-8'))
                finally:
                    sys.stdout.flush()
            else: # run as daemon
                server = FingerServer(('', 79), FingerHandler)
                if self.options['foreground']:
                    server.serve_forever()
                else:
                    with daemon.DaemonContext(uid=pwd.getpwnam('nobody').pw_uid, gid=grp.getgrnam('nogroup').gr_gid):
                        server.serve_forever()
        except Exception as err:
            raise CommandError(err)


# vim: set ts=4 sw=4 et ai si sta:
