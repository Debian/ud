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
from common.models import Host, Group, User
from mako.template import Template
from mako.lookup import TemplateLookup

import cdb
import errno
import grp
import json
import lockfile
import optparse
import os
import posix
import tarfile
import time

from cStringIO import StringIO

class Command(BaseCommand):
    help = 'Generates, on a host-by-host basis, the set of files to be replicated.'

    def handle(self, *args, **options):
        self.options = options
        self.dstdir = settings.CACHE_DIR
        self.tpldir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
        self.finder = TemplateLookup(directories=[self.tpldir], encoding_errors='ignore', output_encoding='utf-8')
        lock = lockfile.FileLock(os.path.join(self.dstdir, 'ud-generate'))
        try:
            lock.acquire(timeout=5)
        except lockfile.AlreadyLocked as err:
            raise CommandError('the lockfile is already locked')
        except lockfile.LockFailed as err:
            raise CommandError('locking the lockfile failed')
        except lockfile.LockTimeout as err:
            raise CommandError('timed out waiting to lock the lockfile')
        try:
            # TODO need_update = ...
            # TODO if need_update:
            # TODO     with open(os.path.join(self.dstdir, 'last_update.trace'), 'w') as tf:
            self.marshall()
            self.generate()
            #               tf.write(...)
        except:
            raise CommandError('something failed')
        finally:
            lock.release()

    def marshall(self):

        def recurse(gids, hostname):
            _gids = set()
            for gid in gids:
                if '@' in gid:
                    if not gid.endswith(hostname):
                        continue
                    gid = gid.split('@')[0]
                _gids.add(gid)
                if gid in _gid2group:
                    _gids |= recurse(_gid2group[gid].subGroup, hostname)
            return _gids

        self.hosts = Host.objects.all()
        self.groups = Group.objects.all()
        self.users = User.objects.all()

        _gid2group = dict()
        _gidNumber2gid = dict()
        for group in self.groups:
            group.hid2users = dict()
            _gid2group[group.gid] = group
            _gidNumber2gid[group.gidNumber] = group.gid

        for host in self.hosts:
            host.users = set()
            host.groups = set()

        # pass 1: find all users in allowedGroups (or subgroup there of)
        for user in self.users:
            if user.gidNumber <= 100:
                user.gid = grp.getgrgid(user.gidNumber)[0]
            elif user.gidNumber in _gidNumber2gid:
                user.gid = _gidNumber2gid[user.gidNumber]
            else:
                continue # TODO error ... log? raise?
            user.hid2gids = dict()
            for host in self.hosts:
                host_gids = set(host.allowedGroups) | set(['adm'])
                user_gids = set([user.gid]) | recurse(user.supplementaryGid, host.hostname)
                if user_gids & host_gids or user.is_allowed_by_hostacl(host.hostname):
                    if user.is_not_retired() and user.has_active_password():
                        user.hid2gids[host.hid] = user_gids
                        host.users.add(user)

        # pass 2: ensure that for each user found, all his groups are included
        for host in self.hosts:
            for user in host.users:
                for gid in user.hid2gids[host.hid]:
                    if gid in _gid2group:
                        group = _gid2group[gid]
                        group.hid2users.setdefault(host.hid, set()).add(user)
                        host.groups.add(group)

    def generate(self):
        dstdir = self.dstdir
        self.makedirs(dstdir)

        # accounts = filter(lambda x: not IsRetired(x), accounts)
        # equivalent filter: user.is_not_retired()
        self.generate_tpl_file(dstdir, 'disabled-accounts', self)
        self.generate_tpl_file(dstdir, 'mail-disable', self)
        self.generate_cdb_file(dstdir, 'mail-forward.cdb', self, 'emailForward')
        self.generate_cdb_file(dstdir, 'mail-contentinspectionaction.cdb', self, 'mailContentInspectionAction')
        self.generate_tpl_file(dstdir, 'debian-private', self)
        self.generate_tpl_file(dstdir, 'authorized_keys', self)     # FIXME hard-coded path in template ... could use settings.CACHE_DIR?
        self.generate_tpl_file(dstdir, 'mail-greylist', self)
        self.generate_tpl_file(dstdir, 'mail-callout', self)
        self.generate_tpl_file(dstdir, 'mail-rbl', self)
        self.generate_tpl_file(dstdir, 'mail-rhsbl', self)
        self.generate_tpl_file(dstdir, 'mail-whitelist', self)
        self.generate_tpl_file(dstdir, 'web-passwords', self)
        # TODO GenVoipPassword(accounts, global_dir + "voip-passwords")
        self.generate_tpl_file(dstdir, 'forward-alias', self)
        with open(os.path.join(dstdir, 'all-accounts.json'), 'w') as f:
            data = list()
            for user in self.users:
                if user.is_not_retired():
                    active = user.has_active_password() and not user.has_expired_password()
                    data.append({'uid':user.uid, 'uidNumber':user.uidNumber, 'active':active})
            json.dump(data, f, sort_keys=True, indent=4, separators=(',',':'))

        # accounts = filter(lambda a: not a in accounts_disabled, accounts)
        # equivalent filter: user.is_not_retired() and user.has_active_password()
        self.generate_tpl_file(dstdir, 'markers', self)             # FIXME wrong count of users... check filter
        # TODO GenSSHKnown(host_attrs, global_dir + "ssh_known_hosts")
        # TODO GenHosts(host_attrs, global_dir + "debianhosts")
        # TODO GenDNS(accounts, global_dir + "dns-zone")
        # TODO GenZoneRecords(host_attrs, global_dir + "dns-sshfp")
        # TODO GenSSHGitolite(accounts, global_dir + "ssh-gitolite")
        # TODO GenKeyrings(global_dir)

        for host in self.hosts:
            self.generate_host(host)

    def generate_host(self, host):
        dstdir = os.path.join(self.dstdir, host.hostname)
        self.makedirs(dstdir)

        self.generate_tpl_file(dstdir, 'passwd.tdb', host)          # FIXME if 'NOPASSWD' in ExtraList: x vs * in template
        self.generate_tpl_file(dstdir, 'group.tdb', host)
        # TODO GenShadowSudo(accounts, OutDir + "sudo-passwd", ('UNTRUSTED' in ExtraList) or ('NOPASSWD' in ExtraList), current_host)
        self.generate_tpl_file(dstdir, 'shadow.tdb', host) # if not 'NOPASSWD' in ExtraList:
        self.generate_cdb_file(dstdir, 'user-forward.cdb', host, 'emailForward')
        self.generate_cdb_file(dstdir, 'batv-tokens.cdb', host, 'bATVToken')
        self.generate_cdb_file(dstdir, 'default-mail-options.cdb', host, 'mailDefaultOptions')

        self.link(self.dstdir, dstdir, 'disabled-accounts')
        self.link(self.dstdir, dstdir, 'mail-disable')
        self.link(self.dstdir, dstdir, 'mail-forward.cdb')
        self.link(self.dstdir, dstdir, 'mail-contentinspectionaction.cdb')
        # TODO self.link(self.dstdir, dstdir, 'debian-private', ('PRIVATE' not in host.extraOptions))
        self.link(self.dstdir, dstdir, 'authorized_keys', ('AUTHKEYS' in host.extraOptions))
        self.link(self.dstdir, dstdir, 'mail-greylist')
        self.link(self.dstdir, dstdir, 'mail-callout')
        self.link(self.dstdir, dstdir, 'mail-rbl')
        self.link(self.dstdir, dstdir, 'mail-rhsbl')
        self.link(self.dstdir, dstdir, 'mail-whitelist')
        # TODO self.link(self.dstdir, dstdir, 'web-passwords', ('WEB-PASSWORDS' not in host.extraOptions))
        # TODO self.link(self.dstdir, dstdir, 'voip-passwords', ('VOIP-PASSWORDS' not in host.extraOptions))
        self.link(self.dstdir, dstdir, 'forward-alias')
        self.link(self.dstdir, dstdir, 'all-accounts.json')

        self.link(self.dstdir, dstdir, 'markers', ('NOMARKERS' not in host.extraOptions))
        # TODO self.link(self.dstdir, dstdir, 'ssh_known_hosts')
        # TODO self.link(self.dstdir, dstdir, 'debianhosts')
        # TODO self.link(self.dstdir, dstdir, 'dns-zone', ('DNS' in host.extraOptions))
        # TODO self.link(self.dstdir, dstdir, 'dns-sshfp', ('DNS' in host.extraOptions))
        # TODO self.generate_tpl_file(dstdir, 'bsmtp', host, ('BSMTP' in host.extraOptions))
        # TODO self.link(self.dstdir, dstdir, 'ssh-gitolite', ('GITOLITE' in host.extraOptions))
        # TODO keyring stuff

        # TODO self.link(self.dstdir, dstdir, 'last_update.trace')

        tf = tarfile.open(name=os.path.join(self.dstdir, host.hostname, 'ssh-keys.tar.gz'), mode='w:gz')
        for user in host.users:
            to = tarfile.TarInfo(name=user.uid)
            contents = '\n'.join(user.sshRSAAuthKey) + '\n'         # FIXME handle allowed_hosts
            to.uid = 0
            to.gid = 65534
            to.uname = user.uid # XXX the magic happens here
            to.gname = user.gid # XXX the magic happens here
            to.mode  = 0400
            to.mtime = int(time.time())
            to.size = len(contents)
            tf.addfile(to, StringIO(contents))
        tf.close()

    def makedirs(self, path):
        try:
            os.makedirs(path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

    def link(self, srcdir, dstdir, filename, guard=True):
        if guard:
            try:
                posix.remove(os.path.join(dstdir, filename))
            except:
                pass
            posix.link(os.path.join(srcdir, filename), os.path.join(dstdir, filename))

    def generate_tpl_file(self, dstdir, template, instance, guard=True):
        if guard:
            t = self.finder.get_template(template)
            with open(os.path.join(dstdir, template), 'w') as f:
                f.write(t.render(instance=instance))

    def generate_cdb_file(self, dstdir, filename, instance, key, guard=True):
        if guard:
            fn = os.path.join(dstdir, filename).encode('ascii', 'ignore')
            maker = cdb.cdbmake(fn, fn + '.tmp')
            for user in instance.users:
                if user.is_not_retired():                           # FIXME really?
                    val = getattr(user, key)
                    if val:
                        maker.add(user.uid, val)
            maker.finish()

# vim: set ts=4 sw=4 et ai si sta:
