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
# Copyright (C) 2013 Martin Zobel-Helas <zobel@debian.org>

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connections
from common.models import Host, Group, User
from mako.lookup import TemplateLookup
from mako.template import Template

import cdb
import errno
import grp
import json
import ldap
import lockfile
import optparse
import os
import posix
import tarfile
import time
import yaml

from StringIO import StringIO

# TODO check unicode handling
class Command(BaseCommand):
    help = 'Generates, on a host-by-host basis, the set of files to be replicated.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('--force',
            action='store_true',
            default=False,
            help='force generate'
        ),
    )

    def handle(self, *args, **options): # TODO load_configuration_file
        self.options = options
        self.dstdir = os.path.join(settings.CACHE_DIR, 'hosts')
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
            if self.need_update() or self.options['force']:
                with open(os.path.join(self.dstdir, 'last_update.trace'), 'w') as f:
                    self.marshall()
                    self.generate()
                    f.write(yaml.dump({'last_ldap_mod': self.last_ldap_mod, 'last_generate': int(time.time())}))
        except Exception as err:
            raise CommandError(err)
        finally:
            lock.release()

    def need_update(self):
        query = '(&(&(!(reqMod=activity-from*))(!(reqMod=activity-pgp*)))(|(reqType=add)(reqType=delete)(reqType=modify)(reqType=modrdn)))'
        mods = connections['ldap'].cursor().connection.search_s('cn=log', ldap.SCOPE_ONELEVEL, query, ['reqEnd'])
        self.last_ldap_mod = long(max([mod[1]['reqEnd'] for mod in mods])[0].split('.')[0])
        try:
            with open(os.path.join(self.dstdir, 'last_update.trace'), 'r') as f:
                y = yaml.load(f)
                if y:
                    return self.last_ldap_mod > y.get('last_ldap_mod', 0) # TODO or last_unix_mod > y.get('last_unix_mod')
                else:
                    return True
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise err
        return True
        
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

        self.generate_tpl_file(dstdir, 'disabled-accounts', users=self.users)
        self.generate_tpl_file(dstdir, 'mail-disable', users=self.users)
        self.generate_cdb_file(dstdir, 'mail-forward.cdb', 'emailForward', users=self.users)
        self.generate_cdb_file(dstdir, 'mail-contentinspectionaction.cdb', 'mailContentInspectionAction', users=self.users)
        self.generate_tpl_file(dstdir, 'debian-private', users=self.users)
        self.generate_tpl_file(dstdir, 'authorized_keys', users=self.users, hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'mail-greylist', users=self.users)
        self.generate_tpl_file(dstdir, 'mail-callout', users=self.users)
        self.generate_tpl_file(dstdir, 'mail-rbl', users=self.users)
        self.generate_tpl_file(dstdir, 'mail-rhsbl', users=self.users)
        self.generate_tpl_file(dstdir, 'mail-whitelist', users=self.users)
        self.generate_tpl_file(dstdir, 'web-passwords', users=self.users)
        self.generate_tpl_file(dstdir, 'voip-passwords', users=self.users)
        self.generate_tpl_file(dstdir, 'forward-alias', users=self.users)
        self.generate_tpl_file(dstdir, 'markers', users=self.users)     # FIXME double check user filter
        self.generate_tpl_file(dstdir, 'ssh_known_hosts', hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'debianhosts', hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'dns-zone', users=self.users)    # FIXME double check user filter
        self.generate_tpl_file(dstdir, 'dns-sshfp', hosts=self.hosts)
        with open(os.path.join(dstdir, 'all-accounts.json'), 'w') as f:
            data = list()
            for user in self.users:
                if user.is_not_retired():
                    active = user.has_active_password() and not user.has_expired_password()
                    data.append({'uid':user.uid, 'uidNumber':user.uidNumber, 'active':active})
            json.dump(data, f, sort_keys=True, indent=4, separators=(',',':'))
        # TODO GenKeyrings(global_dir)

        for host in self.hosts:
            self.generate_host(host)

    def generate_host(self, host):
        dstdir = os.path.join(self.dstdir, host.hostname)
        self.makedirs(dstdir)

        self.generate_tpl_file(dstdir, 'passwd.tdb', users=host.users, host=host)
        self.generate_tpl_file(dstdir, 'group.tdb', groups=host.groups, host=host)
        # TODO GenShadowSudo(accounts, OutDir + "sudo-passwd", ('UNTRUSTED' in ExtraList) or ('NOPASSWD' in ExtraList), current_host)
        self.generate_tpl_file(dstdir, 'shadow.tdb', users=host.users, guard=('NOPASSWD' not in host.exportOptions))
        self.generate_tpl_file(dstdir, 'bsmtp', users=self.users, host=host, guard=('BSMTP' in host.exportOptions))
        self.generate_cdb_file(dstdir, 'user-forward.cdb', 'emailForward', users=host.users)
        self.generate_cdb_file(dstdir, 'batv-tokens.cdb', 'bATVToken', users=host.users)
        self.generate_cdb_file(dstdir, 'default-mail-options.cdb', 'mailDefaultOptions', users=host.users)
        self.link(self.dstdir, dstdir, 'disabled-accounts')
        self.link(self.dstdir, dstdir, 'mail-disable')
        self.link(self.dstdir, dstdir, 'mail-forward.cdb')
        self.link(self.dstdir, dstdir, 'mail-contentinspectionaction.cdb')
        self.link(self.dstdir, dstdir, 'debian-private', ('PRIVATE' not in host.exportOptions))
        self.link(self.dstdir, dstdir, 'authorized_keys', ('AUTHKEYS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'mail-greylist')
        self.link(self.dstdir, dstdir, 'mail-callout')
        self.link(self.dstdir, dstdir, 'mail-rbl')
        self.link(self.dstdir, dstdir, 'mail-rhsbl')
        self.link(self.dstdir, dstdir, 'mail-whitelist')
        self.link(self.dstdir, dstdir, 'web-passwords', ('WEB-PASSWORDS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'voip-passwords', ('VOIP-PASSWORDS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'forward-alias')
        self.link(self.dstdir, dstdir, 'markers', ('NOMARKERS' not in host.exportOptions))
        self.link(self.dstdir, dstdir, 'ssh_known_hosts')               # FIXME handle purpose
        self.link(self.dstdir, dstdir, 'debianhosts')
        self.link(self.dstdir, dstdir, 'dns-zone', ('DNS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'dns-sshfp', ('DNS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'all-accounts.json')
        # TODO keyring stuff

        tf = tarfile.open(name=os.path.join(self.dstdir, host.hostname, 'ssh-keys.tar.gz'), mode='w:gz')
        for user in host.users:
            to = tarfile.TarInfo(name=user.uid)
            contents = '\n'.join(user.sshRSAAuthKey) + '\n'             # FIXME handle allowed_hosts
            to.uid = 0
            to.gid = 65534
            to.uname = user.uid # XXX the magic happens here
            to.gname = user.gid # XXX the magic happens here
            to.mode  = 0400
            to.mtime = int(time.time())
            to.size = len(contents)
            tf.addfile(to, StringIO(contents))
        tf.close()

        self.link(self.dstdir, dstdir, 'last_update.trace')

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

    def generate_tpl_file(self, dstdir, template, hosts=None, groups=None, users=None, host=None, guard=True):
        if guard:
            t = self.finder.get_template(template)
            with open(os.path.join(dstdir, template), 'w') as f:
                f.write(t.render(hosts=hosts, groups=groups, users=users, host=host))

    def generate_cdb_file(self, dstdir, filename, key, hosts=None, groups=None, users=None, host=None, guard=True):
        if guard:
            fn = os.path.join(dstdir, filename).encode('ascii', 'ignore')
            maker = cdb.cdbmake(fn, fn + '.tmp')
            for user in users:
                if user.is_not_retired():                               # FIXME really?
                    val = getattr(user, key)
                    if val:
                        maker.add(user.uid, val)
            maker.finish()


# vim: set ts=4 sw=4 et ai si sta:
