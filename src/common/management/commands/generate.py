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
# Copyright (C) 2013 Martin Zobel-Helas <zobel@debian.org>
# Copyright (C) 2013 Oliver Berger <obergix@debian.org>

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connections
from common.models import DebianHost, DebianGroup, DebianRole, DebianUser, validate_sshRSAAuthKey

from dsa_mq.connection import Connection
from dsa_mq.config import Config

from datetime import datetime, timedelta
from itertools import chain
from mako.lookup import TemplateLookup
from mako.template import Template

import cdb
import errno
import fcntl
import grp
import json
import ldap
import lockfile
import optparse
import os
import posix
import re
import shutil
import tarfile
import time
import yaml

from StringIO import StringIO

from ldap import LDAPError

from _utilities import load_configuration_file

class Command(BaseCommand):
    help = 'Generates, on a host-by-host basis, the set of files to be replicated.'
    option_list = BaseCommand.option_list + (
        optparse.make_option('--force',
            action='store_true',
            default=False,
            help='force generate'
        ),
        optparse.make_option('--config',
            action='store',
            default='/etc/ud/generate.yaml',
            help='specify configuration file'
        ),
        optparse.make_option('--mq',
            action='store_true',
            default=False,
            help='force update notification via mq'
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
                raise CommandError('configuration file must specify username parameter')
            if settings.config.has_key('password'):
                settings.DATABASES['ldap']['PASSWORD'] = settings.config['password']
            else:
                raise CommandError('configuration file must specify password parameter')
        except Exception as err:
            raise CommandError(err)
        self.dstdir = os.path.join(settings.CACHE_DIR, 'hosts')
        self.makedirs(self.dstdir)
        self.tpldir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
        self.finder = TemplateLookup(directories=[self.tpldir], encoding_errors='ignore', output_encoding='utf-8')
        try:
            with open(os.path.join(self.dstdir, 'ud-generate.lock'), 'w') as f:
                lock_acquired = False
                lock_time_out = time.time() + 300
                while not lock_acquired:
                    try:
                        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        lock_acquired = True
                    except IOError:
                        if time.time() > lock_time_out:
                            raise Exception('unable to acquire lock')
                        time.sleep(2)
                if self.options['force'] or self.need_update() :
                    with open(os.path.join(self.dstdir, 'last_update.trace'), 'w') as f:
                        self.marshall()
                        self.generate()
                        last_generate = datetime.utcnow().strftime('%Y%m%d%H%M%S.%fZ')
                        if not hasattr(self, 'last_file_mod') :
                            self.last_file_mod = last_generate
                        if not hasattr(self, 'last_ldap_mod') :
                            self.last_ldap_mod = last_generate
                        f.write(yaml.dump({'last_file_mod': self.last_file_mod, 'last_ldap_mod': self.last_ldap_mod, 'last_generate': last_generate}))
                    if self.options['mq']:
                        notify_via_mq(self.options['mq'], 'Update forced' if self.options['force'] else 'Update needed')
        except Exception as err:
            raise CommandError(err)

    def need_update(self):
        try:
            last_file_mods = [os.path.getmtime(keyring) for keyring in settings.config['keyrings']]
            self.last_file_mod = max([datetime.fromtimestamp(last_file_mod).strftime('%Y%m%d%H%M%S.%fZ') for last_file_mod in last_file_mods])
        except Exception as err:
            raise CommandError(err)
        try:
            query = '(&(&(!(reqMod=activity-from*))(!(reqMod=activity-pgp*)))(|(reqType=add)(reqType=delete)(reqType=modify)(reqType=modrdn)))'
            last_ldap_mods = connections['ldap'].cursor().connection.search_s('cn=log', ldap.SCOPE_ONELEVEL, query, ['reqEnd'])
            self.last_ldap_mod = max([last_ldap_mod[1]['reqEnd'][0] for last_ldap_mod in last_ldap_mods])
        except Exception as err:
            raise CommandError(err)
        try:
            with open(os.path.join(self.dstdir, 'last_update.trace'), 'r') as f:
                y = yaml.safe_load(f)
                if y:
                    if self.last_file_mod > y.get('last_file_mod', (datetime.utcnow() - timedelta(weeks=52)).strftime('%Y%m%d%H%M%S.%fZ')):
                        return True # a keyring entry has been updated since last run
                    if self.last_ldap_mod > y.get('last_ldap_mod', (datetime.utcnow() - timedelta(weeks=52)).strftime('%Y%m%d%H%M%S.%fZ')):
                        return True # an ldapdb entry has been updated since last run
                    return False
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise CommandError(err)
        except Exception as err:
            raise CommandError(err)
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

        self.hosts = DebianHost.objects.all()
        self.groups = DebianGroup.objects.all()
        self.users = list(chain(DebianUser.objects.all(), DebianRole.objects.all()))

        _gid2group = dict()
        _gidNumber2gid = dict()
        for group in self.groups:
            group.hid2users = dict() # real users - group exists on the host
            group.hid2virts = dict() # virt users - group doesn't exist on the host
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
                continue
            user.hid2gids = dict()
            for host in self.hosts:
                host_gids = set(host.allowedGroups) | set(['adm'])
                user_gids = set([user.gid]) | recurse(user.supplementaryGid, host.hostname)
                if user_gids & host_gids or user.is_allowed_by_hostacl(host.hostname):
                    if user.is_not_retired() and user.has_active_password():
                        user.hid2gids[host.hid] = user_gids
                        host.users.add(user)
                for user_gid in user_gids:
                    if user_gid in _gid2group:
                        group = _gid2group[user_gid]
                        group.hid2virts.setdefault(host.hid, set()).add(user)

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
        self.generate_tpl_file(dstdir, 'rtc-passwords', users=self.users)
        self.generate_tpl_file(dstdir, 'forward-alias', users=self.users)
        self.generate_tpl_file(dstdir, 'markers', users=self.users)
        self.generate_tpl_file(dstdir, 'ssh_known_hosts', hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'debianhosts', hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'ssh-gitolite', users=self.users, hosts=self.hosts)
        self.generate_tpl_file(dstdir, 'dns-zone', users=self.users)
        self.generate_tpl_file(dstdir, 'dns-sshfp', hosts=self.hosts)

        with open(os.path.join(dstdir, 'all-accounts.json'), 'w') as f:
            data = list()
            for user in self.users:
                if user.is_not_retired():
                    active = user.has_active_password() and not user.has_expired_password()
                    data.append({'uid':user.uid, 'uidNumber':user.uidNumber, 'active':active})
            json.dump(data, f, sort_keys=True, indent=4, separators=(',',':'))

        for element in settings.config['keyrings']:
            if os.path.isdir(element):
                src = element
                dst = os.path.join(dstdir, os.path.basename(element))
                shutil.rmtree(dst, True)
                shutil.copytree(src, dst)
            else:
                src = element
                dst = dstdir
                shutil.copy(src, dst)

        for host in self.hosts:
            self.generate_host(host)

    def generate_host(self, host):
        dstdir = os.path.join(self.dstdir, host.hostname)
        self.makedirs(dstdir)

        self.generate_tpl_file(dstdir, 'passwd.tdb', users=host.users, host=host)
        self.generate_tpl_file(dstdir, 'group.tdb', groups=host.groups, host=host)
        self.generate_tpl_file(dstdir, 'sudo-passwd', users=host.users, host=host)
        self.generate_tpl_file(dstdir, 'shadow.tdb', users=host.users, guard=('NOPASSWD' not in host.exportOptions))
        self.generate_tpl_file(dstdir, 'bsmtp', users=self.users, host=host, guard=('BSMTP' in host.exportOptions))
        for gid in [match.group(1) for match in (re.search('GITOLITE=(.+)', exportOption) for exportOption in host.exportOptions) if match]:
            virts = set(chain.from_iterable([group.hid2virts[host.hid] for group in self.groups if group.gid == gid]))
            self.generate_tpl_file(dstdir, 'ssh-gitolite', users=virts, hosts=self.hosts, dstfile='ssh-gitolite-' + gid)
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
        self.link(self.dstdir, dstdir, 'rtc-passwords', ('RTC-PASSWORDS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'forward-alias')
        self.link(self.dstdir, dstdir, 'markers', ('NOMARKERS' not in host.exportOptions))
        self.link(self.dstdir, dstdir, 'ssh_known_hosts')
        self.link(self.dstdir, dstdir, 'debianhosts')
        self.link(self.dstdir, dstdir, 'dns-zone', ('DNS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'dns-sshfp', ('DNS' in host.exportOptions))
        self.link(self.dstdir, dstdir, 'all-accounts.json')

        if 'KEYRING' in host.exportOptions:
            for element in settings.config['keyrings']:
                if os.path.isdir(element):
                    src = os.path.join(self.dstdir, os.path.basename(element))
                    dst = os.path.join(dstdir, os.path.basename(element))
                    shutil.rmtree(dst, True)
                    shutil.copytree(src, dst)
                else:
                    tgt = os.path.basename(element)
                    self.link(self.dstdir, dstdir, tgt)
        else:
            for element in settings.config['keyrings']:
                try:
                    if os.path.isdir(element):
                        dst = os.path.join(dstdir, os.path.basename(element))
                        shutil.rmtree(dst, True)
                    else:
                        tgt = os.path.join(dstdir, os.path.basename(element))
                        posix.remove(tgt)
                except:
                    pass

        tf = tarfile.open(name=os.path.join(self.dstdir, host.hostname, 'ssh-keys.tar.gz'), mode='w:gz')
        for user in host.users:
            if not hasattr(user, 'sshRSAAuthKey'):
                continue
            contents = ''
            for sshRSAAuthKey in user.sshRSAAuthKey:
                if sshRSAAuthKey.startswith('allowed_hosts=') and ' ssh-rsa ' in sshRSAAuthKey:
                    hostnames, sshRSAAuthKey = sshRSAAuthKey.split('=', 1)[1].split(' ', 1)
                    if host.hostname not in hostnames.split(','):
                        continue
                contents += sshRSAAuthKey + '\n'
            if contents:
                to = tarfile.TarInfo(name=user.uid)
                to.uid = 0
                to.gid = 65534
                to.uname = user.uid
                to.gname = user.gid
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

    def generate_tpl_file(self, dstdir, template, hosts=None, groups=None, users=None, host=None, guard=True, dstfile=None):
        if guard:
            t = self.finder.get_template(template)
            o = os.path.join(dstdir, dstfile if dstfile else template)
            with open(o, 'w') as f:
                f.write(t.render(hosts=hosts, groups=groups, users=users, host=host))

    def generate_cdb_file(self, dstdir, filename, key, hosts=None, groups=None, users=None, host=None, guard=True):
        if guard:
            fn = os.path.join(dstdir, filename).encode('ascii', 'ignore')
            maker = cdb.cdbmake(fn, fn + '.tmp')
            for user in users: # TODO latest version of python-cdb can do bulk add
                if user.is_not_retired():
                    val = getattr(user, key)
                    if val:
                        maker.add(user.uid, val)
            maker.finish()

    def notify_via_mq(options, message):
        options.section = 'dsa-udgenerate'
        options.config = '/etc/dsa/pubsub.conf'

        config = Config(options)
        conf = {
            'rabbit_userid': config.username,
            'rabbit_password': config.password,
            'rabbit_virtual_host': config.vhost,
            'rabbit_hosts': ['pubsub02.debian.org', 'pubsub01.debian.org'],
            'use_ssl': False
        }

        msg = { 'message': message, timestamp: int(time.time()) }
        conn = None
        try:
            conn = Connection(conf=conf)
            conn.topic_send(config.topic, json.dumps(msg), exchange_name=config.exchange, timeout=5)
        finally:
            if conn:
                conn.close()

# vim: set ts=4 sw=4 et ai si sta:
