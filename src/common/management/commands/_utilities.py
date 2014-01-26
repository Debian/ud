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
from django.core.management.base import CommandError
from django.utils.translation import ugettext as _
from common.models import DebianUser

import email
import email.utils
import nameparser
import optparse
import os
import pyme.core
import shutil
import tempfile
import yaml

from datetime import datetime

def load_configuration_file(filename):
    try:
        settings.config = yaml.safe_load(open(filename))
    except Exception as err:
        raise Exception(_('could not load configuration file'))
    if not settings.config.has_key('keyrings'):
        raise Exception(_('configuration file must specify keyrings parameter'))

def encrypt_result(result, fingerprint):
    try:
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'gpg.conf'), 'w') as f:
            f.write('no-default-keyring\n')
            f.write('secret-keyring /dev/null\n')
            f.write('trust-model always\n')
            for keyring in settings.config['keyrings']:
                f.write('keyring %s\n' % (keyring))
        ctx = pyme.core.Context()
        ctx.set_engine_info(0, '/usr/bin/gpg', tmpdir)
        ctx.set_armor(True)
        recipient = ctx.get_key(fingerprint, 0)
        plaintext = pyme.core.Data(result)
        encrypted = pyme.core.Data()
        ctx.op_encrypt([recipient], True, plaintext, encrypted)
        encrypted.seek(0,0)
        return encrypted.read()
    except Exception as err:
        raise err
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir)

def verify_message(message):
    if message.get('Reply-To'):
        (x,y) = email.utils.parseaddr(message.get('Reply-To'))
        if not y:
            raise Exception(_('malformed message: bad Reply-To header'))
    elif message.get('From'):
        (x,y) = email.utils.parseaddr(message.get('From'))
        if not y:
            raise Exception(_('malformed message: bad From header'))
    try:
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'gpg.conf'), 'w') as f:
            f.write('no-default-keyring\n')
            f.write('secret-keyring /dev/null\n')
            f.write('trust-model always\n')
            for keyring in settings.config['keyrings']:
                f.write('keyring %s\n' % (keyring))
        ctx = pyme.core.Context()
        ctx.set_engine_info(0, '/usr/bin/gpg', tmpdir)
        if message.get_content_type() == 'text/plain':
            try: # normal signature (clearsign or sign & armor)
                plaintext = pyme.core.Data() # output
                signature = pyme.core.Data(message.get_payload())
                ctx.op_verify(signature, None, plaintext)
                plaintext.seek(0,0)
            except Exception as err:
                raise Exception(_('malformed text/plain message'))
            content = plaintext.read()
        elif message.get_content_type() == 'multipart/signed':
            try: # detached signature
                signedtxt = pyme.core.Data(message.get_payload(0).as_string())
                signature = pyme.core.Data(message.get_payload(1).as_string())
                ctx.op_verify(signature, signedtxt, None)
            except:
                raise Exception(_('malformed multipart/signed message'))
            content = message.get_payload(0).get_payload(decode=True)
        else:
            raise Exception(_('malformed message: unsupported content-type'))
        result = ctx.op_verify_result()
        if len(result.signatures) == 0:
            raise Exception(_('malformed message: too few signatures'))
        if len(result.signatures) >= 2:
            raise Exception(_('malformed message: too many signatures'))
        if result.signatures[0].status != 0:
            raise Exception(_('invalid signature'))
        fingerprint = ctx.get_key(result.signatures[0].fpr, 0).subkeys[0].fpr
        timestamp = datetime.fromtimestamp(result.signatures[0].timestamp)
        return (fingerprint, content, timestamp)
    except Exception as err:
        raise err
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir)

def get_user_from_fingerprint(fingerprint):
    try:
        result = DebianUser.objects.filter(keyFingerPrint=fingerprint)
        if len(result) == 1:
            return result[0]
    except:
        pass
    return None

def get_user_from_headers(message):
    try:
        humanName = None
        emailForward = None
        uid = None
        if 'From' in message:
            (x,y) = email.utils.parseaddr(message.get('From'))
            if x:
                humanName = nameparser.HumanName(x)
            if y:
                emailForward = y
                if y.endswith('@debian.org'):
                    uid = y.split('@')[0]
        if emailForward:
            result = DebianUser.objects.filter(emailForward=emailForward)
            if len(result) == 1:
                return result[0]
        if humanName:
            result = DebianUser.objects.filter(cn=humanName.first,sn=humanName.last)
            if len(result) == 1:
                return result[0]
        if uid:
            result = DebianUser.objects.filter(uid=uid)
            if len(result) == 1:
                return result[0]
    except:
        pass
    return None

# vim: set ts=4 sw=4 et ai si sta:
