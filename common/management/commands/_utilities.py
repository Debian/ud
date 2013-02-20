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
from common.models import User

import optparse
import email
import email.utils
import nameparser
import os
import pyme.constants.sigsum
import pyme.core

def verify_message(message):
    if message.get('Reply-To'):
        (x,y) = email.utils.parseaddr(message.get('Reply-To'))
        if not y:
            raise Exception('malformed message: bad Reply-To header')
    elif message.get('From'):
        (x,y) = email.utils.parseaddr(message.get('From'))
        if not y:
            raise Exception('malformed message: bad From header')
    ctx = pyme.core.Context()
    ctx.set_engine_info(0, '/usr/bin/gpg', os.path.join(settings.PROJECT_DIR))
    if message.get_content_type() == 'text/plain':
        try: # normal signature (clearsign or sign & armor)
            plaintext = pyme.core.Data() # output
            signature = pyme.core.Data(message.get_payload())
            ctx.op_verify(signature, None, plaintext)
            plaintext.seek(0,0)
        except Exception as err:
            raise Exception('malformed text/plain message')
        commands = plaintext.read().splitlines()
    elif message.get_content_type() == 'multipart/signed':
        try: # detached signature
            signedtxt = pyme.core.Data(message.get_payload(0).as_string())
            signature = pyme.core.Data(message.get_payload(1).as_string())
            ctx.op_verify(signature, signedtxt, None)
        except:
            raise Exception('malformed multipart/signed message')
        commands = message.get_payload(0).get_payload(decode=True).splitlines()
    else:
        raise Exception('malformed message: unsupported content-type')
    result = ctx.op_verify_result()
    if len(result.signatures) == 0:
        raise Exception('malformed message: too few signatures')
    if len(result.signatures) >= 2:
        raise Exception('malformed message: too many signatures')
    if result.signatures[0].status != 0:
        raise Exception('invalid signature')
    return (result.signatures[0].fpr, commands)

def get_user_from_fingerprint(fingerprint):
    result = User.objects.filter(keyFingerPrint=fingerprint)
    if len(result) == 0:
        raise Exception('too few user objects found')
    if len(result) >= 2:
        raise Exception('too many user objects found')
    return result[0]

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
            result = User.objects.filter(emailForward=emailForward)
            if len(result) == 1: return result[0]
        if humanName:
            result = User.objects.filter(cn=humanName.first,sn=humanName.last)
            if len(result) == 1: return result[0]
        if uid:
            result = User.objects.filter(uid=uid)
            if len(result) == 1: return result[0]
    except:
        pass
    raise Exception('could not find user')

# vim: set ts=4 sw=4 et ai si sta:
