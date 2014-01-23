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

from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db import models

from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models
import ldap
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')

import base64
import datetime
import email.utils
import json
import hashlib
import hmac
import os
import pycountry
import pyme.core
import pyparsing
import re
import shutil
import struct
import sys
import tempfile
import time

from IPy import IP
from M2Crypto import RSA, m2

thismodule = sys.modules[__name__]

def DecDegree(Posn, Anon=False): # FIXME ick... replace with geopy?
    Parts = re.match('[-+]?(\d*)\\.?(\d*)',Posn).groups();
    Val = float(Posn);

    if (abs(Val) >= 1806060.0):
        return 'ERROR'

    # Val is in DGMS
    if abs(Val) >= 18060.0 or len(Parts[0]) > 5:
        Val = Val/100.0
        Secs = Val - long(Val)
        Val = long(Val)/100.0
        Min = Val - long(Val)
        Val = long(Val) + (Min*100.0 + Secs*100.0/60.0)/60.0

    # Val is in DGM
    elif abs(Val) >= 180 or len(Parts[0]) > 3:
        Val = Val/100.0
        Min = Val - long(Val)
        Val = long(Val) + Min*100.0/60.0

    if Anon != 0:
        Str = "%3.2f"%(Val)
    else:
        Str = str(Val)
    if Val >= 0:
        return "+" + Str
    return Str

def make_hmac(key, val):
    return hmac.new(key, val, hashlib.sha1).hexdigest()

def make_passwd_hmac(key, status, purpose, uid, uuid, hostnames, password):
    return make_hmac(key, ':'.join([status, purpose, uid, uuid, hostnames, password]))

def validate_dns_labels(val):
    disallowed = re.compile('[^_A-Z\d-]', re.IGNORECASE)
    for label in val.split('.'):
        if len(label) == 0:
            raise ValidationError('label in name is too short')
        if len(label) > 63:
            raise ValidationError('label in name is too long')
        if label.startswith('-') or label.endswith('-'):
            raise ValidationError('label in name begins/ends with hyphen')
        if '_' in label[1:]:
            raise ValidationError('label in name contains an underscore')
        if disallowed.search(label):
            raise ValidationError('label in name contains invalid characters')

def validate_fqdn(val):
    # fqdn - fully qualified domain name
    if len(val) > 255:
        raise ValidationError('name is too long')
    if not val.endswith('.'):
        raise ValidationError('name does not end in .')
    validate_dns_labels(val[:-1])

def validate_pqdn(val):
    # pqdn - partially qualified domain name
    if len(val) > (255 - len('.debian.net.')):
        raise ValidationError('label is too long')
    if val.endswith('.'):
        raise ValidationError('label ends in .')
    if val.endswith('.debian.net'):
        raise ValidationError('label ends in .debian.net')
    validate_dns_labels(val)

def validate_ipv4(val):
    address = IP(val)
    if address.version() != 4:
        raise ValidationError('value is not an IPv4 address')

def validate_ipv6(val):
    address = IP(val)
    if address.version() != 6:
        raise ValidationError('value is not an IPv6 address')

def validate_activityFrom(val):
    return # TODO

def validate_activityPGP(val):
    return # TODO

def validate_accountStatus(val):
    return # TODO

def validate_allowedHost(val):
    try:
        if not DebianHost.objects.filter(hostname=val):
            raise
    except:
        ValidationError('unknown host')

def validate_bATVToken(val):
    validator = pyparsing.LineStart() + pyparsing.Word(pyparsing.alphanums+'-') + pyparsing.LineEnd()
    validator.parseString(val)

def validate_birthDate(val):
    validator = pyparsing.LineStart() + pyparsing.Word(pyparsing.nums, exact=8) + pyparsing.LineEnd()
    validator.parseString(val)

def validate_c(val):
    try:
        if val is not None:
            if val.upper() not in ['AC', 'EU', 'FX', 'UK', 'YU']:
                pycountry.countries.get(alpha2=val.upper())
    except:
        raise ValidationError('value is not a valid ISO3166-2 country code')

def validate_cn(val):
    return # TODO

def validate_dnsZoneEntry(val, mode='update'):
    # TODO ensure labels / hostnames are lower case
    # TODO ensure label is not owned by another user
    # TODO reimplement fqdn/pqdn/ipv4/ipv6 with pyparsing
    update = (
        pyparsing.LineStart() + pyparsing.Regex(r'(?=\w)[-\w.]+(?<![-_.])') + pyparsing.Keyword('IN') + (
            ( pyparsing.Keyword('A') + pyparsing.Word(pyparsing.nums+'.') ) |
            ( pyparsing.Keyword('AAAA') + pyparsing.Word(pyparsing.hexnums+':') ) |
            ( pyparsing.Keyword('CNAME') + pyparsing.Regex(r'(?=\w)[-\w.]+(?<![-_])[.]') ) |
            ( pyparsing.Keyword('MX') + pyparsing.Regex(r'\d{1,5}') + pyparsing.Regex(r'[-\w.]+\.') ) |
            ( pyparsing.Keyword('TXT') + pyparsing.QuotedString('"', escChar='\\', unquoteResults=False) )
        ) +
        pyparsing.LineEnd()
    )
    delete = (
        pyparsing.LineStart() + pyparsing.Regex(r'^(?=\w)[-\w.]+(?<![-_.])$') + pyparsing.Optional(
            ( pyparsing.Keyword('IN') + pyparsing.Keyword('A') ) |
            ( pyparsing.Keyword('IN') + pyparsing.Keyword('AAAA') ) |
            ( pyparsing.Keyword('IN') + pyparsing.Keyword('CNAME') ) |
            ( pyparsing.Keyword('IN') + pyparsing.Keyword('MX') ) |
            ( pyparsing.Keyword('IN') + pyparsing.Keyword('TXT') )
        ) + pyparsing.LineEnd()
    )
    try:
        validator = update if mode is 'update' else delete
        tokens = validator.parseString(val)
        if mode is 'update': # do deeper validation
            method = 'validate_dnsZoneEntry_%s_%s' % (tokens[1], tokens[2])
            getattr(thismodule, method)(tokens[0], *tokens[3:])
        return tokens
    except ValidationError as err:
        raise err
    except Exception as err:
        raise ValidationError(err)

def validate_dnsZoneEntry_IN_A(name, address):
    validate_pqdn(name)
    validate_ipv4(address)

def validate_dnsZoneEntry_IN_AAAA(name, address):
    validate_pqdn(name)
    validate_ipv6(address)

def validate_dnsZoneEntry_IN_CNAME(name, cname):
    validate_pqdn(name)
    validate_fqdn(cname)

def validate_dnsZoneEntry_IN_MX(name, preference, exchange):
    validate_pqdn(name)
    if int(preference) not in range(65536):
        # per RFC 974, the preference number in MX RRs is an unsigned
        # integer [0,65535] in decimal representation
        # see http://tools.ietf.org/html/rfc974
        raise ValidationError('preference %s out of range' % preference)
    validate_fqdn(exchange)

def validate_dnsZoneEntry_IN_TXT(name, txtdata):
    validate_pqdn(name)
    # Do not need to validate txtdata here as it is validated by
    # QuotedString in the calling function: validate_dnsZoneEntry.

def validate_emailForward(val):
    try:
        validate_email(val)
    except:
        raise ValidationError('value is not a valid for emailForward')

def validate_facsimileTelephoneNumber(val):
    # Let's follow the recommendations of ITU E.123 regarding international notation of telephone numbers:
    # - only spaces should be used to visually separate groups of numbers in international notation
    # - parentheses should not be used in the international notation
    # see http://en.wikipedia.org/wiki/E.123
    validator = (
        pyparsing.LineStart() +
        pyparsing.Word(pyparsing.nums+'+ /') +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_gecos(val):
    return # TODO

def validate_gender(val):
    # follow the ISO 5218 standard for genders
    # see http://en.wikipedia.org/wiki/ISO/IEC_5218
    validator = (
        pyparsing.LineStart() + (
            pyparsing.Keyword('0') | # not known
            pyparsing.Keyword('1') | # male
            pyparsing.Keyword('2') | # female
            pyparsing.Keyword('9')   # unspecified
        ) +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_gidNumber(val):
    try:
        if val not in [65534] and not DebianGroup.objects.filter(gidNumber__exact=val):
            raise
    except:
        raise ValidationError('unknown group')

def validate_icqUin(val):
    validator = pyparsing.LineStart() + pyparsing.Word(pyparsing.nums, min=5) + pyparsing.LineEnd()
    validator.parseString(val)

def validate_ircNick(val):
    return # TODO

def validate_jabberJID(val):
    validator = pyparsing.LineStart() + pyparsing.Regex(r'[^<>@]+@.+') + pyparsing.LineEnd()
    validator.parseString(val)

def validate_keyFingerPrint(val):
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
        try:
            fpr = val.encode('ascii')
            if fpr != ctx.get_key(fpr, 0).subkeys[0].fpr:
                raise ValidationError('key fingerprint is not for primary key')
        except ValidationError:
            raise
        except Exception as err:
            raise ValidationError('key fingerprint not found in keyring(s)')
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir)

def validate_l(val):
    return # TODO

def validate_labeledURI(val):
    return # TODO

def validate_latitude(val):
    return # TODO otherwise have to handle poor quality data (see DecDegree)

def validate_loginShell(val):
    try:
        loginShells = [ '/bin/sh', '/bin/false', '/bin/bash', '/usr/bin/bash',
                        '/bin/csh', '/usr/bin/csh', '/bin/ksh', '/usr/bin/ksh',
                        '/bin/tcsh', '/usr/bin/tcsh', '/bin/zsh', '/usr/bin/zsh']
        if val not in loginShells:
            raise
    except:
        raise ValidationError('value is not a valid login shell')

def validate_longitude(val):
    return # TODO otherwise have to handle poor quality data (see DecDegree)

def validate_mailCallout(val):
    validator = (
        pyparsing.LineStart() + (
            pyparsing.Keyword('TRUE') |
            pyparsing.Keyword('FALSE')
        ) +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_mailContentInspectionAction(val):
    validator = (
        pyparsing.LineStart() + (
            pyparsing.Keyword('reject') |
            pyparsing.Keyword('blackhole') |
            pyparsing.Keyword('markup')
        ) +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_mailDefaultOptions(val):
    validator = (
        pyparsing.LineStart() + (
            pyparsing.Keyword('TRUE') |
            pyparsing.Keyword('FALSE')
        ) +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_mailDisableMessage(val):
    return # TODO

def validate_mailGreylisting(val):
    validator = (
        pyparsing.LineStart() + (
            pyparsing.Keyword('TRUE') |
            pyparsing.Keyword('FALSE')
        ) +
        pyparsing.LineEnd()
    )
    validator.parseString(val)

def validate_mailRBL(val):
    return # TODO

def validate_mailRHSBL(val):
    return # TODO

def validate_mailWhitelist(val):
    return # TODO

def validate_mn(val):
    return # TODO

def validate_privateSub(val):
    return # TODO

def validate_sn(val):
    return # TODO

def validate_sshRSAAuthKey(val, mode='update'):
    hostname = pyparsing.Word(pyparsing.alphanums+'-.')
    flag = (
        # reject flags: cert-authority
        pyparsing.CaselessKeyword('no-agent-forwarding') |
        pyparsing.CaselessKeyword('no-port-forwarding') |
        pyparsing.CaselessKeyword('no-pty') |
        pyparsing.CaselessKeyword('no-user-rc') |
        pyparsing.CaselessKeyword('no-X11-forwarding')
    )
    key = (
        # reject keys: principals, tunnel
        pyparsing.CaselessKeyword('command') |
        pyparsing.CaselessKeyword('environment') |
        pyparsing.CaselessKeyword('from') |
        pyparsing.CaselessKeyword('permitopen')
    )
    keyval = key + pyparsing.Literal('=') + pyparsing.QuotedString('"', unquoteResults=False)
    options = pyparsing.delimitedList(flag | keyval, combine=True)
    allowed_hosts = (
        pyparsing.Suppress(pyparsing.Keyword('allowed_hosts')) +
        pyparsing.Suppress(pyparsing.Literal('=')) +
        pyparsing.Group(pyparsing.delimitedList(hostname))
    )
    update = (
        pyparsing.LineStart() +
        pyparsing.Optional(allowed_hosts, default=[]) +
        pyparsing.Optional(options, default=[]) +
        pyparsing.Keyword('ssh-rsa') + pyparsing.Regex('[a-zA-Z0-9=/+]+') +
        pyparsing.Optional(pyparsing.Regex('.*'), default='') +
        pyparsing.LineEnd()
    )
    delete = (
        pyparsing.LineStart() +
        pyparsing.Keyword('ssh-rsa') + pyparsing.Regex('[a-zA-Z0-9=/+]+') +
        pyparsing.LineEnd()
    )
    try:
        validator = update if mode is 'update' else delete
        tokens = validator.parseString(val)
        if tokens[0] and not set(tokens[0]).issubset(set([x.hostname for x in DebianHost.objects.all()])):
            raise ValidationError('unknown host in allowed_hosts')
        validate_sshRSAAuthKey_key(tokens[3])
        return tokens
    except ValidationError as err:
        raise err
    except Exception as err:
        raise ValidationError(err)

def validate_sshRSAAuthKey_key(encoded_key):
    decoded_key = base64.b64decode(encoded_key)
    if base64.b64encode(decoded_key).rstrip() != encoded_key:
        raise ValidationError('key has incorrect base64 encoding')

    # OpenSSH public keys of type 'ssh-rsa' have three parts, where each
    # part is encoded in OpenSSL MPINT format (4-byte big-endian bit-count
    # followed by the appropriate number of bits).

    try: # part 1: key type hardcoded value ('ssh-rsa')
        x = struct.unpack('>I', decoded_key[:4])[0]
        key_type, decoded_key = decoded_key[4:x+4], decoded_key[x+4:]
    except:
        raise ValidationError('unable to extract type from key')
    if key_type != 'ssh-rsa':
        raise ValidationError('key is not an ssh-rsa key')

    try: # part 2: public exponent
        x = struct.unpack('>I', decoded_key[:4])[0]
        e, decoded_key = decoded_key[:x+4], decoded_key[x+4:]
    except:
        raise ValidationError('unable to extract public exponent from key')

    try: # part 3: large prime
        x = struct.unpack('>I', decoded_key[:4])[0]
        n, decoded_key = decoded_key[:x+4], decoded_key[x+4:]
    except:
        raise ValidationError('unable to extract large prime from key')

    try: # creating a new RSA key
        created_key = RSA.new_pub_key((e, n))
    except:
        raise ValidationError('unable to create key using values extracted from provided key')

    if encoded_key != base64.b64encode('\0\0\0\7ssh-rsa%s%s' % created_key.pub()):
        raise ValidationError('newly created key and provided key do not match')

def validate_sudoPassword(val):
    return # TODO

def validate_supplementaryGid(val):
    try:
        if '@' in val:
            (val,hostname) = val.split('@', 1)
            if not DebianHost.objects.filter(hostname=hostname):
                raise
        DebianGroup.objects.get(gid__exact=val)
    except:
        raise ValidationError('not a valid group')

def validate_userPassword(val):
    return # TODO

def validate_rtcPassword(val):
    return # TODO

def validate_webPassword(val):
    return # TODO


class __LdapDebianServer(ldapdb.models.Model):
    # objectclass ( 1.3.6.1.4.1.9586.100.4.3.2 NAME 'debianServer'
    #     DESC 'Internet-connected server associated with Debian'
    #     SUP top STRUCTURAL
    #     MUST ( host $ hostname )
    #     MAY (
    #         c $ access $ admin $ architecture $ bandwidth $ description $
    #         disk $ distribution $ l $ machine $ memory $ sponsor $
    #         sponsor-admin $ status $ physicalHost $ ipHostNumber $ dnsTTL $
    #         sshRSAHostKey $ purpose $ allowedGroups $ exportOptions $
    #         MXRecord $ sshdistAuthKeysHost
    #     )
    # )

    hid                         = CharField(db_column='host', # XXX host
                                    validators=[], primary_key=True)                    # TODO validator
    hid.permissions             = { 'self': 'none', 'root': 'read' }

    hostname                    = CharField(db_column='hostname',
                                    validators=[])                                      # TODO validator
    hostname.permissions        = { 'self': 'none', 'root': 'read' }

    architecture                = CharField(db_column='architecture',
                                    validators=[])                                      # TODO validator
    architecture.permissions    = { 'self': 'none', 'root': 'read' }

    machine                     = CharField(db_column='machine',
                                    validators=[])                                      # TODO validator
    machine.permissions         = { 'self': 'none', 'root': 'read' }

    ipHostNumber                = ListField(db_column='ipHostNumber',
                                    validators=[])                                      # TODO validator
    ipHostNumber.permissions    = { 'self': 'none', 'root': 'read' }

    dnsTTL                      = CharField(db_column='dnsTTL',
                                    validators=[])                                      # TODO validator
    dnsTTL.permissions          = { 'self': 'none', 'root': 'read' }

    sshRSAHostKey               = ListField(db_column='sshRSAHostKey',
                                    validators=[], null=True, blank=True)               # TODO validator
    sshRSAHostKey.permissions   = { 'self': 'none', 'root': 'read' }

    purpose                     = ListField(db_column='purpose',
                                    validators=[], null=True, blank=True)               # TODO validator
    purpose.permissions         = { 'self': 'none', 'root': 'read' }

    allowedGroups               = ListField(db_column='allowedGroups',
                                    validators=[])                                      # TODO validator
    allowedGroups.permissions   = { 'self': 'none', 'root': 'read' }

    exportOptions               = ListField(db_column='exportOptions',
                                    validators=[])                                      # TODO validator
    exportOptions.permissions   = { 'self': 'none', 'root': 'read' }

    mXRecord                    = ListField(db_column='mXRecord',
                                    validators=[])                                      # TODO validator
    mXRecord.permissions        = { 'self': 'none', 'root': 'read' }

    class Meta:
        abstract = True


class __LdapDebianGroup(ldapdb.models.Model):
    # objectclass ( 1.3.6.1.4.1.9586.100.4.1.2 NAME 'debianGroup'
    #     SUP top STRUCTURAL
    #     DESC 'attributes used for Debian groups'
    #     MUST ( gid $ gidNumber)
    #     MAY ( description $ subGroup $ accountStatus )
    # )

    gid                         = CharField(db_column='gid',
                                    validators=[], primary_key=True)                    # TODO validator
    gid.permissions             = { 'self': 'none', 'root': 'read' }

    gidNumber                   = IntegerField(db_column='gidNumber',
                                    validators=[])                                      # TODO validator

    gidNumber.permissions       = { 'self': 'none', 'root': 'read' }

    subGroup                    = ListField(db_column='subGroup',
                                    validators=[])                                      # TODO validator
    subGroup.permissions        = { 'self': 'none', 'root': 'read' }

    class Meta:
        abstract = True


class __LdapShadowAccount(ldapdb.models.Model):
    # objectclass ( 1.3.6.1.1.1.2.1 NAME 'shadowAccount'
    #     DESC 'Additional attributes for shadow passwords'
    #     SUP top AUXILIARY
    #     MUST uid
    #     MAY (
    #         userPassword $ shadowLastChange $ shadowMin $
    #         shadowMax $ shadowWarning $ shadowInactive $
    #         shadowExpire $ shadowFlag $ description
    #     )
    # )

    # NOTE uid defined subsequently

    # NOTE userPassword defined subsequently

    shadowLastChange                        = IntegerField( db_column='shadowLastChange',
                                                validators=[])
    shadowLastChange.permissions            = { 'self': 'read', 'root': 'read' }

    shadowMin                               = IntegerField( db_column='shadowMin',
                                                validators=[])
    shadowMin.permissions                   = { 'self': 'read', 'root': 'read' , 'root': 'read' }

    shadowMax                               = IntegerField( db_column='shadowMax',
                                                validators=[])
    shadowMax.permissions                   = { 'self': 'read', 'root': 'read' }

    shadowWarning                           = IntegerField( db_column='shadowWarning',
                                                validators=[])
    shadowWarning.permissions               = { 'self': 'read', 'root': 'read' }

    shadowInactive                          = IntegerField( db_column='shadowInactive',
                                                validators=[])
    shadowInactive.permissions              = { 'self': 'read', 'root': 'read' }

    shadowExpire                            = IntegerField( db_column='shadowExpire',
                                                validators=[])
    shadowExpire.permissions                = { 'self': 'read', 'root': 'read' }

    # all other attributes not used

    class Meta:
        abstract = True


class __LdapPerson(ldapdb.models.Model):
    # objectclass ( 2.5.6.6 NAME 'person'
    #     DESC 'RFC2256: a person'
    #     SUP top STRUCTURAL
    #     MUST ( sn $ cn )
    #     MAY ( userPassword $ telephoneNumber $ seeAlso $ description )
    # )

    sn                                      = CharField(db_column='sn',
                                                validators=[validate_sn])
    sn.permissions                          = { 'self': 'read', 'root': 'write' }

    cn                                      = CharField(db_column='cn',
                                                validators=[validate_cn])
    cn.permissions                          = { 'self': 'read', 'root': 'write' }

    # NOTE userPassword defined subsequently

    # NOTE telephoneNumber defined subsequently

    # all other attributes not used

    class Meta:
        abstract = True


class __LdapOrganizationalPerson(__LdapPerson):
    # objectclass ( 2.5.6.7 NAME 'organizationalPerson'
    #     DESC 'RFC2256: an organizational person'
    #     SUP person STRUCTURAL
    #     MAY (
    #         title $ x121Address $ registeredAddress $ destinationIndicator $
    #         preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
    #         telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $
    #         street $ postOfficeBox $ postalCode $ postalAddress $
    #         physicalDeliveryOfficeName $ ou $ st $ l
    #     )
    # )

    # TODO telephoneNumber

    # TODO telephoneNumber.permissions

    facsimileTelephoneNumber                = CharField(db_column='facsimileTelephoneNumber',
                                                validators=[validate_facsimileTelephoneNumber], null=True, blank=True)
    facsimileTelephoneNumber.permissions    = { 'self': 'write', 'root': 'write' }

    # TODO postalCode

    # TODO postalCode.permissions

    # TODO postalAddress

    # TODO postalAddress.permissions

    l                                       = CharField(db_column='l', # XXX localityName
                                                validators=[validate_l], null=True, blank=True)
    l.permissions                           = { 'self': 'write', 'root': 'write' }

    # all other attributes not used

    class Meta:
        abstract = True


class __LdapInetOrgPerson(__LdapOrganizationalPerson):
    # objectclass ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson'
    #     DESC 'RFC2798: Internet Organizational Person'
    #     SUP organizationalPerson STRUCTURAL
    #     MAY (
    #         audio $ businessCategory $ carLicense $ departmentNumber $
    #         displayName $ employeeNumber $ employeeType $ givenName $
    #         homePhone $ homePostalAddress $ initials $ jpegPhoto $
    #         labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $
    #         roomNumber $ secretary $ uid $ userCertificate $
    #         x500uniqueIdentifier $ preferredLanguage $
    #         userSMIMECertificate $ userPKCS12
    #     )
    # )
    # from organizationalPerson

    # TODO jpegPhoto

    # TODO jpegPhoto.permissions

    labeledURI                              = CharField(db_column='labeledURI',
                                                validators=[validate_labeledURI], null=True, blank=True)
    labeledURI.permissions                  = { 'self': 'write', 'root': 'write' }

    # NOTE uid defined subsequently

    # all other attributes not used

    class Meta:
        abstract = True


class __LdapDebianAccount(ldapdb.models.Model):
    # objectclass ( 1.3.6.1.4.1.9586.100.4.1.1 NAME 'debianAccount'
    #     DESC 'Abstraction of an account with POSIX attributes and UTF8 support'
    #     SUP top AUXILIARY
    #     MUST ( cn $ uid $ uidNumber $ gidNumber )
    #     MAY (
    #         userPassword $ loginShell $ gecos $ homeDirectory $
    #         description $ mailDisableMessage $ sudoPassword $
    #         webPassword $ rtcPassword
    #     )
    # )

    # NOTE cn already previously

    uid                                     = CharField(db_column='uid',
                                                validators=[], primary_key=True)
    uid.permissions                         = { 'self': 'read', 'root': 'read' }

    uidNumber                               = IntegerField( db_column='uidNumber',
                                                validators=[])
    uidNumber.permissions                   = { 'self': 'read', 'root': 'read' }

    gidNumber                               = IntegerField(db_column='gidNumber',
                                                validators=[validate_gidNumber])
    gidNumber.permissions                   = { 'self': 'read', 'root': 'write' }

    userPassword                            = CharField(db_column='userPassword',
                                                validators=[validate_userPassword])
    userPassword.permissions                = { 'self': 'none', 'root': 'read' }

    loginShell                              = CharField(db_column='loginShell',
                                                validators=[validate_loginShell])
    loginShell.permissions                  = { 'self': 'read', 'root': 'write' }

    gecos                                   = CharField(db_column='gecos', # XXX overrides posixAccount!
                                                validators=[validate_gecos])
    gecos.permissions                       = { 'self': 'read', 'root': 'write' }

    # TODO homeDirectory - not stored in LDAP; required by posixAccount use a property?

    mailDisableMessage                      = CharField(db_column='mailDisableMessage',
                                                validators=[validate_mailDisableMessage], null=True, blank=True)
    mailDisableMessage.permissions          = { 'self': 'read', 'root': 'write' }

    sudoPassword                            = ListField(db_column='sudoPassword',
                                                validators=[validate_sudoPassword])
    sudoPassword.permissions                = { 'self': 'none', 'root': 'read' }

    webPassword                             = CharField(db_column='webPassword',
                                                validators=[validate_webPassword], null=True, blank=True)
    webPassword.permissions                 = { 'self': 'none', 'root': 'read' }

    rtcPassword                             = CharField(db_column='rtcPassword',
                                                validators=[validate_rtcPassword], null=True, blank=True)
    rtcPassword.permissions                 = { 'self': 'none', 'root': 'read' }

    class Meta:
        abstract = True


class __LdapDebianDeveloper(ldapdb.models.Model):
    # objectclass ( 1.3.6.1.4.1.9586.100.4.3.1 NAME 'debianDeveloper'
    #     DESC 'additional account attributes used by Debian'
    #     SUP top AUXILIARY
    #     MUST ( uid $ cn $ sn )
    #     MAY (
    #         accountComment $ accountStatus $ activity-from $ activity-pgp $
    #         allowedHost $ comment $ countryName $ dnsZoneEntry $ emailForward $
    #         icqUin $ ircNick $ jabberJID $ keyFingerPrint $ latitude $ longitude $
    #         mn $ onVacation $ privateSub $ sshRSAAuthKey $ supplementaryGid $
    #         access $ gender $ birthDate $ mailCallout $ mailGreylisting $ mailRBL $
    #         mailRHSBL $ mailWhitelist $ VoIP $ mailContentInspectionAction $
    #         bATVToken $ mailDefaultOptions
    #     )

    # NOTE uid defined previously

    # NOTE cn defined previously

    # NOTE sn defined previously

    # TODO accountComment

    # TODO accountComment.permissions

    accountStatus                           = CharField(db_column='accountStatus',
                                                validators=[validate_accountStatus], null=True, blank=True)
    accountStatus.permissions               = { 'self': 'none', 'root': 'read' }

    activityFrom                            = CharField(db_column='activity-from', max_length=300,
                                                validators=[validate_activityFrom], null=True, blank=True)
    activityFrom.permissions                = { 'self': 'none', 'root': 'read' }

    activityPGP                             = CharField(db_column='activity-pgp', max_length=300,
                                                validators=[validate_activityPGP], null=True, blank=True)
    activityPGP.permissions                 = { 'self': 'none', 'root': 'read' }

    allowedHost                             = ListField(db_column='allowedHost',
                                                validators=[validate_allowedHost])
    allowedHost.permissions                 = { 'self': 'none', 'root': 'write' }

    # TODO comment

    # TODO comment.permissions

    c                                       = CharField(db_column='c', # XXX in lieu of countryName?
                                                validators=[validate_c], null=True, blank=True)
    c.permissions                           = { 'self': 'write', 'root': 'write' }

    dnsZoneEntry                            = ListField(db_column='dnsZoneEntry',
                                                validators=[validate_dnsZoneEntry])
    dnsZoneEntry.permissions                = { 'self': 'write', 'root': 'write' }

    emailForward                            = CharField(db_column='emailForward',
                                                validators=[validate_emailForward], null=True, blank=True)
    emailForward.permissions                = { 'self': 'write', 'root': 'write' }

    icqUin                                  = CharField(db_column='icqUin',
                                                validators=[validate_icqUin], null=True, blank=True)
    icqUin.permissions                      = { 'self': 'write', 'root': 'write' }

    ircNick                                 = CharField(db_column='ircNick',
                                                validators=[validate_ircNick], null=True, blank=True)
    ircNick.permissions                     = { 'self': 'write', 'root': 'write' }

    jabberJID                               = CharField(db_column='jabberJID',
                                                validators=[validate_jabberJID], null=True, blank=True)
    jabberJID.permissions                   = { 'self': 'write', 'root': 'write' }

    keyFingerPrint                          = CharField(db_column='keyFingerPrint',
                                                validators=[validate_keyFingerPrint], null=True, blank=True)
    keyFingerPrint.permissions              = { 'self': 'read', 'root': 'write' }

    latitude                                = CharField(db_column='latitude',
                                                validators=[validate_latitude], null=True, blank=True)
    latitude.permissions                    = { 'self': 'write', 'root': 'write' }

    longitude                               = CharField(db_column='longitude',
                                                validators=[validate_longitude], null=True, blank=True)
    longitude.permissions                   = { 'self': 'write', 'root': 'write' }

    mn                                      = CharField(db_column='mn',
                                                validators=[validate_mn], null=True, blank=True)
    mn.permissions                          = { 'self': 'read', 'root': 'write' }

    # TODO onVacation

    # TODO onVacation.permissions

    privateSub                              = CharField(db_column='privateSub',
                                                validators=[validate_privateSub], null=True, blank=True)
    privateSub.permissions                  = { 'self': 'read', 'root': 'write' }

    sshRSAAuthKey                           = ListField(db_column='sshRSAAuthKey',
                                                validators=[validate_sshRSAAuthKey], null=True, blank=True)
    sshRSAAuthKey.permissions               = { 'self': 'write', 'root': 'write' }

    supplementaryGid                        = ListField(db_column='supplementaryGid',
                                                validators=[validate_supplementaryGid])
    supplementaryGid.permissions            = { 'self': 'read', 'root': 'write' }

    # TODO access

    # TODO access.permissions

    gender                                  = CharField(db_column='gender', # XXX use IntegerField instead?
                                                validators=[validate_gender], null=True, blank=True)
    gender.permissions                      = { 'self': 'write', 'root': 'write' }

    birthDate                               = CharField(db_column='birthDate',
                                                validators=[validate_birthDate], null=True, blank=True)
    birthDate.permissions                   = { 'self': 'write', 'root': 'write' }

    mailCallout                             = CharField(db_column='mailCallout',
                                                validators=[validate_mailCallout], null=True, blank=True)
    mailCallout.permissions                 = { 'self': 'write', 'root': 'write' }

    mailGreylisting                         = CharField(db_column='mailGreylisting',
                                                validators=[validate_mailGreylisting], null=True, blank=True)
    mailGreylisting.permissions             = { 'self': 'write', 'root': 'write' }

    mailRBL                                 = ListField(db_column='mailRBL',
                                                validators=[validate_mailRBL], null=True, blank=True)
    mailRBL.permissions                     = { 'self': 'write', 'root': 'write' }

    mailRHSBL                               = ListField(db_column='mailRHSBL',
                                                validators=[validate_mailRHSBL], null=True, blank=True)
    mailRHSBL.permissions                   = { 'self': 'write', 'root': 'write' }

    mailWhitelist                           = ListField(db_column='mailWhitelist',
                                                validators=[validate_mailWhitelist], null=True, blank=True)
    mailWhitelist.permissions               = { 'self': 'write', 'root': 'write' }

    # TODO VoIP

    # TODO VoIP.permissions

    mailContentInspectionAction             = CharField(db_column='mailContentInspectionAction',
                                                validators=[validate_mailContentInspectionAction], null=True, blank=True)
    mailContentInspectionAction.permissions = { 'self': 'write', 'root': 'write' }

    bATVToken                               = CharField(db_column='bATVToken',
                                                validators=[validate_bATVToken], null=True, blank=True)
    bATVToken.permissions                   = { 'self': 'write', 'root': 'write' }

    mailDefaultOptions                      = CharField(db_column='mailDefaultOptions',
                                                validators=[validate_mailDefaultOptions], null=True, blank=True)
    mailDefaultOptions.permissions          = { 'self': 'write', 'root': 'write' }

    # NOTE emailAddress = property(_get_emailAddress)

    # NOTE expire = property(_get_expire)

    # NOTE key = property(_get_key)

    # NOTE password = property(_get_password)

    class Meta:
        abstract = True


class __LdapAccount(ldapdb.models.Model):
    # objectclass ( 0.9.2342.19200300.100.4.5 NAME 'account'
    #     SUP top STRUCTURAL
    #     MUST ( userid )
    #     MAY (
    #         description $ seeAlso $ localityName $
    #         organizationName $ organizationalUnitName $ host
    #     )
    # )

    class Meta:
        abstract = True


class __LdapDebianRoleAccount(__LdapAccount):
    # objectclass ( 1.3.6.1.4.1.9586.100.4.3.3 NAME 'debianRoleAccount'
    #     DESC 'Abstraction of an account with POSIX attributes and UTF8 support'
    #     SUP account STRUCTURAL
    #     MAY (
    #         emailForward $ supplementaryGid $ allowedHost $ labeledURI $
    #         mailCallout $ mailGreylisting $ mailRBL $ mailRHSBL $
    #         mailWhitelist $ dnsZoneEntry $ mailContentInspectionAction $
    #         bATVToken $ mailDefaultOptions
    #     )
    # )

    emailForward                            = CharField(db_column='emailForward',
                                                validators=[validate_emailForward], null=True, blank=True)
    emailForward.permissions                = { 'self': 'write', 'root': 'write' }

    supplementaryGid                        = ListField(db_column='supplementaryGid',
                                                validators=[validate_supplementaryGid])
    supplementaryGid.permissions            = { 'self': 'read', 'root': 'write' }

    allowedHost                             = ListField(db_column='allowedHost',
                                                validators=[validate_allowedHost])
    allowedHost.permissions                 = { 'self': 'none', 'root': 'write' }

    labeledURI                              = CharField(db_column='labeledURI',
                                                validators=[validate_labeledURI], null=True, blank=True)
    labeledURI.permissions                  = { 'self': 'write', 'root': 'write' }

    mailCallout                             = CharField(db_column='mailCallout',
                                                validators=[validate_mailCallout], null=True, blank=True)
    mailCallout.permissions                 = { 'self': 'write', 'root': 'write' }

    mailGreylisting                         = CharField(db_column='mailGreylisting',
                                                validators=[validate_mailGreylisting], null=True, blank=True)
    mailGreylisting.permissions             = { 'self': 'write', 'root': 'write' }

    mailRBL                                 = ListField(db_column='mailRBL',
                                                validators=[validate_mailRBL], null=True, blank=True)
    mailRBL.permissions                     = { 'self': 'write', 'root': 'write' }

    mailRHSBL                               = ListField(db_column='mailRHSBL',
                                                validators=[validate_mailRHSBL], null=True, blank=True)
    mailRHSBL.permissions                   = { 'self': 'write', 'root': 'write' }

    mailWhitelist                           = ListField(db_column='mailWhitelist',
                                                validators=[validate_mailWhitelist], null=True, blank=True)
    mailWhitelist.permissions               = { 'self': 'write', 'root': 'write' }

    dnsZoneEntry                            = ListField(db_column='dnsZoneEntry',
                                                validators=[validate_dnsZoneEntry])
    dnsZoneEntry.permissions                = { 'self': 'write', 'root': 'write' }

    mailContentInspectionAction             = CharField(db_column='mailContentInspectionAction',
                                                validators=[validate_mailContentInspectionAction], null=True, blank=True)
    mailContentInspectionAction.permissions = { 'self': 'write', 'root': 'write' }

    bATVToken                               = CharField(db_column='bATVToken',
                                                validators=[validate_bATVToken], null=True, blank=True)
    bATVToken.permissions                   = { 'self': 'write', 'root': 'write' }

    mailDefaultOptions                      = CharField(db_column='mailDefaultOptions',
                                                validators=[validate_mailDefaultOptions], null=True, blank=True)
    mailDefaultOptions.permissions          = { 'self': 'write', 'root': 'write' }

    class Meta:
        abstract = True


class DebianHost(__LdapDebianServer):
    object_classes = ['debianServer']
    base_dn = 'ou=hosts,dc=debian,dc=org'

    def __str__(self):
        return self.hid

    def __unicode__(self):
        return self.hid

    def _get_hostnames(self):
        PurposeHostField = re.compile(r".*\[\[([\*\-]?[a-z0-9.\-]*)(?:\|.*)?\]\]")
        hostnames = [self.hostname]
        if self.hostname.endswith('.debian.org'):
            hostnames.append(self.hostname[:-len('.debian.org')])
        for purpose in self.purpose:
            m = PurposeHostField.match(purpose)
            if m:
               m = m.group(1)
               if m.startswith('*'):
                  continue # we ignore [[*..]] entries
               if m.startswith('-'):
                  m = m[1:]
               if m:
                  hostnames.append(m)
                  if m.endswith('.debian.org'):
                     hostnames.append(m[:-len('.debian.org')])
        return hostnames
    hostnames = property(_get_hostnames)

class DebianGroup(__LdapDebianGroup):
    object_classes = ['debianGroup']
    base_dn = 'ou=users,dc=debian,dc=org'

    def __str__(self):
        return self.gid

    def __unicode__(self):
        return self.gid


class __BaseClass(object):
    def __str__(self):
        return self.uid

    def __unicode__(self):
        return self.uid

    def do_delete(self, key, val=None):
        try:
            field = self._meta.get_field(key)
            if type(field) == ListField:
                method = '_do_delete_%s' % (key)
                if not hasattr(self, method):
                    raise Exception('delete function not implemented')
                getattr(self, method)(val)
            else:
                setattr(self, key, field.clean(val, self))
        except ValidationError as err:
            raise err
        except Exception as err:
            raise ValidationError(err)

    def do_update(self, key, val):
        try:
            field = self._meta.get_field(key)
            if type(field) == ListField:
                method = '_do_update_%s' % (key)
                if not hasattr(self, method):
                    raise Exception('update function not implemented')
                getattr(self, method)(val)
            else:
                setattr(self, key, field.clean(val, self))
        except ValidationError as err:
            raise err
        except Exception as err:
            raise ValidationError(err)

    def _do_delete_dnsZoneEntry(self, line):
        tokens = validate_dnsZoneEntry(line, mode='delete')
        label = '%s ' % (tokens[0])   # "foo " the trailing space is a guard
        query = ' '.join(tokens)      # "foo" or "foo IN A"
        records = [x for x in self.dnsZoneEntry if x.startswith(label)]
        for old_value in [x for x in records if x.startswith(query)]:
            self.dnsZoneEntry.remove(old_value)

    def _do_update_dnsZoneEntry(self, line):
        tokens = validate_dnsZoneEntry(line, mode='update')
        label = '%s ' % (tokens[0])   # "foo " the trailing space is a guard
        query = ' '.join(tokens[0:3]) # "foo IN A"
        new_value = ' '.join(tokens)  # "foo IN A 1.2.3.4"
        users = DebianUser.objects.filter(dnsZoneEntry__startswith=label)
        if len(users) == 0: # no user owns any resource record for the label
            self.dnsZoneEntry.append(new_value)
        if len(users) == 1: # one user owns resource record(s) for the label
            if users[0].uid == self.uid:       # if that user is me
                records = [x for x in self.dnsZoneEntry if x.startswith(query)]
                if tokens[2] in ['MX']:          # allow multiple MX records
                    if new_value not in records:    # add if does not exist
                        self.dnsZoneEntry.append(new_value)
                else:                            # but only one record for the rest
                    if len(records) == 0:           # add if does not exist
                        self.dnsZoneEntry.append(new_value)
                    elif len(records) == 1:         # else replace
                        old_value = records[0]
                        if new_value != old_value:
                            self.dnsZoneEntry.remove(old_value)
                            self.dnsZoneEntry.append(new_value)
                    else:
                        raise ValidationError('record cannot be added: multiple entries')
            else:
                raise ValidationError('record cannot be added: owned by another user')
        if len(users) >= 2: # two or more users own the record ... should never happen
            raise ValidationError('record cannot be added: owned by multiple users')

    def _do_delete_sshRSAAuthKey(self, line):
        tokens = validate_sshRSAAuthKey(key, mode='delete')
        query = tokens[3]
        self.__do_delete_ListField('sshRSAAuthKey', query)

    def _do_update_sshRSAAuthKey(self, line):
        tokens = validate_sshRSAAuthKey(key, mode='update')
        value = ''
        if tokens[0]: value += 'allowed_hosts=%s ' % (','.join(tokens[0]))
        if tokens[1]: value += '%s ' % (tokens[1])
        query = tokens[3]
        value += 'ssh-rsa %s' % (tokens[3])
        if comment: value += ' %s' % (tokens[4])
        self.__do_update_ListField('sshRSAAuthKey', query, value)

    def __do_delete_ListField(self, key, query):
        field = getattr(self, key)
        records = [x for x in field if query in x]
        for record in records:
            field.remove(record)

    def __do_update_ListField(self, key, query, new_value):
        # a given key can only be used once
        field = getattr(self, key)
        records = [x for x in field if query in x]
        if len(records) == 0:
            field.append(new_value)
        if len(records) == 1:
            old_value = records[0]
            if new_value != old_value: # change if different
                field.remove(old_value)
                field.append(new_value)
        if len(records) >= 2: # should not get here
            raise ValidationError('field cannot be updated: multiple entries exist!')

    def is_active(self):
        return self.is_not_retired() and hasattr(self, 'keyFingerPrint') and len(self.keyFingerPrint)

    def is_retired(self):
        if hasattr(self, 'accountStatus') and self.accountStatus:
            parts = self.accountStatus.split()
            status = parts[0]
            if status == 'inactive':
                return True
            elif status == 'memorial':
                return True
            elif status == 'retiring':
                # We'll give them a few extra days over what we said
                age = 6 * 31 * 24 * 60 * 60
                try:
                    return (time.time() - time.mktime(time.strptime(parts[1], '%Y-%m-%d'))) > age
                except IndexError:
                    return False
                except ValueError:
                    return False
        return False

    def is_not_retired(self):
        return not self.is_retired()

    def has_active_password(self):
        if not self.userPassword:
            return False
        if self.userPassword.upper() == '{CRYPT}*LK*':
            return False
        if self.userPassword.upper().startswith("{CRYPT}!"):
            return False
        return True

    def has_locked_password(self):
        return not self.has_active_password()

    def has_expired_password(self):
        if self.shadowExpire and self.shadowExpire < (time.time() / 3600 / 24):
            return True
        return False

    def is_guest_account(self):
        if settings.config.has_key('guestGid'):
            if self.gidNumber == settings.config['guestGid']:
                return True
        return False

    def is_not_guest_account(self):
        return not self.is_guest_account()

    def is_allowed_by_hostacl(self, desired_hostname):
        if not self.allowedHost:
            return False
        if desired_hostname in self.allowedHost:
            return True
        for entry in self.allowedHost:
            parts = entry.split(None, 1)
            if len(parts) == 1:
                continue
            (allowed_hostname, expire) = parts
            if allowed_hostname != desired_hostname:
                continue
            try:
                parsed = datetime.datetime.strptime(expire, '%Y%m%d')
            except ValueError:
                return False
            return parsed >= datetime.datetime.now()
        return False

    def _get_emailAddress(self):
        tokens = list()
        if self.cn: tokens.append(self.cn)
        if self.mn: tokens.append(self.mn)
        if self.sn: tokens.append(self.sn)
        return email.utils.formataddr((' '.join(tokens), '%s@debian.org' % (self.uid)))
    emailAddress = property(_get_emailAddress)

    def _get_expire(self):
        if not self.has_active_password():
            return '1' # not 0; see Debian Bug #308229
        else:
            return self.shadowExpire
    expire = property(_get_expire)

    def _get_key(self):
        rval = ''
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
            key = pyme.core.Data()
            ctx.op_export(self.keyFingerPrint.encode('ascii'), 0, key)
            key.seek(0,0)
            rval = key.read()
        except Exception as err:
            raise err
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir)
        return rval
    key = property(_get_key)

    def _get_password(self):
        p = self.userPassword
        if not p.upper().startswith('{CRYPT}') or len(p) > 50:
            return p
        else:
            return p[7:]
    password = property(_get_password)

    def validate(self):
        # TODO ... validate some additional business rules regarding ownership of DNS records
        errors = list()
        for fieldname in self._meta.get_all_field_names():
            field = self._meta.get_field(fieldname)
            values = getattr(self, fieldname)
            if type(values) is not list:
                values = [values]
            for value in values:
                try:
                    field.clean(value, self)
                except ValidationError as err:
                    errors.append(json.dumps([fieldname, value, err.messages]))
                except pyparsing.ParseException as err:
                    errors.append(json.dumps([fieldname, value, str(err)]))
        if errors:
            raise ValidationError(errors)

    def sudoPasswordForHost(self, host):
        sudoPasswordForHost = '*'
        for entry in self.sudoPassword:
            match = re.compile('^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) (confirmed:[0-9a-f]{40}|unconfirmed) ([a-z0-9.,*]+) ([^ ]+)$').match(entry)
            if match == None:
                continue # invalid entry so continue searching
            uuid = match.group(1)
            status = match.group(2)
            hostnames = match.group(3)
            sudoPassword = match.group(4)
            host_is_untrusted = ('UNTRUSTED' in host.exportOptions) or ('NOPASSWD' in host.exportOptions)
            apply_to_all_hosts = hostnames == '*'
            apply_to_this_host = host.hostname in hostnames.split(',')
            if status != 'confirmed:' + make_passwd_hmac(settings.config['hmac_key'], 'password-is-confirmed', 'sudo', self.uid, uuid, hostnames, sudoPassword):
                continue # entry is not confirmed so continue searching
            if not (apply_to_all_hosts or apply_to_this_host):
                continue # entry applies neither globally nor specifically so continue searching
            if apply_to_all_hosts and host_is_untrusted:
                continue # entry applies globally but this host is untrusted so continue searching
            sudoPasswordForHost = sudoPassword
            if apply_to_this_host:
                break    # entry applies specifically so stop searching
            # continue searching
        if len(sudoPasswordForHost) > 50:
            sudoPasswordForHost = '*'
        return sudoPasswordForHost


class DebianUser(__LdapInetOrgPerson, __LdapDebianAccount, __LdapShadowAccount, __LdapDebianDeveloper, __BaseClass):
    object_classes = ['debianDeveloper']
    base_dn = 'ou=users,dc=debian,dc=org'

    def _get_latitude_as_decdegree(self): # FIXME ick ... bad data in, bad data out
        return DecDegree(self.latitude, True)
    latitude_as_decdegree = property(_get_latitude_as_decdegree)

    def _get_longitude_as_decdegree(self): # FIXME ick ... bad data in, bad data out
        return DecDegree(self.longitude, True)
    longitude_as_decdegree = property(_get_longitude_as_decdegree)


class DebianRole(__LdapDebianAccount, __LdapShadowAccount, __LdapDebianRoleAccount, __BaseClass):
    object_classes = ['debianRoleAccount']
    base_dn = 'ou=users,dc=debian,dc=org'


class ReplayCache(models.Model):
    fingerprint = models.CharField(max_length=200)
    timestamp = models.DateTimeField()
    digest = models.CharField(max_length=200)

# vim: ts=4 sw=4 et ai si sm:
