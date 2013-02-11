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

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models
import ldap
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')

import pyparsing
from pyparsing import CaselessKeyword, Keyword, LineEnd, LineStart, Literal, Optional, QuotedString, Regex, Suppress, Word
from pyparsing import alphanums, delimitedList

import base64
import datetime
import json
import hashlib
import struct
import time
import re
from IPy import IP
from M2Crypto import RSA, m2

import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
h = NullHandler()
logging.getLogger('pycountry.db').addHandler(h)
import pycountry

# not IDN ready
def validate_dns_labels(val):
    disallowed = re.compile('[^A-Z\d-]', re.IGNORECASE)
    for label in val.split('.'):
        if len(label) == 0:
            raise ValidationError('label in name is too short')
        if len(label) > 63:
            raise ValidationError('label in name is too long')
        if label.startswith('-') or label.endswith('-'):
            raise ValidationError('label in name begins/ends with hyphen')
        if disallowed.search(label):
            raise ValidationError('label in name contains invalid characters')

# fully qualified domain name
def validate_fqdn(val):
    if len(val) > 255:
        raise ValidationError('name is too long')
    if not val.endswith('.'):
        raise ValidationError('name does not end in .')
    validate_dns_labels(val[:-1])
    
# partially qualified domain name
def validate_pqdn(val):
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

def validate_accountStatus(val):
    return # TODO

def validate_allowedHost(val):
    try:
        if not Host.objects.filter(hostname=val):
            raise
    except:
        ValidationError('unknown host')

def validate_bATVToken(val):
    return # TODO

def validate_birthDate(val):
    return # TODO

def validate_c(val):
    try:
        if val.upper() not in ['AC', 'EU', 'FX', 'UK', 'YU']:
            pycountry.countries.get(alpha2=val.upper())
    except:
        raise ValidationError('value is not a valid ISO3166-2 country code')

def validate_cn(val):
    return # TODO

def validate_dnsZoneEntry(val):
    return # TODO ... but ListField

def validate_emailForward(val):
    try:
        validate_email(val)
    except:
        raise ValidationError('value is not a valid for emailForward')

def validate_facsimileTelephoneNumber(val):
    return # TODO

def validate_gecos(val):
    return # TODO

def validate_gidNumber(val):
    try:
        if val not in [65534] and not Group.objects.filter(gidNumber__exact=val):
            raise
    except:
        raise ValidationError('unknown group')

def validate_ircNick(val):
    return # TODO

def validate_keyFingerPrint(val):
    return # TODO

def validate_l(val):
    return # TODO

def validate_loginShell(val):
    try:
        loginShells = [ '/bin/sh', '/bin/false', '/bin/bash', '/usr/bin/bash', '/bin/csh', '/usr/bin/csh', '/bin/ksh', '/usr/bin/ksh', '/bin/tcsh', '/usr/bin/tcsh', '/bin/zsh', '/usr/bin/zsh']
        if val not in loginShells:
            raise
    except:
        raise ValidationError('value is not a valid login shell')

def validate_sshRSAAuthKey(val):
    return # TODO ... but ListField

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

    key_size = len(created_key)
    if key_size not in [1024, 2048, 4096]:
        raise ValidationError('key must have size 1024, 2048 or 4096 bits')

    fingerprint = hashlib.md5(encoded_key).hexdigest()[12:]
    for line in file('/usr/share/ssh/blacklist.RSA-%d' % (key_size)):
        if fingerprint == line.rstrip():
            raise ValidationError('key is weak (debian openssl fiasco)')

def validate_sshRSAAuthKey_options(options):
    flag = (
        # reject flags: cert-authority
        CaselessKeyword('no-agent-forwarding') |
        CaselessKeyword('no-port-forwarding') |
        CaselessKeyword('no-pty') |
        CaselessKeyword('no-user-rc') |
        CaselessKeyword('no-X11-forwarding')
    )
    key = (
        # reject keys: principals, tunnel
        CaselessKeyword('command') |
        CaselessKeyword('environment') |
        CaselessKeyword('from') |
        CaselessKeyword('permitopen')
    )
    keyval = key + Literal('=') + QuotedString('"', unquoteResults=False)
    valid_options = LineStart() + delimitedList(flag | keyval, combine=True) + LineEnd()
    try:
        valid_options.parseString(options)
    except:
        raise ValidationError('options are not valid')

def validate_sshRSAAuthKey_allowed_hosts(allowed_hosts):
    if not set(allowed_hosts).issubset(set([x.hostname for x in Host.objects.all()])):
        raise ValidationError('unknown host in allowed_hosts')

def validate_supplementaryGid(val):
    try:
        if '@' in val:
            (val,hostname) = val.split('@', 1)
            if not Host.objects.filter(hostname=hostname):
                raise
        Group.objects.get(gid__exact=val)
    except:
        raise ValidationError('not a valid group')


class Host(ldapdb.models.Model):
    base_dn = 'ou=hosts,dc=debian,dc=org'
    object_classes = ['debianServer']
    allowedGroups               = ListField(    db_column='allowedGroups',                  validators=[])                          # TODO validator
    architecture                = CharField(    db_column='architecture',                   validators=[])                          # TODO validator
    dnsTTL                      = CharField(    db_column='dnsTTL',                         validators=[])                          # TODO validator
    exportOptions               = ListField(    db_column='exportOptions',                  validators=[])                          # TODO validator
    hid                         = CharField(    db_column='host',                           validators=[], primary_key=True)        # TODO validator
    hostname                    = CharField(    db_column='hostname',                       validators=[])                          # TODO validator
    ipHostNumber                = ListField(    db_column='ipHostNumber',                   validators=[])                          # TODO validator
    machine                     = CharField(    db_column='machine',                        validators=[])                          # TODO validator
    mXRecord                    = ListField(    db_column='mXRecord',                       validators=[])                          # TODO validator
    sshRSAHostKey               = ListField(    db_column='sshRSAHostKey',                  validators=[], blank=True)              # TODO validator

    def __str__(self):
        return self.hid

    def __unicode__(self):
        return self.hid


class Group(ldapdb.models.Model):
    base_dn = 'ou=users,dc=debian,dc=org'
    object_classes = ['debianGroup']
    gid                         = CharField(    db_column='gid',                            validators=[], primary_key=True)        # TODO validator
    gidNumber                   = IntegerField( db_column='gidNumber',                      validators=[])                          # TODO validator
    subGroup                    = ListField(    db_column='subGroup',                       validators=[])                          # TODO validator

    def __str__(self):
        return self.gid

    def __unicode__(self):
        return self.gid


class User(ldapdb.models.Model):
    base_dn = 'ou=users,dc=debian,dc=org'
    object_classes = ['debianAccount']
    accountStatus               = CharField(    db_column='accountStatus',                  validators=[validate_accountStatus], blank=True)
    activityFrom                = CharField(    db_column='activity-from',                  validators=[], blank=True)              # TODO validator
    activityPGP                 = CharField(    db_column='activity-pgp',                   validators=[], blank=True)              # TODO validator
    allowedHost                 = ListField(    db_column='allowedHost',                    validators=[validate_allowedHost])
    bATVToken                   = CharField(    db_column='bATVToken',                      validators=[validate_bATVToken], blank=True)
    birthDate                   = CharField(    db_column='birthDate',                      validators=[validate_birthDate], blank=True)
    c                           = CharField(    db_column='c',                              validators=[validate_c], blank=True)
    cn                          = CharField(    db_column='cn',                             validators=[validate_cn])
    dnsZoneEntry                = ListField(    db_column='dnsZoneEntry',                   validators=[validate_dnsZoneEntry])
    emailForward                = CharField(    db_column='emailForward',                   validators=[validate_emailForward], blank=True)
    facsimileTelephoneNumber    = CharField(    db_column='facsimileTelephoneNumber',       validators=[validate_facsimileTelephoneNumber], blank=True)
    gecos                       = CharField(    db_column='gecos',                          validators=[validate_gecos])
    gidNumber                   = IntegerField( db_column='gidNumber',                      validators=[validate_gidNumber])
    # TODO gender
    # TODO homeDirectory - not stored in LDAP; required by posixAccount use a property?
    # TODO icqUin
    ircNick                     = CharField(    db_column='ircNick',                        validators=[validate_ircNick], blank=True)
    # TODO jabberJID
    # TODO jpegPhoto
    keyFingerPrint              = CharField(    db_column='keyFingerPrint',                 validators=[validate_keyFingerPrint], blank=True)
    l                           = CharField(    db_column='l',                              validators=[validate_l], blank=True)
    # TODO labeledURI
    latitude                    = CharField(    db_column='latitude',                       validators=[], blank=True)              # TODO validator
    loginShell                  = CharField(    db_column='loginShell',                     validators=[validate_loginShell])
    longitude                   = CharField(    db_column='longitude',                      validators=[], blank=True)              # TODO validator
    # TODO mailCallout
    mailContentInspectionAction = CharField(    db_column='mailContentInspectionAction',    validators=[], blank=True)              # TODO validator
    mailDefaultOptions          = CharField(    db_column='mailDefaultOptions',             validators=[], blank=True)              # TODO validator
    mailDisableMessage          = CharField(    db_column='mailDisableMessage',             validators=[], blank=True)              # TODO validator
    mailCallout                 = CharField(    db_column='mailCallout',                    validators=[], blank=True)              # TODO validator
    mailGreylisting             = CharField(    db_column='mailGreylisting',                validators=[], blank=True)              # TODO validator
    mailRBL                     = ListField(    db_column='mailRBL',                        validators=[], blank=True)              # TODO validator
    mailRHSBL                   = ListField(    db_column='mailRHSBL',                      validators=[], blank=True)              # TODO validator
    mailWhitelist               = ListField(    db_column='mailWhitelist',                  validators=[], blank=True)              # TODO validator
    # TODO onVacation
    # TODO postalAddress
    # TODO postalCode
    privateSub                  = CharField(    db_column='privateSub',                     validators=[], blank=True)              # TODO validator
    shadowExpire                = IntegerField( db_column='shadowExpire',                   validators=[])                          # TODO validator
    shadowInactive              = IntegerField( db_column='shadowInactive',                 validators=[])                          # TODO validator
    shadowLastChange            = IntegerField( db_column='shadowLastChange',               validators=[])                          # TODO validator
    shadowMax                   = IntegerField( db_column='shadowMax',                      validators=[])                          # TODO validator
    shadowMin                   = IntegerField( db_column='shadowMin',                      validators=[])                          # TODO validator
    shadowWarning               = IntegerField( db_column='shadowWarning',                  validators=[])                          # TODO validator
    sn                          = CharField(    db_column='sn',                             validators=[])                          # TODO validator
    sshRSAAuthKey               = ListField(    db_column='sshRSAAuthKey',                  validators=[validate_sshRSAAuthKey], blank=True)
    supplementaryGid            = ListField(    db_column='supplementaryGid',               validators=[validate_supplementaryGid])
    # TODO telephoneNumber
    # TODO VoIP
    uid                         = CharField(    db_column='uid',                            validators=[], primary_key=True)        # TODO validator
    uidNumber                   = IntegerField( db_column='uidNumber',                      validators=[])                          # TODO validator
    userPassword                = CharField(    db_column='userPassword',                   validators=[])                          # TODO validator
    voipPassword                = CharField(    db_column='voipPassword',                   validators=[], blank=True)              # TODO validator
    webPassword                 = CharField(    db_column='webPassword',                    validators=[], blank=True)              # TODO validator

    def __str__(self):
        return self.uid

    def __unicode__(self):
        return self.uid

    def update(self, key, val):
        (field, model, direct, m2m) = self._meta.get_field_by_name(key)
        if direct and not m2m:
            setattr(self, key, field.clean(val, self))

    def __delete_dnsZoneEntry(self, query, delete_all=False):
        users = User.objects.filter(dnsZoneEntry__startswith=query)
        if len(users) == 1: # one user owns the resource record
            if users[0].uid == self.uid: # if that user is me
                records = [x for x in self.dnsZoneEntry if x.startswith(query)]
                if delete_all:
                    for old_value in records:
                        self.dnsZoneEntry.remove(old_value)
                else:
                    if len(records) == 1:
                        old_value = records[0]
                        self.dnsZoneEntry.remove(old_value)
                    else:
                        raise ValidationError('record cannot be deleted: multiple records')
            else:
                raise ValidationError('record cannot be deleted: owned by another user')
        if len(users) >= 2: # two or more users own the record ... should never happen
            raise ValidationError('record cannot be deleted: owned by multiple users')

    def __update_dnsZoneEntry(self, query, new_value, allow_multiple=False):
        users = User.objects.filter(dnsZoneEntry__startswith=query)
        if len(users) == 0: # no user owns the resource record
            self.dnsZoneEntry.append(new_value)
        if len(users) == 1: # one user owns the resource record
            if users[0].uid == self.uid: # if that user is me
                records = [x for x in self.dnsZoneEntry if x.startswith(query)]
                if allow_multiple:
                    if new_value not in records:
                        self.dnsZoneEntry.append(new_value)
                else:
                    if len(records) == 1:
                        old_value = records[0]
                        if new_value != old_value: # change if different
                            self.dnsZoneEntry.remove(old_value)
                            self.dnsZoneEntry.append(new_value)
                    else:
                        raise ValidationError('record cannot be added: multiple entries')
            else:
                raise ValidationError('record cannot be added: owned by another user')
        if len(users) >= 2: # two or more users own the record ... should never happen
            raise ValidationError('record cannot be added: owned by multiple users')

    def delete_dnsZoneEntry(self, name):
        validate_pqdn(name)
        query = '%s' % (name.lower())
        self.__delete_dnsZoneEntry(query, True)

    def delete_dnsZoneEntry_IN_A(self, name):
        validate_pqdn(name)
        query = '%s IN A' % (name.lower())
        self.__delete_dnsZoneEntry(query)

    def update_dnsZoneEntry_IN_A(self, name, address):
        validate_pqdn(name)
        validate_ipv4(address)
        query = '%s IN A' % (name.lower())
        value = '%s IN A %s' % (name.lower(), address)
        self.__update_dnsZoneEntry(query, value)

    def delete_dnsZoneEntry_IN_AAAA(self, name):
        validate_pqdn(name)
        query = '%s IN AAAA' % (name.lower())
        self.__delete_dnsZoneEntry(query)

    def update_dnsZoneEntry_IN_AAAA(self, name, address):
        validate_pqdn(name)
        validate_ipv6(address)
        query = '%s IN AAAA' % (name.lower())
        value = '%s IN AAAA %s' % (name.lower(), address)
        self.__update_dnsZoneEntry(query, value)

    def delete_dnsZoneEntry_IN_CNAME(self, name):
        validate_pqdn(name)
        query = '%s IN CNAME' % (name.lower())
        self.__delete_dnsZoneEntry(query)

    def update_dnsZoneEntry_IN_CNAME(self, name, cname):
        validate_pqdn(name)
        validate_fqdn(cname)
        query = '%s IN CNAME' % (name.lower())
        value = '%s IN CNAME %s' % (name.lower(), cname.lower())
        self.__update_dnsZoneEntry(query, value)

    def delete_dnsZoneEntry_IN_MX(self, name):
        validate_pqdn(name)
        query = '%s IN MX' % (name.lower())
        self.__delete_dnsZoneEntry(query, True)

    def update_dnsZoneEntry_IN_MX(self, name, preference, exchange):
        validate_pqdn(name)
        if int(preference) < 1 or int(preference) > 999:
            raise ValidationError('preference %s out of range' % preference)
        validate_fqdn(exchange)
        query = '%s IN MX' % (name.lower())
        value = '%s IN MX %d %s' % (name.lower(), int(preference), exchange.lower())
        self.__update_dnsZoneEntry(query, value, True)

    def delete_dnsZoneEntry_IN_TXT(self, name):
        validate_pqdn(name)
        query = '%s IN TXT' % (name.lower())
        self.__delete_dnsZoneEntry(query)

    def update_dnsZoneEntry_IN_TXT(self, name, txtdata):
        validate_pqdn(name)
        # TODO validate txtdata
        query = '%s IN TXT' % (name.lower())
        value = '%s IN TXT %s' % (name.lower(), txtdata)
        self.__update_dnsZoneEntry(query, value)

    def __delete_ListField(self, key, query):
        field = getattr(self, key)
        records = [x for x in field if query in x]
        for record in records:
            field.remove(record)

    # a given key can only be used once
    def __update_ListField(self, key, query, new_value):
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

    def delete_sshRSAAuthKey(self, key):
        validate_sshRSAAuthKey_key(key)
        query = key
        self.__delete_ListField('sshRSAAuthKey', query)

    def update_sshRSAAuthKey(self, key, allowed_hosts=[], options=None, comment=None):
        value = ''
        if allowed_hosts:
            validate_sshRSAAuthKey_allowed_hosts(allowed_hosts)
            value = 'allowed_hosts=%s ' % (','.join(allowed_hosts))
        if options:
            validate_sshRSAAuthKey_options(options)
            value += '%s ' % (options)
        validate_sshRSAAuthKey_key(key)
        query = key
        value += 'ssh-rsa %s' % (key)
        if comment:
            # TODO validate comment
            value += ' %s' % (comment)
        self.__update_ListField('sshRSAAuthKey', query, value)

    def is_active(self):
        return self.is_not_retired() and len(self.keyFingerPrint)

    def is_retired(self):
        if self.accountStatus:
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

    def _get_password(self):
        p = self.userPassword
        if not p.upper().startswith('{CRYPT}') or len(p) > 50:
            return p
        else:
            return p[7:]
    password = property(_get_password)

    def _get_emailAddress(self):
        tokens = list()
        if self.cn: tokens.append(self.cn)
        if self.sn: tokens.append(self.sn)
        tokens.append('<%s@debian.org>' % (self.uid))
        return ' '.join(tokens)
    emailAddress = property(_get_emailAddress)

    def _get_expire(self):
        if not self.has_active_password():
            return '1' # not 0; see Debian Bug #308229
        else:
            return self.shadowExpire
    expire = property(_get_expire)
    
    def validate(self):
        errors = list()
        for fieldname in self._meta.get_all_field_names():
            (field, model, direct, m2m) = self._meta.get_field_by_name(fieldname)
            values = getattr(self, fieldname)
            if type(values) is not list:
                values = [values]
            for value in values:
                try:
                    field.clean(value, self)
                except ValidationError as err:
                    errors.append(json.dumps([fieldname, value, err.messages]))
        if errors:
            raise ValidationError(errors)

# vim: ts=4 sw=4 et ai si sta:
