from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models
import ldap
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')

import re
from IPy import IP

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

def validate_bATVToken(val):
    return

def validate_birthDate(val):
    return

def validate_c(val):
    if len(val) < 2:
        raise ValidationError('value is too short')
    if len(val) > 2:
        raise ValidationError('value is too long')

def validate_dnsZoneEntry(val):
    return

def validate_emailForward(val):
    try:
        validate_email(val)
    except:
        raise ValidationError('value is not a valid email address')

def validate_facsimileTelephoneNumber(val):
    return

def validate_ircNick(val):
    return

def validate_l(val):
    return

class User(ldapdb.models.Model):
    base_dn = 'ou=users,dc=debian,dc=org'
    object_classes = ['debianAccount', 'debianDeveloper', 'inetOrgPerson', 'shadowAccount']
    bATVToken                   = CharField(    db_column='bATVToken',                validators=[validate_bATVToken])
    birthDate                   = CharField(    db_column='birthDate',                validators=[validate_birthDate])
    c                           = CharField(    db_column='c',                        validators=[validate_c])
    cn                          = CharField(    db_column='cn',                       editable = False)
    dnsZoneEntry                = ListField(    db_column='dnsZoneEntry',             validators=[validate_dnsZoneEntry])
    emailForward                = CharField(    db_column='emailForward',             validators=[validate_emailForward])
    facsimileTelephoneNumber    = CharField(    db_column='facsimileTelephoneNumber', validators=[validate_facsimileTelephoneNumber])
    #gender
    #icqUin
    ircNick                     = CharField(    db_column='ircNick',                  validators=[validate_ircNick])
    #jabberJID
    #jpegPhoto
    keyFingerPrint              = CharField(    db_column='keyFingerPrint',           editable = False)
    l                           = CharField(    db_column='l',                        validators=[validate_l])
    #labeledURI
    #latitude
    #loginShell
    #longitude
    #mailCallout
    #mailContentInspectionAction
    #mailDefaultOptions
    #mailDisableMessage
    #mailGreylisting
    #mailRBL
    #mailRHSBL
    #mailWhitelist
    #onVacation
    #postalAddress
    #postalCode
    sn                          = CharField(    db_column='sn',                       editable = False)
    #telephoneNumber
    #VoIP
    uid                         = CharField(    db_column='uid',                      editable = False, primary_key=True)
    uidNumber                   = IntegerField( db_column='uidNumber',                editable = False)

    def __str__(self):
        return self.uid

    def __unicode__(self):
        return self.uid

    def update(self, key, val):
        (field, model, direct, m2m) = self._meta.get_field_by_name(key)
        if direct and not m2m:
            setattr(self, key, field.clean(val, self))

    def update_dnsZoneEntry_IN_A(self, name, address):
        validate_pqdn(name)
        validate_ipv4(address)
        val = '%s IN A %s' % (name.lower(), address)
        # TODO update

    def update_dnsZoneEntry_IN_AAAA(self, name, address):
        validate_pqdn(name)
        validate_ipv6(address)
        val = '%s IN AAAA %s' % (name.lower(), address)
        # TODO update

    def update_dnsZoneEntry_IN_CNAME(self, name, cname):
        validate_pqdn(name)
        validate_fqdn(cname)
        val = '%s IN CNAME %s' % (name.lower(), cname.lower())

    def update_dnsZoneEntry_IN_MX(self, name, preference, exchange):
        validate_pqdn(name)
        # TODO ensure preference is numeric 1-999
        validate_fqdn(exchange)
        val = '%s IN MX %s %s' % (name.lower(), preference, exchange.lower())
        # TODO update

    def update_dnsZoneEntry_IN_TXT(self, name, txtdata):
        validate_pqdn(name)
        # TODO validate txtdata
        val = '%s IN TXT %s' % (name.lower(), txtdata)
        # TODO update

    def update_list(self, key, val):
        (field, model, direct, m2m) = self._meta.get_field_by_name(key)
        #if direct and not m2m:
        #    setattr(self, key, field.clean(val, self))

# vim: ts=4 sw=4 et ai si sta:
