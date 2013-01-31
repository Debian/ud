from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models
import ldap

ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')

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

    def update_list(self, key, val):
        (field, model, direct, m2m) = self._meta.get_field_by_name(key)
        #if direct and not m2m:
        #    setattr(self, key, field.clean(val, self))

# vim: ts=4 sw=4 et ai si sta:
