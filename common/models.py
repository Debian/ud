from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models
import ldap

ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')

class User(ldapdb.models.Model):
    base_dn = "ou=users,dc=debian,dc=org"
    object_classes = ['debianAccount']
    uidNumber = IntegerField(db_column='uidNumber', unique=True)
    uid = CharField(db_column='uid', max_length=200, primary_key=True)
    cn = CharField(db_column='cn', max_length=200)
    sn = CharField(db_column='sn', max_length=200)

    def __str__(self):
        return self.uid

    def __unicode__(self):
        return self.uid

