# Copyright (C) 2013 Luca Filipozzi <lfilipoz@debian.org>

from IPy import IP
from pyparsing import Keyword, LineEnd, LineStart, NoMatch, ParseException, Regex, Word
from pyparsing import alphas, alphanums, hexnums, nums
import re

# TODO move validation to django model
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

class MailGate:
    def __init__(self):
        expressions = NoMatch()

        show_expression = Keyword('show')
        expressions |= show_expression.setParseAction(self.do_show)

        reset_password_expression = Keyword('reset') + Keyword('password')
        expressions |= reset_password_expression.setParseAction(self.do_reset_password)

        update_expression = Keyword('update') + Keyword('bATVToken') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('bATVToken')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('birthDate') + Regex(r'[0-9]{4,4}[01][0-9][0-3][0-9]')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('birthDate')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('c') + Regex(r'..')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('c')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('A') + Word(nums+'.')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_A)
        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('AAAA') + Word(hexnums+':')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_AAAA)
        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('CNAME') + Regex(r'[-\w.]+\.')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_CNAME)
        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('MX') + Regex(r'\d{1,3}') + Regex(r'[-\w.]+\.')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_MX)
        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('TXT') + Regex(r'[-\d. a-z\t<>@]+')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_TXT)
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('emailForward') + Regex(r'[^<>@]+@.+')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('emailForward')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('facsimileTelephoneNumber') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('facsimileTelephoneNumber')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('gender') + (Keyword('male') | Keyword('female') | Keyword('unspecified'))
        expressions |= update_expression.setParseAction(self.do_update_gender)

        update_expression = Keyword('update') + Keyword('icqUin') + Regex(r'\d+')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('icqUin')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('ircNick') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('ircNick')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('jabberJID') + Regex(r'[^<>@]+@.+')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('jabberJID')
        expressions |= delete_expression.setParseAction(self.do_delete)

        # TODO 'update jpegPhoto'

        update_expression = Keyword('update') + Keyword('l') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('l')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('labeledURI') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('labeledURI')
        expressions |= delete_expression.setParseAction(self.do_delete)

        # TODO 'update latitude'

        update_expression = Keyword('update') + Keyword('loginShell') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)

        # TODO 'update longitude'

        update_expression = Keyword('update') + Keyword('mailCallout') + (Keyword('TRUE') | Keyword('FALSE'))
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('mailCallout')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('mailContentInspectionAction') + (Keyword('reject') | Keyword('blackhole') | Keyword('markup'))
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('mailContentInspectionAction')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('mailDefaultOptions') + (Keyword('TRUE') | Keyword('FALSE'))
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('mailDefaultOptions')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('mailDisableMessage') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('mailDisableMessage')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('mailGreylisting') + (Keyword('TRUE') | Keyword('FALSE'))
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('mailGreylisting')
        expressions |= delete_expression.setParseAction(self.do_delete)

        # TODO 'update mailRBL'

        # TODO 'update mailRHSBL'

        # TODO 'update mailWhitelist'

        update_expression = Keyword('update') + Keyword('onVacation') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('onVacation')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('postalAddress') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('postalAddress')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('postalCode') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('postalCode')
        expressions |= delete_expression.setParseAction(self.do_delete)

        # TODO 'update sshRSAAuthKey'

        update_expression = Keyword('update') + Keyword('telephoneNumber') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('telephoneNumber')
        expressions |= delete_expression.setParseAction(self.do_delete)

        update_expression = Keyword('update') + Keyword('VoIP') + Regex(r'.*')
        expressions |= update_expression.setParseAction(self.do_update)
        delete_expression = Keyword('delete') + Keyword('VoIP')
        expressions |= delete_expression.setParseAction(self.do_delete)

        self.grammar = LineStart() + expressions + LineEnd()
        self.grammar.setFailAction(self.failure)

    def process_commands(self, user, commands):
        self.user = user
        self.result = []

        # process the commands
        commit = True
        for line in commands:
            if line == '-- ': # stop processing if email signature marker seen
                break
            try:
                self.grammar.parseString(line)
            except ParseException:
                commit = False

        # commit the changes
        if commit:
            try:
                user.save()
            except Exception as err:
                self.result.append('==> fatal error: %s' % err)
        else:
            self.result.append('==> parse error - no changes saved')

        return self.result

    def success(self, s, res):
        self.result.append('> %s' % s)
        self.result.append('ack: %s' % res)

    def failure(self, s, loc, expr, err):
        self.result.append('> %s' % s)
        self.result.append('nak: %s' % err)
        raise ParseException(err)

    def do_delete(self, s, loc, tokens):
        try:
            key = tokens[1]
            self.delete(key)
            self.success(s, 'do delete: %s' % (key))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_show(self, s, loc, tokens):
        try:
            self.success(s, 'do show')
            #self.result.append(self.user)
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_reset_password(self, s, loc, tokens):
        try: # TODO
            self.success(s, 'do reset password')
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update(self, s, loc, tokens):
        try:
            key = tokens[1]
            val = tokens[2]
            self.user.update(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_A(self, s, loc, tokens):
        try:
            key = tokens[1]
            name = tokens[2]
            if not is_valid_hostname(name) or name.endswith('.debian.net'):
                raise Exception("'%s' is not a valid label" % name)
            address = IP(tokens[5])
            if address.version() != 4:
                raise Exception("'%s' is not a valid IPv4 address" % address)
            val = ('%s IN A %s') % (name, address)
            self.user.update_list(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_AAAA(self, s, loc, tokens):
        try:
            key = tokens[1]
            name = tokens[2]
            if not is_valid_hostname(name) or name.endswith('.debian.net'):
                raise Exception("'%s' is not a valid label" % name)
            address = IP(tokens[5])
            if address.version() != 6:
                raise Exception("'%s' is not a valid IPv6 address" % address)
            val = ('%s IN AAAA %s') % (name, address)
            self.user.update_list(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_CNAME(self, s, loc, tokens):
        try:
            key = tokens[1]
            name = tokens[2]
            if not is_valid_hostname(name) or name.endswith('.debian.net'):
                raise Exception("'%s' is not a valid label" % name)
            cname = tokens[5]
            if not is_valid_hostname(cname):
                raise Exception("'%s' is not a valid hostname" % cname)
            val = ('%s IN CNAME %s') % (name, cname)
            self.user.update_list(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_MX(self, s, loc, tokens):
        try:
            key = tokens[1]
            name = tokens[2]
            if not is_valid_hostname(name) or name.endswith('.debian.net'):
                raise Exception("'%s' is not a valid label" % name)
            preference = tokens[5]
            exchange = tokens[6]
            if not is_valid_hostname(exchange):
                raise Exception("'%s' is not a valid hostname" % exchange)
            val = ('%s IN MX %s %s') % (tokens[2], preference, exchange)
            self.user.update_list(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_TXT(self, s, loc, tokens):
        try:
            key = tokens[1]
            name = tokens[2]
            if not is_valid_hostname(name) or name.endswith('.debian.net'):
                raise Exception("'%s' is not a valid label" % name)
            txtdata = tokens[5]
            val = ('%s IN TXT %s') % (name, txtdata)
            self.user.update_list(key, val)
            self.success(s, "do update: %s <- '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_gender(self, s, loc, tokens):
        try:
            key = tokens[1]
            val = {'male': 1, 'female': 2, 'unspecified': 9}[tokens[2]]
            self.user.update(key, val)
            self.success(s, "do update: %s -< '%s'" % (key, val))
        except Exception as err:
            self.failure(s, loc, None, err)

# vim: set ts=4 sw=4 et ai si sta:
