# Copyright (C) 2013 Luca Filipozzi <lfilipoz@debian.org>

from django.core.exceptions import ValidationError

from pyparsing import Keyword, LineEnd, LineStart, NoMatch, ParseException, Regex, Word
from pyparsing import alphas, alphanums, hexnums, nums

class MailGateException(Exception):
    def __init__(self, message):
        super(MailGateException, self).__init__(message)

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
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('A')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry_IN_A)

        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('AAAA') + Word(hexnums+':')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_AAAA)
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('AAAA')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry_IN_AAAA)

        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('CNAME') + Regex(r'[-\w.]+\.')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_CNAME)
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('CNAME')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry_IN_CNAME)

        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('MX') + Regex(r'\d{1,3}') + Regex(r'[-\w.]+\.')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_MX)
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('MX')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry_IN_MX)

        update_expression = Keyword('update') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('TXT') + Regex(r'[-\d. a-z\t<>@]+')
        expressions |= update_expression.setParseAction(self.do_update_dnsZoneEntry_IN_TXT)
        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w') + Keyword('IN') + Keyword('TXT')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry_IN_TXT)

        delete_expression = Keyword('delete') + Keyword('dnsZoneEntry') + Regex(r'[-\w.]+\w')
        expressions |= delete_expression.setParseAction(self.do_delete_dnsZoneEntry)

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

    def process_commands(self, user, commands, dryrun=False):
        self.user = user
        self.rval = []
        commit = True
        for line in commands: # process the commands
            if line == '-- ': # stop processing if email signature marker seen
                break
            try:
                self.grammar.parseString(line)
            except MailGateException:
                commit = False
        if commit: # commit the changes
            if not dryrun:
                try:
                    user.save()
                except Exception as err:
                    self.rval.append('==> fatal error: %s' % err)
            else:
                self.rval.append('==> dryrun: no changes saved')
        else:
            self.rval.append('==> parse error: no changes saved')
        return self.rval

    def success(self, s, res):
        self.rval.append('> %s' % s)
        self.rval.append('ack: %s' % res)

    def failure(self, s, loc, expr, err):
        self.rval.append('> %s' % s)
        if type(err) == ValidationError:
            for message in err.messages:
                self.rval.append('nak: %s' % message)
        else:
            self.rval.append('nak: %s' % err)
        raise MailGateException('mailgate error')

    def do_delete(self, s, loc, tokens):
        try:
            self.delete(tokens[1])
            self.success(s, 'do delete: %s' % (tokens[1]))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_show(self, s, loc, tokens):
        try: # TODO
            self.success(s, 'do show')
            #self.rval.append(self.user)
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_reset_password(self, s, loc, tokens):
        try: # TODO
            self.success(s, 'do reset password')
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update(self, s, loc, tokens):
        try:
            self.user.update(tokens[1], tokens[2])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], tokens[2]))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry_IN_A(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry_IN_A(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_A(self, s, loc, tokens):
        try:
            self.user.update_dnsZoneEntry_IN_A(tokens[2], tokens[5])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry_IN_AAAA(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry_IN_AAAA(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_AAAA(self, s, loc, tokens):
        try:
            self.user.update_dnsZoneEntry_IN_AAAA(tokens[2], tokens[5])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry_IN_CNAME(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry_IN_CNAME(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_CNAME(self, s, loc, tokens):
        try:
            self.user.update_dnsZoneEntry_IN_CNAME(tokens[2], tokens[5])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry_IN_MX(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry_IN_MX(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_MX(self, s, loc, tokens):
        try:
            self.user.update_dnsZoneEntry_IN_MX(tokens[2], tokens[5], tokens[6])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_delete_dnsZoneEntry_IN_TXT(self, s, loc, tokens):
        try:
            self.user.delete_dnsZoneEntry_IN_CNAME(tokens[2])
            self.success(s, "do delete: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_dnsZoneEntry_IN_TXT(self, s, loc, tokens):
        try:
            self.user.update_dnsZoneEntry_IN_CNAME(tokens[2], tokens[5])
            self.success(s, "do update: %s <- '%s'" % (tokens[1], ' '.join(tokens[2:])))
        except Exception as err:
            self.failure(s, loc, None, err)

    def do_update_gender(self, s, loc, tokens):
        try: # TODO
            tokens[2] = {'male': 1, 'female': 2, 'unspecified': 9}[tokens[2]]
            self.user.update(tokens[1], tokens[2])
            self.success(s, "do update: %s -< '%s'" % (tokens[1], tokens[2]))
        except Exception as err:
            self.failure(s, loc, None, err)

# vim: set ts=4 sw=4 et ai si sta:
