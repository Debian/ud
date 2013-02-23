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

from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from ldapdb.models.fields import CharField, IntegerField, ListField

import cmd
import io

class Handler(cmd.Cmd):
    def __init__(self, fd, entry, operator):
        cmd.Cmd.__init__(self)
        self.fd = fd
        self.entry = entry
        self.operator = operator
        self.dirty = set() # TODO add to model (mixin)
        self.pad = max([len(x.name) for x in self.entry._meta.fields])
        self.has_errors = False

    def write(self, line):
        if type(self.fd) is io.StringIO:
            self.fd.write(line)
        else:
            self.fd.write(line.encode('utf-8'))

    def complete_delete(self, text, line, begidx, endidx):
        completions = list()
        parts = line.split(' ')
        if len(parts) == 2:
            if text:
                completions = [x.name for x in self.entry._meta.fields if x.name.startswith(text)]
            else:
                completions = [x.name for x in self.entry._meta.fields]
        elif len(parts) > 2:
            if parts[1] in [x.name for x in self.entry._meta.fields]:
                field = self.entry._meta.get_field(parts[1])
                values = getattr(self.entry, field.name)
                if type(values) is list and values:
                    # TODO complete_delete_dnsZoneEntry and friends
                    this = ' '.join(parts[2:(-1 if text else len(parts))])
                    that = ''
                    completions = [x.replace(this,that).strip() for x in values if x.startswith(' '.join(parts[2:]))]
        return completions

    def complete_update(self, text, line, begidx, endidx):
        completions = list()
        parts = line.split(' ')
        if len(parts) == 2:
            if text:
                completions = [x.name for x in self.entry._meta.fields if x.name.startswith(text)]
            else:
                completions = [x.name for x in self.entry._meta.fields]
        elif len(parts) > 2:
            if parts[1] in [x.name for x in self.entry._meta.fields]:
                field = self.entry._meta.get_field(parts[1])
                values = getattr(self.entry, field.name)
                if type(values) is not list:
                    values = [values]
                if values:
                    this = ' '.join(parts[2:(-1 if text else len(parts))])
                    that = ''
                    completions = [x.replace(this,that).strip() for x in values if x.startswith(' '.join(parts[2:]))]
        return completions

    def do_EOF(self, line):
        """exit from the command loop on CTRL^D"""
        self.write(u'\n')
        return True

    def do_delete(self, line):
        """delete a specific attribute: delete <key> [val]"""
        try:
            parts = line.strip().split(' ', 1)
            key = parts[0]
            val = parts[1] if len(parts) is 2 else None
            # TODO move permission check into model?
            field = self.entry._meta.get_field(key)
            if 'adm' in self.operator.supplementaryGid:
                if field.permissions['root'] is not 'write':
                    self.write(u'nak: insufficient privileges\n')
                    return
            else:
                if field.permissions['self'] is not 'write':
                    self.write(u'nak: insufficient privileges\n')
                    return
            self.entry.do_delete(key, val)
            self.dirty.add(key)
            if val:
                self.write(u'ack: delete %s -> %s\n' % (key, val))
            else:
                self.write(u'ack: delete %s\n' % (key))
        except ValidationError as err:
            for message in err.messages:
                self.write(u'nak: %s\n' % (message))
                self.has_errors = True
        except Exception as err:
            self.write(u'nak: %s\n' % (err))
            self.has_errors = True

    def do_discard(self, line):
        """discard local modifications"""
        if self.dirty:
            self.entry = self.entry.__class__._default_manager.get(pk=self.entry.pk)
            self.dirty.clear()
            self.write(u'ack: local modifications discarded\n')
        else:
            self.write(u'ack: no local modifications to discard\n')

    def do_exit(self, line):
        """exit from the command loop"""
        return True

    def do_help(self, line):
        """obtain help on commands: help <command>"""
        cmd.Cmd.do_help(self, line)

    def do_history(self, line):
        """display history of commands"""
        for entry in self.history:
            self.write(u'%s\n' % (entry))

    def do_quit(self, line):
        """exits from the command loop"""
        return True

    def do_save(self, line):
        """save local modifications"""
        if self.dirty:
            self.entry.save()
            self.entry = self.entry.__class__._default_manager.get(pk=self.entry.pk)
            self.dirty.clear()
            self.write(u'ack: local modifications saved\n')
        else:
            self.write(u'ack: no local modifications to save\n')

    def do_show(self, line):
        """show current attributes (flag local modifications with **)"""
        for field in self.entry._meta.fields:
            if field.name is 'dn':
                continue
            # TODO move permission check into model?
            if 'adm' in self.operator.supplementaryGid:
                if field.permissions['root'] is 'none':
                    continue
                elif field.permissions['root'] is 'read':
                    delim = ':ro:'
                elif field.permissions['root'] is 'write':
                    delim = ':**:' if field.name in self.dirty else ':rw:'
            else:
                if field.permissions['self'] is 'none':
                    continue
                elif field.permissions['self'] is 'read':
                    delim = ':ro:'
                elif field.permissions['self'] is 'write':
                    delim = ':**:' if field.name in self.dirty else ':rw:'
            values = getattr(self.entry, field.name)
            if type(values) is not list:
                values = [values]
            if values:
                self.write(u'%s %s %s\n' % (field.name.rjust(self.pad), delim, values[0]))
                for value in values[1:]:
                    self.write(u'%s %s\n' % (' ' * (self.pad+len(delim)+1), value))
            else:
                self.write(u'%s %s\n' % (field.name.rjust(self.pad), delim))

    def do_switch(self, line):
        """switch to a different entry"""
        # TODO move permission check into model?
        if 'adm' in self.operator.supplementaryGid:
            try:
                if self.dirty:
                    self.entry.save()
                entry = self.entry.__class__._default_manager.get(pk=line)
                self.entry = entry
                self.dirty.clear()
                self.write(u'ack: switched entry\n')
            except ObjectDoesNotExist:
                self.write(u'nak: unable to switch entry\n')
        else:
            self.write(u'nak: insufficient privileges\n')

    def do_update(self, line):
        """update a specific attribute: update <key> <val>"""
        try:
            (key, val) = line.strip().split(' ', 1)
            if key and val:
                field = self.entry._meta.get_field(key)
                # TODO move permission check into model?
                if 'adm' in self.operator.supplementaryGid:
                    if field.permissions['root'] is not 'write':
                        self.write(u'nak: insufficient privileges\n')
                        return
                else:
                    if field.permissions['self'] is not 'write':
                        self.write(u'nak: insufficient privileges\n')
                        return
                self.entry.do_update(key, val)
                self.dirty.add(key)
                self.write(u'ack: update %s <- %s\n' % (key, val))
        except ValidationError as err:
            for message in err.messages:
                self.write(u'nak: %s\n' % (message))
                self.has_errors = True
        except Exception as err:
            self.write(u'nak: %s\n' % (err))
            self.has_errors = True

    def do_validate(self, line):
        """validate all attributes"""
        try:
            self.entry.validate()
            self.write(u'ack: no validation errors\n')
        except ValidationError as err:
            for message in err.messages:
                self.write(u'nak: %s\n' % (message))
                self.has_errors = True
            pass

    def _get_prompt(self):
        suffix = '#' if 'adm' in self.operator.supplementaryGid else '$'
        return 'ud:%s:%s%s ' % (self.entry._meta.verbose_name, self.entry.pk, suffix)
    prompt = property(_get_prompt)

    def default(self, line):
        self.write(u'nak: unknown command\n')
        self.has_errors = True

    def emptyline(self):
        return False

    def cmdloop(self, intro=None):
        try:
            cmd.Cmd.cmdloop(self, intro=self.intro)
        except KeyboardInterrupt: # handle ctrl-C
            self.write(u'\n')
            self.do_discard('')

    def onecmd(self, line):
        return cmd.Cmd.onecmd(self, line)

    def precmd(self, line):
        line = line.strip()
        if line:
            self.history.append(line)
        return cmd.Cmd.precmd(self, line)

    def postcmd(self, stop, line):
        return cmd.Cmd.postcmd(self, stop, line)

    def preloop(self):
        self.history = list()
        return cmd.Cmd.preloop(self)

    def postloop(self):
        self.do_save('')
        return cmd.Cmd.postloop(self)


# vim: set ts=4 sw=4 et ai si sta:
