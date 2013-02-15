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
from django.core.exceptions import ValidationError
from ldapdb.models.fields import CharField, IntegerField, ListField

import cmd

class Handler(cmd.Cmd):
    def __init__(self, fd, entry, keys, options):
        cmd.Cmd.__init__(self)
        self.fd = fd
        self.entry = entry
        self.keys = keys   # TODO add to model
        self.options = options
        self.dirty = set() # TODO add to model (mixin)
        self.prompt = 'ud:%s:%s # ' % (entry._meta.verbose_name, entry.pk)
        self.pad = max([len(x) for x in self.keys])
        self.has_errors = False

    def do_EOF(self, line):
        """exit from the command loop on CTRL^D"""
        return True

    def do_delete(self, line):
        """delete a specific attribute: delete <key> [val]"""
        try:
            parts = line.strip().split(' ', 1)
            key = parts[0]
            val = parts[1] if len(parts) is 2 else None
            self.entry.do_delete(key, val)
            self.dirty.add(key)
            if val:
                self.fd.write('ack: delete %s -> %s\n' % (key, val))
            else:
                self.fd.write('ack: delete %s\n' % (key))
        except ValidationError as err:
            for message in err.messages:
                self.fd.write('nak: %s\n' % (message))
                self.has_errors = True
        except Exception as err:
            self.fd.write('nak: %s\n' % (err))
            self.has_errors = True

    def do_discard(self, line):
        """discard local modifications"""
        if self.dirty:
            self.entry = self.entry.__class__._default_manager.get(pk=self.entry.pk)
            self.dirty.clear()
            self.fd.write('ack: local modifications discarded\n')
        else:
            self.fd.write('ack: no local modifications to discard\n')

    def do_exit(self, line):
        """exit from the command loop"""
        return True

    def do_help(self, line):
        """obtain help on commands: help <command>"""
        cmd.Cmd.do_help(self, line)

    def do_history(self, line):
        """display history of commands"""
        for entry in self.history:
            self.fd.write(entry + '\n')

    def do_save(self, line):
        """save local modifications"""
        if self.dirty:
            if not self.options['dryrun']:
                self.entry.save()
                self.entry = self.entry.__class__._default_manager.get(pk=self.entry.pk)
                self.dirty.clear()
                self.fd.write('ack: local modifications saved\n')
            else:
                self.fd.write('ack: local modifications not saved (dryrun)\n')
        else:
            self.fd.write('ack: no local modifications to save\n')

    def do_show(self, line):
        """show current attributes (flag local modifications with *)"""
        for key in self.keys:
            delim = '*' if key in self.dirty else ':'
            field = self.entry._meta.get_field(key)
            values = getattr(self.entry, key)
            if type(values) is not list:
                values = [values]
            if values:
                self.fd.write('%s %s %s\n' % (key.rjust(self.pad), delim, values[0]))
                for value in values[1:]:
                    self.fd.write('%s   %s\n' % (' ' * (self.pad), value))
            else:
                self.fd.write('%s %s\n' % (key.rjust(self.pad), delim))

    def do_update(self, line):
        """update a specific attribute: update <key> <val>"""
        try:
            (key, val) = line.strip().split(' ', 1)
            if key and val:
                self.entry.do_update(key, val)
                self.dirty.add(key)
                self.fd.write('ack: update %s <- %s\n' % (key, val))
        except ValidationError as err:
            for message in err.messages:
                self.fd.write('nak: %s\n' % (message))
                self.has_errors = True
        except Exception as err:
            self.fd.write('nak: %s\n' % (err))
            self.has_errors = True

    def do_validate(self, line):
        """validate all attributes"""
        self.entry.validate()

    def do_quit(self, line):
        """exits from the command loop"""
        return True

    def default(self, line):
        self.fd.write('nak: unknown command\n')
        self.has_errors = True

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
        self.fd.write('exiting... %s\n' % ('dirty' if self.dirty else ''))
        return cmd.Cmd.postloop(self)


# vim: set ts=4 sw=4 et ai si sta:
