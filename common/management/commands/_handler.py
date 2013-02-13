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
from ldapdb.models.fields import CharField, IntegerField, ListField

import cmd

class Handler(cmd.Cmd):
    def __init__(self, entry, keys):
        cmd.Cmd.__init__(self)
        self.entry = entry
        self.keys = keys   # TODO add to model
        self.dirty = set() # TODO add to model (mixin)
        self.prompt = '%s:%s # ' % (entry._meta.verbose_name, entry.pk)
        self.pad = max([len(x) for x in self.keys])

    def do_EOF(self, line):
        """exits from the command loop on CTRL^D"""
        return True

    def do_delete(self, line):
        """delete a specific attribute: delete <key> [val]"""
        (key, val) = line.split(' ', 1)
        self.dirty.add(key)
        # TODO self.delete(key, val)
        return True

    def do_discard(self, line):
        """discard local modifications"""
        self.entry = self.entry.__class__._default_manager.get(pk=self.entry.pk)
        self.dirty.clear()

    def do_exit(self, line):
        """exits from the command loop"""
        return True

    def do_help(self, line):
        """obtain help on commands: help <command>"""
        cmd.Cmd.do_help(self, line)

    def do_history(self, line):
        """displays history of commands"""
        for entry in self.history:
            print entry

    def do_save(self, line):
        self.entry.save()
        self.dirty.clear()

    def do_show(self, line):
        """show current attributes (flag local modifications)"""
        for key in self.keys:
            delim = '*' if key in self.dirty else ':'
            field = self.entry._meta.get_field(key)
            values = getattr(self.entry, key)
            if type(values) is not list:
                values = [values]
            if values:
                print '%s %s %s' % (key.rjust(self.pad), delim, values[0])
                for value in values[1:]:
                    print '%s   %s' % (' ' * (self.pad), value)
            else:
                print '%s %s' % (key.rjust(self.pad), delim)

    def do_update(self, line):
        """update a specific attribute: update <key> <val>"""
        (key, val) = line.split(' ', 1)
        if key and val:
            try:
                self.entry.update(key, val)
                self.dirty.add(key)
            except Exception as err:
                print err

    def do_validate(self, line):
        """validate all attributes"""
        self.entry.validate()

    def do_quit(self, line):
        """exits from the command loop"""
        return True

    def precmd(self, line):
        line = line.strip()
        if line:
            self.history.append(line)
        return line

    def postcmd(self, post, line):
        return post

    def preloop(self):
        cmd.Cmd.preloop(self)
        self.history = list()

    def postloop(self):
        cmd.Cmd.postloop(self)
        print "Exiting... %s" % ('dirty' if self.dirty else '')


# vim: set ts=4 sw=4 et ai si sta:
