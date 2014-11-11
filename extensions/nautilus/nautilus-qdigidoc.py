#
# QDigiDoc Nautilus Extension
#
# Copyright (C) 2010  Erkko Kebbinau
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
import os
import urllib
import gettext
import locale

from gi.repository import Nautilus, GObject, Gio

APP = 'nautilus-qdigidoc'

class OpenDigidocExtension(GObject.GObject, Nautilus.MenuProvider):
    def __init__(self):
        pass

    def _open_client(self, paths):
        args = ""
        for path in paths:
            args += "\"%s\" " % path
        cmd = ("qdigidocclient " + args + "&")
        os.system(cmd)

    def menu_activate_cb(self, menu, paths):
        self._open_client(paths)

    def valid_file(self, file):
        return file.get_file_type() == Gio.FileType.REGULAR and file.get_uri_scheme() == 'file'

    def get_file_items(self, window, files):
        paths = []
        for file in files:
            if self.valid_file(file):
                path = urllib.unquote(file.get_uri()[7:])
                paths.append(path)

        if len(paths) < 1:
            return

        locale.setlocale(locale.LC_ALL, '')
        gettext.bindtextdomain(APP)
        gettext.textdomain(APP)
        _ = gettext.gettext

        tooltip_message = gettext.ngettext('Sign selected file with Digidoc3 Client',
                                           'Sign selected files with Digidoc3 Client',
                                           len(paths))

        item = Nautilus.MenuItem(
            name="OpenDigidocExtension::DigidocSigner",
            label=_('Sign digitally'),
            tip=tooltip_message
        )
        item.set_property('icon', 'qdigidoc-client')

        item.connect('activate', self.menu_activate_cb, paths)
        return item,
