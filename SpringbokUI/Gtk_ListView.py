#! /usr/bin/env python
# -*- coding: utf-8 -*-

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
import re

from gi.repository import GObject


class Gtk_ListView():
    """Gtk_ListView class.
    This class create a list view in a scrolled window and contains method for adding/deleting row.

    Parameters
    ----------
    name : string. The name of the treeview column
    header_visible : bool (optional, default=False). True if the header column must be visible
    """
    def __init__(self, name, header_visible=False):
        self.scrolled_window = Gtk.ScrolledWindow()
        self.scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.model = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING)
        self.tree_view = Gtk.TreeView(self.model)
        self.tree_view.set_headers_visible(header_visible)
        self.scrolled_window.add(self.tree_view)
        cell = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn(name, cell, text=0, foreground=1, background=2)
        self.tree_view.append_column(column)
        self.elem_list = []

    def search(self, pattern):
        """Clear the model and append only element that match the pattern"""
        self.model.clear()
        [self.model.append(e) for e in self.elem_list if re.search(pattern, e[0], re.I)]

    def clear(self):
        """Clear all element in the list view"""
        self.elem_list = []
        self.model.clear()

    def add_row(self, name, foreground='black', background='white'):
        """Add a row in the list view

        Parameters
        ----------
        name : string. The string row to add.
        foreground : string (optional, default='black'). The text color
        background : string (optional, default='white'). The background color
        """
        self.elem_list.append([name, foreground, background])
        self.model.append([name, foreground, background])
