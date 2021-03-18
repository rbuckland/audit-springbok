#! /usr/bin/env python
# -*- coding: utf-8 -*-

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from . import Gtk_Main


class Gtk_DialogBox:
    """Gtk_DialogBox class. Shorthand for popup window notifications"""
    def __init__(self, message, gtk_message=Gtk.MessageType.INFO, gtk_button=Gtk.ButtonsType.OK):
        self.message = message
        self.gtk_message = gtk_message
        self.gtk_button = gtk_button
        self.run()

    def run(self):
        """Run the dialog Box"""
        md = Gtk.MessageDialog(Gtk_Main.Gtk_Main().window,
                               Gtk.DialogFlags.DESTROY_WITH_PARENT, self.gtk_message,
                               self.gtk_button, self.message)
        md.run()
        md.destroy()
