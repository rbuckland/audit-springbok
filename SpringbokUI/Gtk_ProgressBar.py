#! /usr/bin/env python
# -*- coding: utf-8 -*-

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from . import Gtk_Main
import time


class Gtk_ProgressBar():
    """Gtk_ProgressBar class.
    A class showing a progress bar in a new popup window. (Used for long treatment like anomaly detection)

    Parameters
    ----------
    progress_bar : gtk ProgressBar
    popup : gtk window
    """
    def __init__(self, text, max_value, callable=None, *args):
        self.progress_bar = Gtk.ProgressBar() # adjustment=None
        self.progress_bar.set_text(text)
        self.progress_bar.set_fraction(0)

        self.text = text
        self.value = 0
        self.max_value = max_value if max_value else 1
        self.start_time = time.time()

        self.popup = Gtk.Window()
        self.popup.set_title("Processing ...")

        self.popup.set_modal(True)
        self.popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        self.popup.set_type_hint(Gdk.WindowTypeHint.DIALOG)

        self.vbox = Gtk.VBox()
        self.vbox.pack_start(self.progress_bar, True, True, 0)

        if callable:
            self.cancel_button = Gtk.Button("Cancel")
            self.cancel_button.connect("clicked", callable, args)
            self.popup.connect("destroy", callable, args)
            self.vbox.pack_start(self.cancel_button, True, True, 0)

        self.popup.add(self.vbox)

        self.popup.show_all()

    def update(self, value):
        """Update the progress bar"""
        if value == 0:
            return
        self.value += value
        t = time.time() - self.start_time
        self.progress_bar.set_text("%s : %d h %d m %d s" % (self.text, t / 3600, (t % 3600) / 60, t % 60))
        self.progress_bar.set_fraction(1. * self.value / self.max_value)

    def destroy(self):
        """Destroy the window with the progress bar"""
        self.popup.destroy()
