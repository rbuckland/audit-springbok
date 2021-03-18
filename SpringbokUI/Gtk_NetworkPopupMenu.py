#! /usr/bin/env python
# -*- coding: utf-8 -*-

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from functools import reduce
from SpringbokUI.Gtk_HelpMessage import Gtk_Message

import csv
import collections
import threading
from . import Gtk_Main
from Parser import Parser
from .Gtk_QueryPath import Gtk_QueryPath
from .Gtk_ListView import Gtk_ListView
from .Gtk_TreeView import Gtk_TreeView
from .Gtk_DialogBox import Gtk_DialogBox
from . import Gtk_Export
from SpringBase import Rule
from SpringBase import Ip
from SpringBase import Firewall
from SpringBase import Port
from SpringBase import Interface
from AnomalyDetection.InternalDetection import InternalDetection
from NetworkGraph import NetworkGraph
from Parser.Routing.RoutingParser import RoutingParser

######## Modification of the class by Maurice TCHAMGOUE N. on 30-06-2015
###          * Adding the method on_remove_all_menu : this method is called
###            when the user make a right click on 'remove all'. It will clear
###            the topology by removing all firewalls



class Gtk_NewtworkPopupMenu:
    """Gtk_NetworkPopupMenu class.
    Popup menu when right click on the gtk canvas.

    Parameters
    ----------
    node : the clicked Node
    """
    def __init__(self):
        self.object = None
        self.menu = Gtk.Menu()
        self.node = None
        self.menu.connect("focus-out-event", lambda x: self.menu.popdown())

    def popup(self, object, event, node):
        """Clear the popup menu and add child element depending if node is a firewall or a network.

        Parameters
        ----------
        node : the clicked Node
        """
        self.node = node
        self.object = object
        list(map(self.menu.remove, self.menu.get_children()))

        # Show conf #
        if isinstance(self.node.object, Firewall.Firewall):
            self.show_conf = Gtk.MenuItem("Show configuration")
            self.menu.append(self.show_conf)
            self.show_conf.connect("activate", self.on_show_conf)

        # Add Note #
        if isinstance(self.node.object, Firewall.Firewall) or isinstance(self.node.object, Ip.Ip):
            self.add_note = Gtk.MenuItem("Add note")
            self.menu.append(self.add_note)
            self.add_note.connect("activate", self.on_add_note)

        # Anomaly detection #
        if isinstance(self.node.object, Firewall.Firewall):
            self.anomaly_menu = Gtk.MenuItem("Detect anomaly")
            self.menu.append(self.anomaly_menu)
            self.anomaly_menu.connect("activate", self.on_anomaly_menu)

        # Configuration error #
        if isinstance(self.node.object, Firewall.Firewall):
            self.config_error_menu = Gtk.MenuItem("Configuration error")
            self.menu.append(self.config_error_menu)
            self.config_error_menu.connect("activate", self.on_config_error_menu)

        # Object list #
        if isinstance(self.node.object, Firewall.Firewall):
            self.object_menu = Gtk.MenuItem("Object list")
            self.menu.append(self.object_menu)
            self.object_menu.connect("activate", self.on_object_menu)

        # Service list #
        if isinstance(self.node.object, Firewall.Firewall):
            self.service_menu = Gtk.MenuItem("Service list")
            self.menu.append(self.service_menu)
            self.service_menu.connect("activate", self.on_service_menu)

        # Export Interfaces #
        if isinstance(self.node.object, Firewall.Firewall):
            self.export_itf_menu = Gtk.MenuItem("Export interfaces list")
            self.menu.append(self.export_itf_menu)
            self.export_itf_menu.connect("activate", self.on_export_itf_list)

        # Error conf #
        if isinstance(self.node.object, Firewall.Firewall):
            self.error_conf_menu = Gtk.MenuItem("Generate anonymous configuration")
            self.menu.append(self.error_conf_menu)
            self.error_conf_menu.connect("activate", self.on_error_conf)

        # Remove #
        if isinstance(self.node.object, Firewall.Firewall):
            self.remove_menu = Gtk.MenuItem("Remove")
            self.menu.append(self.remove_menu)
            self.remove_menu.connect("activate", self.on_remove_menu)

        # Show Nat rules #
        if isinstance(self.node.object, Firewall.Firewall):
            self.show_nat_rule = Gtk.MenuItem("Show nat rules")
            self.menu.append(self.show_nat_rule)
            self.show_nat_rule.connect("activate", self.on_show_nat_rule)

        # Show IPSec Tunnels #
        if isinstance(self.node.object, Firewall.Firewall):
            self.show_ipsec_tunnels = Gtk.MenuItem("Show IPSec tunnels")
            self.menu.append(self.show_ipsec_tunnels)
            self.show_ipsec_tunnels.connect("activate", self.on_show_ipsec_tunnels)

        # Add route config file #
        if isinstance(self.node.object, Firewall.Firewall):
            self.add_route_config = Gtk.MenuItem("add route config")
            self.menu.append(self.add_route_config)
            self.add_route_config.connect("activate", self.on_add_route_config)

        # Add interface config file #
        if isinstance(self.node.object, Firewall.Firewall):
            self.add_interface_config = Gtk.MenuItem("add interface config")
            self.menu.append(self.add_interface_config)
            self.add_interface_config.connect("activate", self.on_add_interface_config)

        # Itinerary #
        if isinstance(self.node.object, Ip.Ip):
            self.itinerary_menu = Gtk.Menu()

            self.itinerary = Gtk.MenuItem("Itinerary")
            self.itinerary.set_submenu(self.itinerary_menu)

            self.itinerary_from = Gtk.MenuItem("Itinerary from this place")
            self.itinerary_to = Gtk.MenuItem("Itinerary to this place")

            self.itinerary_menu.append(self.itinerary_from)
            self.itinerary_menu.append(self.itinerary_to)

            self.menu.append(self.itinerary)
            self.itinerary_from.connect("activate", self.on_itinerary, 'from')
            self.itinerary_to.connect("activate", self.on_itinerary, 'to')

        # Sensitivity #
        if isinstance(self.node.object, Ip.Ip):
            self.sensitivity_menu = Gtk.Menu()

            self.sensitivity = Gtk.MenuItem("Sensitivity")
            self.sensitivity.set_submenu(self.sensitivity_menu)

            self.sensitivity_vhigh = Gtk.MenuItem("Very high")
            self.sensitivity_high = Gtk.MenuItem("High")
            self.sensitivity_normal = Gtk.MenuItem("Normal")
            self.sensitivity_low = Gtk.MenuItem("Low")
            self.sensitivity_vlow = Gtk.MenuItem("Very low")

            self.sensitivity_menu.append(self.sensitivity_vhigh)
            self.sensitivity_menu.append(self.sensitivity_high)
            self.sensitivity_menu.append(self.sensitivity_normal)
            self.sensitivity_menu.append(self.sensitivity_low)
            self.sensitivity_menu.append(self.sensitivity_vlow)

            self.menu.append(self.sensitivity)
            self.sensitivity_vhigh.connect("activate", self.on_sensitivity, 'vhigh')
            self.sensitivity_high.connect("activate", self.on_sensitivity, 'high')
            self.sensitivity_normal.connect("activate", self.on_sensitivity, 'normal')
            self.sensitivity_low.connect("activate", self.on_sensitivity, 'low')
            self.sensitivity_vlow.connect("activate", self.on_sensitivity, 'vlow')

        # Show rules #
        if isinstance(self.node.object, Interface.Interface):
            def get_firewall(x, y):
                if isinstance(x, Firewall.Firewall):
                    return x
                elif isinstance(y, Firewall.Firewall):
                    return y
                return None

            def get_ip(x, y):
                if isinstance(x, Ip.Ip):
                    return x
                elif isinstance(y, Ip.Ip):
                    return y
                return None
            self.acl_menu = Gtk.Menu()
            self.acl = Gtk.MenuItem("ACL")
            self.acl.set_submenu(self.acl_menu)
            firewall = get_firewall(self.object[0], self.object[1])
            ip = get_ip(self.object[0], self.object[1])
            acl_list = NetworkGraph.NetworkGraph().get_acl_list(ip, None, firewall)
            acl_list += NetworkGraph.NetworkGraph().get_acl_list(None, ip, firewall)
            for acl in set(acl_list):
                self.tmp_acl = Gtk.MenuItem(acl.name)
                self.acl_menu.append(self.tmp_acl)
                self.tmp_acl.connect("activate", self.on_acl, acl)
            self.menu.append(self.acl)


        self.menu.popup(None, None, None, event.button, event.time)
        self.menu.show_all()

    def popup_clear(self, event):
        """A popup containing the option clear.
        The clear option will remove all marker and marked path
        """
        def on_clear(widget):
            g = NetworkGraph.NetworkGraph()
            for elem in g.graph.edges(data=True):
                edge = elem[2]['object']
                edge.clear_path()

            for k, v in list(g.graph.node.items()):
                v['object'].clear_marker()

            Gtk_Main.Gtk_Main().lateral_pane.path.clear()
            Gtk_Main.Gtk_Main().lateral_pane.path_route.clear()

        def on_background_image(widget):
            dialog = Gtk.FileChooserDialog("Import firewall configuration",
                                           None,
                                           Gtk.FileChooserAction.OPEN,
                                           (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                            Gtk.STOCK_OPEN, Gtk.ResponseType.OK))
            dialog.set_default_response(Gtk.ResponseType.OK)
            filter = Gtk.FileFilter()
            filter.set_name("PNG images")
            filter.add_pattern("*.png")
            dialog.add_filter(filter)
            response = dialog.run()
            if response == Gtk.ResponseType.OK:
                filename = dialog.get_filename()
                Gtk_Main.Gtk_Main().networkcanvas.background_image(filename)
            dialog.destroy()
            return True

        def on_remove_all_menu(widget):
            """Remove a firewall. Close all pages, clear paths and details, remove firewall and redraw the graph"""
            for row in Gtk_Main.Gtk_Main().lateral_pane.firewalls.model:
                if 1 == 1:
                    Gtk_Main.Gtk_Main().lateral_pane.firewalls.model.remove(row.iter)
                    # break
            for node in NetworkGraph.NetworkGraph().graph.nodes(data=True):
                self.node = node[1]['object']
                if isinstance(self.node.object, Firewall.Firewall):
                    self.on_remove_menu(node)
                    self.node = None
            # g.remove_nodes_from(nodes)
            Gtk_Main.Gtk_Main().lateral_pane.details.clear()
            Gtk_Main.Gtk_Main().lateral_pane.path.clear()
            Gtk_Main.Gtk_Main().notebook.close_all_closable()

            Gtk_Main.Gtk_Main().draw()

        list(map(self.menu.remove, self.menu.get_children()))

        # Clear #
        self.clear = Gtk.MenuItem("Clear query path")
        self.menu.append(self.clear)
        self.clear.connect("activate", on_clear)

        # Background #
        self.background = Gtk.MenuItem("Background image")
        self.menu.append(self.background)
        self.background.connect("activate", on_background_image)

        # Remove all firewalls
        self.remove_all = Gtk.MenuItem('Remove all')
        self.menu.append(self.remove_all)
        self.remove_all.connect("activate", on_remove_all_menu)

        self.menu.popup(None, None, None, event.button, event.time)
        self.menu.show_all()

    def on_show_conf(self, item):
        """Show conf file in new tab"""
        firewall = self.node.object
        Gtk_Main.Gtk_Main().notebook.add_conf_tab(firewall.name, firewall.hostname)

    def on_add_note(self, item):
        """Show a popup window to add on a firewall."""
        entry = Gtk.Entry()
        button = Gtk.Button("OK")

        popup = Gtk.Window()
        popup.set_title("Add note")

        popup.set_modal(True)
        popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        popup.set_type_hint(Gdk.WindowTypeHint.DIALOG)

        vbox2 = Gtk.VBox()
        vbox2.pack_start(Gtk.Label("Add a note for this node :", True, True, 0))
        vbox2.pack_end(entry, True, True, 0)

        vbox = Gtk.VBox()
        vbox.pack_start(vbox2, True, True, 0)
        vbox.pack_end(button, True, True, 0)
        popup.add(vbox)

        popup.show_all()

        def on_click(widget):
            self.node.add_note(entry.get_text())
            Gtk_Main.Gtk_Main().networkcanvas.do_refresh()
            popup.destroy()

        button.connect("clicked", on_click)

    def on_anomaly_menu(self, item):
        """Launch the internal detection anomaly and add a new page on the notebook showing the result"""
        def start_detection(popup, deep_search):
            popup.destroy()
            internal_detection = InternalDetection(self.node, deep_search)
            error_list = internal_detection.detect_anomaly()

            if not reduce(lambda x, y: x | y, [len(x) > 0 for error in error_list for x in error], False):
                Gtk_DialogBox("No error found !")
                return

            Gtk_Main.Gtk_Main().notebook.add_internal_anomaly_tab(internal_detection)
            Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_INTERNAL_ANOMALY)

        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_DEEP_SEARCH)
        check_button = Gtk.CheckButton("Deep search")
        cancel_button = Gtk.Button("Cancel")
        cancel_button.connect("clicked", lambda x: popup.destroy())
        start_button = Gtk.Button("Start")
        start_button.connect("clicked", lambda x: start_detection(popup, check_button.get_active()))

        hbox = Gtk.HBox()
        hbox.pack_start(cancel_button, True, True, 0)
        hbox.pack_start(start_button, True, True, 0)

        vbox = Gtk.VBox()
        vbox.pack_start(check_button, True, True, 0)
        vbox.pack_start(hbox, True, True, 0)

        popup = Gtk.Window()
        popup.set_title("Internal detection")
        popup.set_modal(True)
        popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        popup.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        popup.add(vbox)
        popup.show_all()

    def on_config_error_menu(self, item):
        """Show configuration error (unused object and unbinded rules) in new pages"""
        if not self.node.object.unused_objects and not self.node.object.unbounded_rules:
            Gtk_DialogBox("No error found !")
            return

        treeview = Gtk_TreeView("Configuration error (%s)" % self.node.object.hostname)
        if self.node.object.unused_objects:
            p_iter1 = treeview.add_row(None, "Unused objects", 'black', '#B9B9B9')
            count = 0
            for i in self.node.object.unused_objects:
                treeview.add_row(p_iter1, "Unused object: " + i, 'black', '#FFFFFF' if count % 2 else '#DCDCDC')
                count += 1

        if self.node.object.unbounded_rules:
            p_iter1 = treeview.add_row(None, "Unbounded rules", 'black', '#B9B9B9')
            count = 0
            for i in self.node.object.unbounded_rules:
                treeview.add_row(p_iter1, "Unbounded rule: " + i, 'black', '#FFFFFF' if count % 2 else '#DCDCDC')
                count += 1
        Gtk_Main.Gtk_Main().notebook.add_tab(treeview.scrolled_window, "Configuration error (%s)" % self.node.object.hostname,
                                             can_close=True, ref=self.node.object, export=Gtk_Export.export_error_configuration)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_ERROR_CONFIG)

    def on_object_menu(self, item):
        """Show all element in dictionary in a new tab"""
        od = collections.OrderedDict(sorted(self.node.object.get_objects().items()))

        if not od:
            Gtk_DialogBox("No object found !")
            return

        object_dictionary = Gtk_TreeView("Object list")

        for k, v in list(od.items()):
            p_iter = object_dictionary.add_row(None, k, 'black', '#969696')
            for k1, v1 in list(self.node.object.resolve(k).items()):
                p_iter2 = object_dictionary.add_row(p_iter, k1, 'black', '#B9B9B9')
                count = 0
                for e in v1:
                    object_dictionary.add_row(p_iter2, e, 'black', '#FFFFFF' if count % 2 else '#DCDCDC')
                    count += 1
            rule_list = list(set([i for i in v if isinstance(i, Rule.Rule)]))
            if rule_list:
                p_iter2 = object_dictionary.add_row(p_iter, 'Rule', 'black', '#B9B9B9')
                count = 0
                for e in rule_list:
                    object_dictionary.add_row(p_iter2, e.to_string(' '), 'black', '#FFFFFF' if count % 2 else '#DCDCDC')
                    count += 1


        Gtk_Main.Gtk_Main().notebook.add_tab(object_dictionary.scrolled_window,
                                             "Object list (%s)" % self.node.object.hostname,
                                             can_close=True)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_SHOW_OBJECT)

    def on_service_menu(self, item):
        """Show all service enable in a new tab"""
        service_list = Gtk_TreeView("Service list")
        p_iter_dict = {}
        handler_id = None

        def on_service_row_expanded(treeview, iter, path, p_iter_dict):
            model = treeview.get_model()
            if not (model[iter].parent and not model[iter].parent.parent):
                return
            treeview.freeze_child_notify()
            treeview.set_model(None)
            min = p_iter_dict[model[iter][0]][0]
            max = p_iter_dict[model[iter][0]][1]
            if model[iter].parent[0] == 'TCP':
                od = collections.OrderedDict(sorted(self.node.object.get_services(min, max, 'tcp').items()))
            elif model[iter].parent[0] == 'UDP':
                od = collections.OrderedDict(sorted(self.node.object.get_services(min, max, 'udp').items()))
            else:
                od = collections.OrderedDict(sorted(self.node.object.get_services(min, max, None).items()))
            iter_child = model.iter_children(iter)
            # apparently if we remove all, even if we add rows after, the row doesn't expand
            # so we least just 1 who we remove later
            while model.iter_n_children(iter) > 1:
                model.remove(iter_child)
                iter_child = model.iter_children(iter)
            for k, v in list(od.items()):
                name = Port.Port.get_service_name(k)
                p_iter1 = model.append(iter, [name if name else k, 'black', '#B9B9B9'])
                count = 0
                for e in list(set(v)):
                    model.append(p_iter1, [e.to_string(' '), 'black', '#FFFFFF' if count % 2 else '#DCDCDC'])
                    count += 1
            treeview.set_model(model)
            treeview.thaw_child_notify()
            # remove the first one see above why
            model.remove(model.iter_children(iter))
            # disconnect handler and force expand
            treeview.handler_block(handler_id)
            treeview.expand_to_path(path)
            treeview.handler_unblock(handler_id)

        Gtk_Main.Gtk_Main().create_progress_bar("Services", 3*2**6)
        for j in range(0, 3):
            if j == 0:
                protocol = 'tcp'
                p_proto = service_list.add_row(None, "TCP", 'black', '#737373')
            elif j == 1:
                protocol = 'udp'
                p_proto = service_list.add_row(None, "UDP", 'black', '#737373')
            else:
                protocol = None
                p_proto = service_list.add_row(None, "IP", 'black', '#737373')
            for i in range(0, 2**16, 2**10):
                Gtk_Main.Gtk_Main().update_interface()
                Gtk_Main.Gtk_Main().update_progress_bar(1)
                if self.node.object.get_services(i, i + 2**10 - 1, protocol):
                    p_iter = service_list.add_row(p_proto, "[ %i - %i ]" % (i, i + 2**10 - 1), 'black', '#969696')
                    p_iter_dict["[ %i - %i ]" % (i, i + 2**10 - 1)] = (i, i + 2**10 - 1)
                    service_list.add_row(p_iter, ' ', 'black', '#FFFFFF')
        Gtk_Main.Gtk_Main().destroy_progress_bar()


        handler_id = service_list.treeview.connect("row-expanded", on_service_row_expanded, p_iter_dict)

        Gtk_Main.Gtk_Main().notebook.add_tab(service_list.scrolled_window,
                                             "Service list (%s)" % self.node.object.hostname,
                                             can_close=True)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_SHOW_SERVICE)

    def on_export_itf_list(self, item):
        """Launch parser and generate an anonymous configuration file with parsed token"""
        filename = None

        dialog = Gtk.FileChooserDialog('Save interfaces list',
                                       None,
                                       Gtk.FileChooserAction.SAVE,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        dialog.set_default_response(Gtk.ResponseType.OK)
        response = dialog.run()

        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()

        dialog.destroy()

        if not filename:
            return

        try:
            with open(filename, 'wb') as csvfile:
                spamwriter = csv.writer(csvfile)
                g = NetworkGraph.NetworkGraph()
                tmp_intf = [e[2]['object'].object for e in g.graph.edges(self.node.object, data=True)]
                for e in sorted(tmp_intf, key=lambda tmp_intf: tmp_intf.nameif):
                    message = [e.nameif, e.name, e.network.to_string()]
                    for key, value in list(e.attributes.items()):
                        message.append("%s : %s" % (key, value))
                    spamwriter.writerow(message)
        except Exception as e:
            Gtk_DialogBox(e.message)
        except:
            Gtk_DialogBox("An error occurred.")

    def on_error_conf(self, item):
        """Launch parser and generate an anonymous configuration file with parsed token"""
        filename = None

        dialog = Gtk.FileChooserDialog('Save anonymous configuration file',
                                       None,
                                       Gtk.FileChooserAction.SAVE,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        dialog.set_default_response(Gtk.ResponseType.OK)
        response = dialog.run()

        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()

        dialog.destroy()

        if not filename:
            return

        try:
            Parser.generate_debug_conf(filename, self.node.object.name, self.node.object.type)
        except Exception as e:
            Gtk_DialogBox(e.message)
        except:
            Gtk_DialogBox("An error occurred.")

    def on_remove_menu(self, item):
        """Remove a firewall. Close all pages, clear paths and details, remove firewall and redraw the graph"""
        for row in Gtk_Main.Gtk_Main().lateral_pane.firewalls.model:
            if row[0].split('\n')[0] == self.node.object.hostname:
                Gtk_Main.Gtk_Main().lateral_pane.firewalls.model.remove(row.iter)
                break
        Gtk_Main.Gtk_Main().lateral_pane.details.clear()
        Gtk_Main.Gtk_Main().lateral_pane.path.clear()
        Gtk_Main.Gtk_Main().notebook.close_all_closable()
        NetworkGraph.NetworkGraph().remove_firewall(self.node)
        Gtk_Main.Gtk_Main().draw()


    def on_itinerary(self, item, itinerary):
        """Add a marker on the node and if both marker are present, show query path menu

        Parameters
        ----------
        itinerary : string. (values : 'from', 'to')
        """
        both_marker = self.node.add_marker(itinerary)
        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()

        if both_marker is not None:
            Gtk_QueryPath(both_marker[0], both_marker[1])
            Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_QUERY_PATH)

    def on_sensitivity(self, item, sensitivity):
        """Change network style depending on the sensitivity

        Parameters
        ----------
        sensitivity : string.
        """
        if sensitivity == 'vhigh':
            self.node.add_image('red')
        elif sensitivity == 'high':
            self.node.add_image('orange')
        elif sensitivity == 'normal':
            self.node.add_image('blue')
        elif sensitivity == 'low':
            self.node.add_image('cyan')
        elif sensitivity == 'vlow':
            self.node.add_image('green')
        self.node.sensitivity = sensitivity
        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()

    def on_acl(self, item, acl):
        """Show acl list"""
        Gtk_Main.Gtk_Main().notebook.add_interface_tab(acl)

    def on_show_nat_rule(self, widget):
        Gtk_Main.Gtk_Main().notebook.add_nat_rule_tab(self.node.object, self.node.object.nat_rule_list)

    def on_show_ipsec_tunnels(self, widget):
        Gtk_Main.Gtk_Main().notebook.add_ipsec_tunnels(self.node.object, self.node.object.ipsec_maps)
        print ('maps ipsec')

    def on_add_route_config(self, widget):
        # self.node.object => instance firewall
        Gtk_Main.Gtk_Main().statusbar.change_message("Importing Routing configuration ...")
        filename = self.open_filechooser("Import the routing configuration file")
        if not filename:
            Gtk_Main.Gtk_Main().statusbar.change_message("Ready")
            return

        if self.node.object.type == "Fortinet FortiGate" or self.node.object.type == "Iptables":
            parser = RoutingParser(self.node.object, filename)
            parser.parse()
            new_routes = parser.get_routes()
            for new_route in new_routes:
                self.node.object.route_list.append(new_route)


        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def on_add_interface_config(self, widget):
        Gtk_Main.Gtk_Main().statusbar.change_message("Importing Interface configuration ...")
        filename = self.open_filechooser("Import the Interface configuration file")
        if not filename:
            Gtk_Main.Gtk_Main().statusbar.change_message("Ready")
            return

        if self.node.object.type == "Iptables":
            parser = RoutingParser(self.node.object, filename)
            parser.parse_interface()
            new_interfaces = parser.get_interface()
            for new_interface in new_interfaces:
                self.node.object.interfaces.append(new_interface)

        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def open_filechooser(self, name, multiple_select=False):
        """Open a file chooser for opening a file.

        Parameters
        ----------
        name : string. the title name of the file chooser dialog
        multiple_select : bool (optional, default=False). If true enable multiple selection

        Return
        ------
        If mulitple_select is true return the list of selected file (or empty list if cancel)
        If mulitple_select is false return the name of the selected file (or None if cancel)
        """
        filename = [] if multiple_select else None

        dialog = Gtk.FileChooserDialog(name,
                                       None,
                                       Gtk.FileChooserAction.OPEN,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK))
        dialog.set_select_multiple(multiple_select)
        dialog.set_default_response(Gtk.ResponseType.OK)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            if multiple_select:
                filename = dialog.get_filenames()
            else:
                filename = dialog.get_filename()
        dialog.destroy()
        return filename