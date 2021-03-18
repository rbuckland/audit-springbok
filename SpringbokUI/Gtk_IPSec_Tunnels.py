from reportlab.lib.validators import isInstanceOf

__author__ = 'maurice'

#! /usr/bin/python
#coding:utf8

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Action import Action
from SpringBase.Interface import Interface
from SpringBase.ACL import ACL
from SpringBase.Firewall import Firewall
from ROBDD.synthesis import synthesize
from ROBDD.synthesis import Bdd
from .Gtk_HelpMessage import Gtk_Message
from . import Gtk_Main
from socket import inet_ntoa
from struct import pack

class Gtk_IPSec_Tunnels:

    # To add a new row in the matrix table
    def add_row(self, elements=None):
        self.liststore.append(elements)

    def add_empty_row(self, widget):
        if len(self.liststore) != 0:
            self.liststore.append([str(int(self.liststore[-1][0]) + 1),
                                       None, None, None, None, None, None, False, 'white'])
        elif len(self.liststore) == 0:
            self.liststore.append(['0',
                                       None, None, None, None, None, None, False, 'white'])
        self.id_calculation()

    # to remove an element in the matrix table (by its reference)
    def remove_row(self, liststore, ref):
        liststore.remove(ref)

    # to remove all selected flaws in the matrix table
    def remove_selected_rows(self, widget):
        for row in self.liststore:
            if row[7] == True:
                self.liststore.remove(row.iter)
        self.id_calculation()

    ## to fix the id of each row of the table after insertion,
    #  deletion...of a row
    def id_calculation(self):
        j = 0
        for i in range(len(self.liststore)):
            self.liststore[j][0] = str(j)
            j += 1

    # to clear the whole matrix tab
    def clear_liststore(self, liststore):
        liststore.clear()

    # to retrieve data in a cell
    def get_one_value(self, liststore, iter, column):
        return liststore.get_value(iter, column)

    # to update datas when modified by the user
    def on_modify_value(self, cellrenderer, path, new_value, liststore, column):
        print("updating '%s' to '%s'" % (liststore[path][column], new_value))
        liststore[path][column] = new_value
        return

    # to manage toggle button
    def on_selected (self, cellrenderer, path, liststore, column):
        liststore[path][7] = not liststore[path][7]
        return

    # to change the color of a row
    def modify_row_color(self, liststore, path, color):
        liststore[path][8] = color

    # to change the color of a row by
    def modify_row_color2(self, row, color):
        row[8] = color

    ### this function is intend to retrieve the flows in the matrix
    #   table as Rules, and return them into a list (of Rule  instance)
    def get_all_flows(self):
        for flow in self.liststore:
            current_rule = Rule(None, None, [], [], [], [], [], Action(False))
            try:
                if isinstance(flow[0], str) and len(flow[0]) != 0:
                    current_rule.identifier = int(flow[0])
                if isinstance(flow[1], str) and len(flow[1]) != 0:
                    protocols = flow[1].split(',')
                    for protocol in protocols:
                        current_rule.protocol.append(Operator('EQ', Protocol(protocol)))
                if isinstance(flow[2], str) and len(flow[2]) != 0:
                    ips = flow[2].split(',')
                    for ip in ips:
                        if '/' in ip:
                            mask = ip[ip.index('/')+1:]
                            ip = ip[:ip.index('/')]
                            current_rule.ip_source.append(Operator('EQ', Ip(ip, self.fromDec2Dotted(int(mask)))))
                        else:
                            current_rule.ip_source.append(Operator('EQ', Ip(ip, '255.255.255.255')))
                if isinstance(flow[3], str) and len(flow[3]) != 0:
                    ports = flow[3].split(',')
                    for port in ports:
                        current_rule.port_source.append(Operator('EQ', Port(int(port))))
                if isinstance(flow[4], str) and len(flow[4]) != 0:
                    ips = flow[4].split(',')
                    for ip in ips:
                        if '/' in ip:
                            mask = ip[ip.index('/')+1:]
                            ip = ip[:ip.index('/')]
                            current_rule.ip_dest.append(Operator('EQ', Ip(ip, self.fromDec2Dotted(int(mask)))))
                        else:
                            current_rule.ip_dest.append(Operator('EQ', Ip(ip, '255.255.255.255')))
                if isinstance(flow[5], str) and len(flow[5]) != 0 :
                    ports = flow[5].split(',')
                    for port in ports:
                        current_rule.port_dest.append(Operator('EQ', Port(int(port))))
                if flow[6] == 'deny':
                    current_rule.action = Action(False)
                elif flow[6] == 'accept':
                    current_rule.action = Action(True)
            except KeyError:
                print('error')#
            self.flows.append(current_rule)

    ####  To launch the matrix verification : it will first call the 'get_all_flows'
    #     method to grab all the flow to test, and apply the verification of
    #     all these flows on the selected firewall
    def launch_verification(self, widget):
        self.flows = []
        self.result.clear()
        self.get_all_flows()
        for flow in self.flows:
            for acl in self.firewall.acl:
                for rule in acl.rules:
                    if  ((self.is_subset(rule, flow) == True) and (flow.action.to_string() != rule.action.to_string())):
                        if flow.identifier in self.result:
                            self.result[flow.identifier].append((rule, self.firewall))
                        else:
                            self.result[flow.identifier] = []
                            self.result[flow.identifier].append((rule, self.firewall))
        self.show_results_as_colors()

    ## this medthod return True if rule is a subset of test_rule,
    #  false otherwise (using ROBDD)
    def is_subset(self, rule, test_rule):
        return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2

    ## this function just output matrix verification result by coloring
    #  in green or red flows in the matrix flow table according to their fitness
    #  for the firewall
    def show_results_as_colors(self):
        reds = [row for row in self.liststore if int(row[0]) in list(self.result.keys())]
        greens = [row for row in self.liststore if int(row[0]) not in list(self.result.keys())]
        for row in reds:
            self.modify_row_color2(row, 'red')
        for row in greens:
            self.modify_row_color2(row, 'green')

    ## return a string representation of the attribute(ip, port, protocol...)
    def un_list2(self, aList):
        result = ''
        for element in aList:
            result += element
        return result

    ## return a string representation of the attribute(ip, port, protocol...)
    def un_list(self, aList):
        result = ''
        if len(aList) == 0:
            return 'any'
        for element in aList:
            if isinstance(element.v1, Protocol):
                result += element.v1.get_service_name(element.v1.get_value()) + ', '
            elif isinstance(element.v1, Port):
                result += str(element.v1.get_value()) + ', '
            elif isinstance(element.v1, Ip):
                result += element.v1.to_string() + ', '
        return result[:-2]


    ## to fill the matrix flow table with imported flows
    def add_tunels_to_table(self, vpn_list):
        for map_name, map_data in vpn_list.items():
            iface = map_data['iface']
            del map_data['iface']
            for seq_num, datas in map_data.items():
                if 'acl' in datas:
                    for rule in datas['acl'].rules:
                        print('rules', rule.to_string())
                        self.add_row(['0', map_name, seq_num, iface.name, iface.network.to_string(),
                                      datas['peer_dst'].to_string(), self.un_list(rule.protocol),
                                      self.un_list(rule.ip_source), self.un_list(rule.port_source),
                                      self.un_list(rule.ip_dest), self.un_list(rule.port_dest)])
                else:
                    self.add_row(['0', map_name, seq_num, iface.name, iface.network.to_string(),
                                      datas['peer_dst'].to_string(), 'any', 'any', 'any','any', 'any'])
        self.id_calculation()

    # used when the save button is clicked
    def on_saving_matrix_flow(self, widget):
        data = ''
        for row in self.liststore:
            data += 'protocol : ' + row[1] + '\n' if row[1] else 'protocol :\n'
            data += 'ip-source : ' + row[2] + '\n' if row[2] else  'ip-source :\n'
            data += 'ip-destination : ' + row[4] + '\n' if row[4] else 'ip-destination :\n'
            data += 'port-src : ' + row[3] + '\n' if row[3] else 'port-src :\n'
            data += 'port-dst : ' + row[5] + '\n' if row[2] else 'port-dst :\n'
            data += 'action : ' + row[6] + '\n' if row[6] else 'action:\n'
            if (row[0] != self.liststore[-1][0]):
                data += '--\n'
        Gtk_Main.Gtk_Main().statusbar.change_message("Saving matrix flow table ...")
        filename = self.save_filechooser("Save matrix flow")
        if not filename:
            return

        f = open(filename, 'w')
        f.write(data)
        f.close()
        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    # the filechooser for saving file
    def save_filechooser(self, name):
        """Open a file chooser for saving a file.

        Parameters
        ----------
        name : string. The title name of the file chooser dialog

        Return
        ------
        Return the file name to save the file"""
        dialog = Gtk.FileChooserDialog(name,
                                       None,
                                       Gtk.FileChooserAction.SAVE,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        dialog.set_default_response(Gtk.ResponseType.OK)

        last_folder = dialog.get_current_folder()
        if last_folder:
            dialog.set_current_folder(last_folder)
        response = dialog.run()
        filename = None
        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            self.last_folder = dialog.get_current_folder()
        dialog.destroy()
        return filename

    def fromDotted2Dec(self, ipaddr):
        return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

    def fromDec2Dotted(self, mask):
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return inet_ntoa(pack('>I', bits))


    #### ______init_______ ####
    ## Parameers :
    #  flowlist : a list containing all different flows to test
    #  firewall : the firewall instance on wich the matrix verification
    #  is going to be performed.

    def __init__(self,  vpn_list, firewall):
        # the liststore wich will contains all the flows
        self.liststore = Gtk.ListStore(str, str, str, str, str, str, str, str, str, str, str)

        # the treeview
        self.treeview = Gtk.TreeView(self.liststore)

        # different renderers of type text
        self.cellId = Gtk.CellRendererText()
        self.cellId.set_property('editable', False)
        self.cellId.set_property('xalign', 0.5)
        self.cellId.connect('edited', self.on_modify_value, self.liststore, 0)

        self.cellMap_name = Gtk.CellRendererText()
        self.cellMap_name.set_property('editable', False)
        self.cellMap_name.set_property('xalign', 0.5)
        self.cellMap_name.connect('edited', self.on_modify_value, self.liststore, 1)

        self.cellSeq_number = Gtk.CellRendererText()
        self.cellSeq_number.set_property('editable', False)
        self.cellSeq_number.set_property('xalign', 0.5)
        self.cellSeq_number.connect('edited', self.on_modify_value, self.liststore, 2)

        self.cellIface = Gtk.CellRendererText()
        self.cellIface.set_property('editable', False)
        self.cellIface.set_property('xalign', 0.5)
        self.cellIface.connect('edited', self.on_modify_value, self.liststore, 3)

        self.cellLocal_peer = Gtk.CellRendererText()
        self.cellLocal_peer.set_property('editable', False)
        self.cellLocal_peer.set_property('xalign', 0.5)
        self.cellLocal_peer.connect('edited', self.on_modify_value, self.liststore, 4)

        self.cellRemote_peer = Gtk.CellRendererText()
        self.cellRemote_peer.set_property('editable', False)
        self.cellRemote_peer.set_property('xalign', 0.5)
        self.cellRemote_peer.connect('edited', self.on_modify_value, self.liststore, 5)

        self.cellProto = Gtk.CellRendererText()
        self.cellProto.set_property('editable', False)
        self.cellProto.set_property('xalign', 0.5)
        self.cellProto.connect('edited', self.on_modify_value, self.liststore, 6)

        self.cellIp_src = Gtk.CellRendererText()
        self.cellIp_src.set_property('editable', False)
        self.cellIp_src.set_property('xalign', 0.5)
        self.cellIp_src.connect('edited', self.on_modify_value, self.liststore, 7)

        self.cellPort_src = Gtk.CellRendererText()
        self.cellPort_src.set_property('editable', False)
        self.cellPort_src.set_property('xalign', 0.5)
        self.cellPort_src.connect('edited', self.on_modify_value, self.liststore, 8)

        self.cellIp_dst = Gtk.CellRendererText()
        self.cellIp_dst.set_property('editable', False)
        self.cellIp_dst.set_property('xalign', 0.5)
        self.cellIp_dst.connect('edited', self.on_modify_value, self.liststore, 9)

        self.cellPort_dst = Gtk.CellRendererText()
        self.cellPort_dst.set_property('editable', False)
        self.cellPort_dst.set_property('xalign', 0.5)
        self.cellPort_dst.connect('edited', self.on_modify_value, self.liststore, 10)

        # different type of columns of our table
        self.columnId = Gtk.TreeViewColumn('Id', self.cellId, text=0)
        self.columnId.set_resizable(True)
        self.treeview.append_column(self.columnId)
        self.columnId.set_expand(True)

        self.columnMap_name = Gtk.TreeViewColumn('Map name', self.cellMap_name, text=1)
        self.columnMap_name.set_resizable(True)
        self.treeview.append_column(self.columnMap_name)
        self.columnMap_name.set_expand(True)

        self.columnSeq_number = Gtk.TreeViewColumn('Seq Number', self.cellSeq_number, text=2)
        self.columnSeq_number.set_resizable(True)
        self.treeview.append_column(self.columnSeq_number)
        self.columnSeq_number.set_expand(True)

        self.columnIface = Gtk.TreeViewColumn('Interface', self.cellIface, text=3)
        self.columnIface.set_resizable(True)
        self.treeview.append_column(self.columnIface)
        self.columnIface.set_expand(True)

        self.columnLocal_peer = Gtk.TreeViewColumn('Local peer', self.cellLocal_peer, text=4)
        self.columnLocal_peer.set_resizable(True)
        self.treeview.append_column(self.columnLocal_peer)
        self.columnLocal_peer.set_expand(True)

        self.columnRemote_peer = Gtk.TreeViewColumn('Remote peer', self.cellRemote_peer, text=5)
        self.columnRemote_peer.set_resizable(True)
        self.treeview.append_column(self.columnRemote_peer)
        self.columnRemote_peer.set_expand(True)

        self.columnProto = Gtk.TreeViewColumn('Protocol', self.cellProto, text=6)
        self.columnProto.set_resizable(True)
        self.treeview.append_column(self.columnProto)
        self.columnProto.set_expand(True)

        self.columnIp_src = Gtk.TreeViewColumn('Source IP', self.cellIp_src, text=7)
        self.columnIp_src.set_resizable(True)
        self.treeview.append_column(self.columnIp_src)
        self.columnIp_src.set_expand(True)

        self.columnPort_src = Gtk.TreeViewColumn('Source Port', self.cellPort_src, text=8)
        self.columnPort_src.set_resizable(True)
        self.treeview.append_column(self.columnPort_src)
        self.columnPort_src.set_expand(True)

        self.columnIp_dst = Gtk.TreeViewColumn('Destination IP', self.cellIp_dst, text=9)
        self.columnIp_dst.set_resizable(True)
        self.treeview.append_column(self.columnIp_dst)
        self.columnIp_dst.set_expand(True)

        self.columnPort_dst = Gtk.TreeViewColumn('Destination Port', self.cellPort_dst, text=10)
        self.columnPort_dst.set_resizable(True)
        self.treeview.append_column(self.columnPort_dst)
        self.columnPort_dst.set_expand(True)

        self.lastColumn = Gtk.TreeViewColumn('')
        self.lastColumn.set_expand(False)
        self.lastColumn.set_fixed_width(1)
        self.treeview.append_column(self.lastColumn)

        # self.add_flows_to_table(nat_rule_list)
        self.add_tunels_to_table(vpn_list)

        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.add(self.treeview)
        self.vbox = Gtk.VBox()
        self.hbox = Gtk.HBox()
        self.hbox1 = Gtk.HBox()
        self.vbox1 = Gtk.VBox()

        self.vbox.pack_start(self.hbox, True, True, 0)
        # self.vbox.pack_start(self.hbox1, True, True, 0)

        self.table = Gtk.Table(10, 20, True)
        self.table.attach(self.scrolled, 0, 20, 0, 10)
        self.hbox.pack_start(self.table, True, True, 0)

        self.flows = []
        self.firewall = firewall  # remember to change it in firewall (receive in parameter)
        self.result = {}

        # Begining of showing results

        self.treeview1 = Gtk.TreeView()