#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append("../../")

from SpringbokUI import Gtk_Main
import Parser.Parser as Parser
import AnomalyDetection.InternalDetection as InternalDetection
import NetworkGraph.Node as Node
from SpringBase.Firewall import Firewall


def test(file):
    ''' Juniper parse test.
    This function take a configuration file as parameter and :
    - detect the file type (Cisco Asa, Juniper, ...)
    - return rule list
    '''
    res = ''
    type = Parser.suppose_type(file)
    if type is None:
        type = "Parser.JuniperNetscreen.JuniperNetscreenYacc"
    firewalls = Parser.parser(file, type, None)
    for fw in firewalls:
        for acl in fw.acl:
            for rule in acl.rules:
                res += rule.to_string(' ') + '\n'
    return res
