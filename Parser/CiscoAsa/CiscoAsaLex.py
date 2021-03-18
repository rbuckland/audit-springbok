#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex

reserved = {
    r'any$|any4$|any6$': 'ANY',
    r'accept$|permit$': 'ACCEPT',
    r'deny$|reject$': 'DENY',
    r'access-group$': 'ACCESS_GROUP',
    r'in$': 'IN',
    r'out$': 'OUT',
    r'access-list$': 'ACCESS_LIST',
    r'extended$': 'EXTENDED',
    r'standard$': 'STANDARD',
    r'none$': 'NONE',
    r'no$': 'NO',
    # protocol
    r'tcp$': 'TCP',
    r'udp$': 'UDP',
    r'tcp-udp$': 'TCP_UDP',
    r'icmp$': 'ICMP',
    r'icmp6$': 'ICMP6',
    # parameters
    r'host$': 'HOST',
    r'hostname$': 'HOSTNAME',
    r'log$': 'LOG',
    r'interval$': 'INTERVAL',
    r'disable$': 'DISABLE',
    r'default$': 'DEFAULT',
    r'inactive$': 'INACTIVE',
    r'time-range$': 'TIME_RANGE',
    r'remark': 'REMARK',
    # object
    r'object$': 'OBJECT',
    r'object-group$': 'OBJECT_GROUP',
    r'user-group$': 'USER_GROUP',
    r'object-group-user$': 'OBJECT_GROUP_USER',
    r'security-group$': 'SECURITY_GROUP',
    r'object-group-security$': 'OBJECT_GROUP_SECURITY',
    r'user$': 'USER',
    r'name$': 'NAME',
    r'rename$': 'RENAME',
    r'tag$': 'TAG',
    r'network$': 'NETWORK',
    r'fqdn$': 'FQDN',
    r'service$': 'SERVICE',
    r'protocol$': 'PROTOCOL',
    r'icmp-type$': 'ICMP_TYPE',
    r'icmp-object$': 'ICMP_OBJECT',
    r'group-object$': 'GROUP_OBJECT',
    r'network-object$': 'NETWORK_OBJECT',
    r'protocol-object$': 'PROTOCOL_OBJECT',
    r'port-object$': 'PORT_OBJECT',
    r'service-object$': 'SERVICE_OBJECT',
    r'source$': 'SOURCE',
    r'destination$': 'DESTINATION',
    r'security$': 'SECURITY',
    # interface
    r'interface$': 'INTERFACE',
    r'ip$': 'IP',
    r'address$': 'ADDRESS',
    r'redundant$': 'REDUNDANT',
    r'port-channel$': 'PORT_CHANNEL',
    r'standby$': 'STANDBY',
    r'cluster-pool$': 'CLUSTER_POOL',
    r'nameif$': 'NAMEIF',
    # operators
    r'lt$': 'OP_LT',
    r'gt$': 'OP_GT',
    r'eq$': 'OP_EQ',
    r'neq$': 'OP_NEQ',
    r'range$': 'OP_RANGE',
    r'route$' : 'ROUTE',
    r'static$': 'STATIC',
    r'nat$': 'NAT',
    r'global$': 'GLOBAL',
    r'alias$': 'ALIAS',
    r'netmask$': 'NETMASK',
    r'enable$': 'ENABLE',
    r'crypto$': 'CRYPTO',
    r'ipsec$': 'IPSEC',
    r'transform-set$': 'TRANSFORMSET',
    r'dynamic-map$': 'DYNAMICMAP',
    r'map$': 'MAP',
    r'isakmp$': 'ISAKMP',
    r'policy$': 'POLICY',
    r'match$': 'MATCH',
    r'set$': 'SET',
    r'peer$': 'PEER',



}

tokens = [
             'BANG',
             'IP_ADDR',
             'NUMBER',
             'WS',
             'NL',
             'WORD',
             'LPAREN',
             'RPAREN',
             'HYPHEN',
             'COMA',

         ] + list(reserved.values())


# def t_ignore_OTHER(t):
#     r'^(PIX|enable|passwd|domain-name|logging|mtu|failover|pdm|arp|aaa|timeout|snmp|floodguard|telnet|ssh|console|terminal|crypto|pager|global|nat|static|fixup|route|vpngroup).*$'
#     pass


def t_BANG(t):
    r'!'
    return t

def t_HYPHEN(t):
    r'-'
    return t

def t_LPAREN(t):
    r'\('
    return t

def t_RPAREN(t):
    r'\)'
    return t


def t_IP_ADDR(t):
    r'\d+\.\d+\.\d+\.\d+'
    return t


def t_NUMBER(t):
    r'\d+'
    return t


def t_WS(t):
    r'[ \t]+'
    pass


def t_NL(t):
    r'[\n\r]+'
    return t


def t_COMA(t):
    r','
    return t


def t_WORD(t):
    r'[a-zA-Z0-9/\\\._-]+'
    # Check for reserved words
    for k, v in list(reserved.items()):
        if re.match(k, t.value, re.I):
            t.type = v
    return t


def t_error(t):
    t.lexer.skip(1)
    return t


lexer = lex.lex()

if __name__ == '__main__':
    lex.runmain()
