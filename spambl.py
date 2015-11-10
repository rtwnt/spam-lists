#!/usr/bin/python
# -*- coding: utf-8 -*-

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''

class DNSBL(object):
    ''' Represents a DNSBL service provider '''
    
    def __init__(self, identifier, query_suffix, code_item_class, lists_ips, lists_uris):
        ''' Create new DNSBL object
        
        :param identifier: a value designating DNSBL service provider: its name or url address.
        :param query_suffix: a suffix added to DNSBL query address
        :param code_item_class: item classes associated with DNSBL query return codes
        :param lists_ips: information if this object represents an ip blocklist
        :param lists_uris: information if this object represents a domain name blocklist
        '''
        
        self.identifier = identifier
        self._query_suffix = query_suffix
        self._code_item_class = code_item_class
        self.lists_ips = lists_ips
        self.lists_uris = lists_uris
        
        
if __name__ == '__main__':
    pass