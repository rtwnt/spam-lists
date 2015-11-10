#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''

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
        
    def get_classification(self, code):
        ''' Return classification for given code
        
        :param code: a valid return code extracted from response to DNSBL query
        :raises UnknownCodeError: raised when given code is not specified in self._code_item_class
        :returns: a value associated with a valid return code
        '''
        
        try:
            return self._code_item_class[code]
        
        except KeyError:
            
            msg_template = 'Using a code value "{}" unsupported by DNSBL instance representing {}'
            raise UnknownCodeError(msg_template.format(code, self.identifier)), None, exc_info()[2]
        
    def _get_host_and_query_prefix(self, host_collection):
        ''' Get valid hosts and  query prefixes from hosts given in host_collection
        
        :param host_collection: a container with valid host values
        :returns: a tuple with original host and a value prepared for lookup
        '''
        if self.lists_ips:
            for ip in host_collection.ips:
                ip = str(ip)
                suffix = '.in-addr.arpa' if ip.version == 4 else '.ip6.arpa'
                reverse = ip.replace(suffix, '')
                
                yield ip, reverse
            
        if self.lists_uris:
            for hostname in host_collection.hostnames:
                hostname = str(hostname)
                yield hostname, hostname.rstrip('.')
        
        
if __name__ == '__main__':
    pass