#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''
    
class DNSBLItem(object):
    ''' Represents a host listed on a DNS blacklist '''
    
    _classification = None
    
    def __init__(self, host, source, return_code):
        ''' Create a new instance of DNSBLItem 
        
        :param host: the host value listed on a DNS blacklist, either host name or ip address
        :param source: dnsbl service object
        :param return_code: last octet of ip address returned after querying the source for the host
        '''
        self.host = host
        self.source = source
        self._return_code = return_code
        
    @property
    def classification(self):
        ''' Classification of this host according to provider of the list from which it has been extracted '''
        if not self._classification:
            self._classification = self.source.get_classification(self._return_code)
            
        return self._classification

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
                suffix = '.in-addr.arpa' if ip.version == 4 else '.ip6.arpa'
                reverse = ip.reverse_pointer.replace(suffix, '')
                
                yield ip, reverse
            
        if self.lists_uris:
            for hostname in host_collection.hostnames:
                hostname = str(hostname)
                
                yield hostname, hostname.rstrip('.')
                
    def _query_for(self, host_collection):
        ''' Get hosts that are included both in this blocklist and in host_collection
        
        :param host_collection: a container with valid host values
        :returns: an item listed on this DNSBL, as an instance of DNSBLItem
        '''
        for host, prefix in self._get_host_and_query_prefix(host_collection):
            try:
                response = query(prefix+'.'+self._query_suffix)
                
            except NXDOMAIN:
                pass
            
            else:
                last_octet = response[0].to_text().split('.')[-1]
                yield DNSBLItem(host, self, last_octet)
                
    def contains_any(self, host_collection):
        ''' Check if given host collection contains any items listed on this DNSBL
        
        :param host_collection: a container with valid host values
        '''
        
        return any(self._query_for(host_collection))
    
    def lookup(self, host_collection):
        ''' Get items from this dns blocklist
        
        :param host_collection: a container with valud host values
        :returns: all hosts from this dns blocklist that are also included in host_collection
        '''
        return tuple(self._query_for(host_collection))
    
class HpHostsItem(object):
    ''' Represents a host listed in hpHosts'''
    
    def __init__(self, host, source, classification):
        
        self.host = host
        self.source = source
        self.classification = classification
    
class HpHosts(object):
    ''' hpHosts client '''
    
    identifier = ' http://www.hosts-file.net/'
    _LISTED = 'Listed'
    
    def __init__(self, client_name):
        '''
        Constructor
        
        :param client_name: name of client using the service
        '''
        
        self.app_id = client_name
        
    def _query(self, host, classification = False):
        ''' Query the client for data of given host
        
        :param host: a valid host string
        :param classification: if True: hpHosts is queried also for classification for given host, if listed
        :returns: content of response to GET request to hpHosts for data on the given host
        '''
        url = 'http://verify.hosts-file.net/?v={0}&s={1}'.format(self.app_id, host)
        url = url + '&class=true' if classification else url
        
        return get(url).content
    
    def __contains__(self, host):
        ''' Check if given host is present in hpHosts blacklist
        
        :param host: a valid host string
        :returns: a boolean value True if given host is listed on hpHosts, False otherwise
        '''
        return self._LISTED in self._query(host)
        
if __name__ == '__main__':
    pass