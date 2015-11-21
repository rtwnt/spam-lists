#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get, post, HTTPError
from itertools import izip, product
from ipaddress import ip_address
import re
from dns import name

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''

class DNSBLClientError(SpamBLError):
    ''' A base for some exceptions raised by BaseDNSBLClient '''
    
    msg_tpl = None
    def __init__(self, client, dnsbl_service, *args):
        msg = self.msg_tpl.format(client.__class__.__name__, dnsbl_service.__class__.__name__)
        
        super(DNSBLClientError, self).__init__(msg, *args)

class DNSBLContentError(DNSBLClientError, ValueError):
    ''' Raise when trying to use an instance of DNSBL service that doesn't
    support expected type of items
    ''' 
    
    msg_tpl = 'This instance of {} does not list items required by {}'
    
class DNSBLTypeError(DNSBLClientError, TypeError):
    ''' Raise when trying to use an object that is expected to represent dnsbl service
    but doesn't have required attributes
    '''
    
    msg_tpl = 'This instance of {} does not have an attribute required by {}'
    
class UnathorizedAPIKeyError(SpamBLError):
    ''' Raise when trying to use an unathorized api key '''
    
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
    

class DNSBLService(object):
    ''' Represents a DNSBL service '''
    def __init__(self, identifier, query_suffix, code_item_class, lists_ips, lists_uris):
        ''' Create new DNSBLService object
        
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
            
            msg_template = 'Unexpected code value for dnsbl service {}: {}'
            raise UnknownCodeError(msg_template.format(self.identifier, code)), None, exc_info()[2]
    
    def query(self, value):
        ''' Query DNSBL service for given value
        
        :param value: a valid hostname or a valid inverted ip address
        :returns: an integer representing classification code for given value, if it is listed. Otherwise,
        it returns None
        '''
        try:
            response = query(value+'.'+self._query_suffix)
                
        except NXDOMAIN:
            return None
            
        else:
            last_octet = response[0].to_text().split('.')[-1]
            
            return int(last_octet)
        
class BaseDNSBLClient(object):
    ''' Implements basic feaures of DNSBL client classes '''
    
    def __init__(self):
        self.dnsbl_services = []
        
    def _get_relative_domain(self, host):
        ''' Get relative domain name for given host
        
        :param host: a valid host
        :returns: a dns name object
        '''
        
        raise NotImplementedError('The method is not implemented')
    
    def _required_content_in(self, dnsbl):
        ''' Check if dnsbl has content required by this client
        
        :param dnsbl: an object representing dnsbl service
        '''
        
        raise NotImplementedError('The method is not implemented')
    
    def add_dnsbl(self, dnsbl):
        ''' Create new instance
        
        :param dnsbl: an object representing dnsbl service
        '''
        
        try:
            required_content_in = self._required_content_in(dnsbl)
        except AttributeError:
            raise DNSBLTypeError(self, dnsbl), None, exc_info()[2]
            
        if not required_content_in:
            raise DNSBLContentError(self, dnsbl)
            
        self.dnsbl_services.append(dnsbl)
    
    def _get_item_data(self, host):
        ''' Query registered dnsbl services for data on given host
        
        :param host: a valid host
        :returns: a tuple containing host, source and return code for listed host, or
        an empty tuple for not listed one
        '''
        for source in self.dnsbl_services:
            return_code = source.query(host)
            yield (host, source, return_code) if return_code else ()
            
    def __contains__(self, host):
        return any(self._get_item_data(host))
    
    def lookup(self, host):
        ''' Get all items listed in registered dnsbl services for given host 
        
        :params host: a valid host
        :returns: a list of objects representing host on different dns blocklists on which
        it is listed
        '''
        
        return tuple(DNSBLItem(*data) for data in self._get_item_data(host) if data)
        
class DNSBLClient(object):
    ''' Responsible for querying DNSBL services that list ip addresses'''
                
class URIDNSBLClient(object):
    ''' Responsible for querying DNSBL services that list hostnames '''
    
class ListItem(object):
    ''' Represents a host listed on a blocklist'''
    
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
    
    def lookup(self, host):
        ''' Get an object representing a value for a given host, if listed in hpHosts
        
        :param host: a valid host string
        :returns: a ListItem object, or None if host is not listed
        '''
        data = self._query(host, True)
        
        if self._LISTED in data:
            elements = data.split(',')
            classification = elements[1] if len(elements) > 1 else None
            
            return ListItem(host, self.identifier, classification)
        return None
        
class GoogleSafeBrowsing(object):
    ''' Google Safe Browsing lookup API client '''
    
    protocol_version = '3.1'
    max_urls_per_request = 500
    
    def __init__(self, client_name, app_version, api_key):
        ''' Create new instance
        
        :param client_name: name of application using the API
        :param app_version: version of the application
        :param api_key: API key given by Google: 
        https://developers.google.com/safe-browsing/key_signup
        '''
        
        self.api_key = api_key
        self.client_name = client_name
        self.app_version = app_version
        self._request_address_val = ''
        
    @property
    def _request_address(self):
        ''' Get address of POST request to the service '''
        
        if not self._request_address_val:
            tpl = 'https://sb-ssl.google.com/safebrowsing/api/lookup?client={0}&key={1}&appver={2}&pver={3}'
            self._request_address_val = tpl.format(self.client_name, self.api_key, self.app_version, self.protocol_version)
            
        return self._request_address_val
    
    def _query_once(self, urls):
        ''' Perform a single POST request using lookup API
        
        :param urls: a sequence of urls to put in request body
        :returns: a response object
        :raises UnathorizedAPIKeyError: when the API key for this instance 
        is not valid
        :raises HTTPError: if the HTTPError was raised for a HTTP code
        other than 401, the exception is reraised
        '''
        
        request_body = '{}\n{}'.format(len(urls), '\n'.join(urls))
        response = post(self._request_address, request_body)
            
        try:
                response.raise_for_status()
                
        except HTTPError:
            if response.status_code == 401:
                raise UnathorizedAPIKeyError('The API key is not authorized'), None, exc_info()[2]
            else:
                raise
            
        return response
        
    def _query(self, urls):
        ''' Test urls for being listed by the service
        
        :param urls: a sequence of urls  to be tested
        :returns: a tuple containing chunk of urls and a response pertaining to them
        if the code of response was 200, which means at least one of the queried URLs 
        is matched in either the phishing, malware, or unwanted software lists.
        '''
        
        for i in range(0, len(urls), self.max_urls_per_request):
            
            chunk = urls[i:i+self.max_urls_per_request]
            response = self._query_once(chunk)
            
            if response.status_code == 200:
                yield chunk, response
    
    def contains_any(self, urls):
        ''' Check if the service recognizes any of given urls as spam
        
        :param urls: a sequence of urls to be tested
        :returns: True if any of the urls was recognized as spam
        '''
        
        return any(self._query(urls))
    
    def lookup(self, urls):
        ''' Get items for all listed urls
        
        :param urls: a sequence of urls to be tested
        :returns: a tuple containing listed url objects
        '''
        
        items = []
        
        for url_list, response in self._query(urls):
            classification_set = response.content.splitlines()
            
            for url, _class in izip(url_list, classification_set):
                if _class != 'ok':
                    items.append(ListItem(url, self, _class.split(',')))
                    
        return tuple(items)
    

class HostCollection(object):
    ''' Provides a container for ip addresses and domain names
    
    Contains methods for testing if the collection matches partly with 
    another instance. The match is detected when:
    
    * both collections have at least one the same ip address in them
    * this collection contains a subdomain of a domain in the other collection
    '''
    
    def __init__(self, hosts=()):
        ''' Create new instance
        
        :param hosts: a sequence of ip adresses and hostnames
        '''
        
        self.ip_addresses = set()
        self.hostnames = set()
        
        for host in hosts:
            self.add(host)
        
    def is_valid_hostname(self, host):
        ''' Test if given value is a valid hostname string 
        
        :param host: a value to be tested
        '''
        
        if host[-1] == '.':
            host = host[:-1]
            
        label = '(?!-)[a-z0-9-]{1,63}(?<!-)'
        
        return 1 < len(host) < 253 and re.match('^(?:'+label+'\.)*'+label+'$', host)
        
    def add(self, host):
        ''' Add the given value to collection
        
        :param host: an ip address or a hostname
        :raises ValueError: raised when the given value is not a valid ip address nor a hostname
        '''
        try:
            host = ip_address(host)
            
        except ValueError:
            if self.is_valid_hostname(host):
                self.hostnames.add(name.from_text(host))
                
            else:
                raise ValueError, "The value '{}' is not a valid host".format(host), exc_info()[2]
            
        else:
            self.ip_addresses.add(host)
            return
            
    def get_domain_matches(self, other):
        ''' Get domains from the other that are subdomains
        of domains in this host collection 
        
        :param other: an instance of HostCollection
        :returns: a subdomain of a domain in the other
        '''
        
        for sub, _super in product(self.hostnames, other.hostnames):
            if sub.is_subdomain(_super):
                yield sub
    
    def contains_match(self, other):
        ''' Test if the other contains a matching value 
        
        :param other: an instance of HostCollection
        :returns: True if any match between the collections is detected
        '''
        if any(ip in self.ip_addresses for ip in other.ip_addresses):
            return True
        
        return any(self.get_domain_matches(other))
        
        

if __name__ == '__main__':
    pass