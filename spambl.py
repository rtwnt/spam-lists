#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get, post, HTTPError
from itertools import izip, product
from ipaddress import ip_address
from dns import name
from collections import namedtuple
import validators
from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain, from_address as name_from_ip

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''
    
class UnathorizedAPIKeyError(SpamBLError):
    ''' Raise when trying to use an unathorized api key '''
    

def relative_name(hostname):
    ''' Create relative domain name
    
    :param hostname: a hostname string
    :returns: instance of dns.name.Name for given hostname, relative to
    the root domain dns.name.root.
    :raises ValueError: if the hostname is not valid
    '''
    
    if validators.domain(hostname):
        return name.from_text(hostname).relativize(name.root)
    
    raise ValueError('Value "{}" is not a valid hostname'.format(hostname))

def relative_reverse_pointer(ip):
    ''' Create relative reverse pointer
    
    :param ip: instance of ip address class from ipaddress module
    :returns: a dns.name.Name instance for given IP, representing
    reverse pointer relative to the reverse pointer base domain
    for the version of given ip
    '''
    
    ip = ip_address(ip)
    root = ipv4_reverse_domain if ip.version == 4 else ipv6_reverse_domain
    
    return name_from_ip(str(ip)).relativize(root)
    
class BaseDNSBL(object):
    ''' Represents a DNSBL service '''
    def __init__(self, identifier, query_suffix, code_item_class):
        ''' Create new BaseDNSBL object
        
        :param identifier: a value designating DNSBL service provider: its name or url address.
        :param query_suffix: a suffix added to DNSBL query address
        :param code_item_class: item classes associated with DNSBL query return codes
        '''
        
        self._identifier = identifier

        self._query_suffix = name.from_text(query_suffix)
        self._code_item_class = code_item_class
    
    def _do_query(self, hostname):
        ''' Query DNSBL service for given value
        
        :param hostname: a relative domain name
        :returns: an integer representing classification code for given value, if it is listed. Otherwise,
        it returns None
        '''
        
        if hostname.is_absolute():
            raise ValueError('The value {} is not a relative host!'.format(hostname))
        
        query_name = hostname.derelativize(self._query_suffix)
        
        try:
            response = query(query_name)
            last_octet = response[0].to_text().split('.')[-1]
            
            return int(last_octet)
                
        except NXDOMAIN:
            return None
        
    def __str__(self):
        return str(self._identifier)
        
    def __contains__(self, host):
        ''' Check if given host is listed by this service
        
        :param host: a host string
        :return: True if the host is listed, otherwise False
        '''
        return bool(self._query(host))
    
    def lookup(self, host):
        ''' Perform item lookup for given host
        
        :param host: a host value expected by query_method
        :returns: an instance of AddressListItem representing given
        host
        :raises UnknownCodeError: if return code does not
        map to any taxonomic unit present in _code_item_class
        '''
        
        return_code = self._query(host)
        
        if not return_code:
            return None
        
        try:
            classification = self._code_item_class[return_code]
            
            return AddressListItem(str(host), self._identifier, classification)
        
        except UnknownCodeError as e:
            raise type(e), 'Source:'+str(self), exc_info()[2]
        
class IpDNSBL(BaseDNSBL):
    
    def _query(self, ip):
        ''' Query for given ip
        
        :param ip: a value representing ip address
        :returns: a return code from the service if it lists the ip, otherwise None
        '''
        query_prefix = relative_reverse_pointer(ip)
        
        return self._do_query(query_prefix)

class DomainDNSBL(BaseDNSBL):
    
    def _query(self, hostname):
        ''' Query the service for given hostname
        
        :param hostname: a string value representing a hostname
        :returns: a return code from the service if the hostname is listed on it, otherwise None
        '''
        
        query_prefix = relative_name(hostname)
        return self._do_query(query_prefix)

class GeneralDNSBL(BaseDNSBL):
    
    def _query(self, host):
        ''' Query the service for given host
        
        :param host: a value representing a host: an ip address or a hostname
        :returns: a return code from the service if the host is listed on it, otherwise None
        '''
        
        for f in relative_reverse_pointer, relative_name:
            try:
                query_prefix = f(host)
                return self._do_query(query_prefix)
            
            except ValueError: pass
        
        raise ValueError, 'The value "{}" is not a valid host'.format(host), exc_info()[2]

class CodeClassificationMap(object):
    ''' A map containing taxonomical units assigned to integer codes'''
    def __init__(self, classification):
        ''' Create new instance
        
        :param classification: a dictionary mapping integer codes to taxonomical units
        '''
        self.classification = classification
        
    def __getitem__(self, index):
        ''' Get taxonomical unit for given index 
        :param index: an integer value that's supposed to map to a class
        :raises UnknownCodeError: raised when given index does not
        map to a class
        '''
        _class = self.classification.get(index)
        
        if _class is None:
            msg = 'The classification code {} was not recognized'.format(index)
            raise UnknownCodeError(msg)
        
        return _class
        
class SumClassificationMap(CodeClassificationMap):
    ''' A map containing taxonomical units assigned to integer codes
    
    Multiple items in the instance of this class may be accessed by
    providing a sum of valid indexes as index'''
    
    
    def _get_codes(self, index):
        ''' Get codes from given index
        
        The valid codes are different powers of 2. This method transforms
        given integer to a binary string. A reversed value limited to digits
        of binary number is extracted from it, and each of its characters
        is enumerated. If it's not 0, it represents one of the powers
        of 2 whose sums result in index
        
        :param index: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns a list of powers of 2 whose sum is equal to index
        '''
        
        return (2**y for y, x in enumerate(bin(index)[:1:-1]) if int(x))
    
    def __getitem__(self, index):
        ''' Get taxonomical units for given index
        
        :param index: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns: a tuple containing taxonomical units
        '''
        classifications = []
        
        for code in self._get_codes(index):
            _class = CodeClassificationMap.__getitem__(self, code)
            classifications.append(_class)
            
        return tuple(classifications)
    
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
            
            return AddressListItem(host, self.identifier, classification)
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
        
        urls = list(set(urls))
        
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
                    items.append(AddressListItem(url, self, _class.split(',')))
                    
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
        
    def add(self, host):
        ''' Add the given value to collection
        
        :param host: an ip address or a hostname
        :raises ValueError: raised when the given value is not a valid ip address nor a hostname
        '''
        try:
            host = ip_address(host)
            self.ip_addresses.add(host)
            return
            
        except ValueError:
            pass
        
        try:
            host = relative_name(host)
            self.hostnames.add(host)
            
        except ValueError:
            raise ValueError, 'The value "{}" is not a valid host'.format(host), exc_info()[2]
            
    def get_domain_matches(self, other):
        ''' Get domains from the other that are subdomains
        of domains in this host collection 
        
        :param other: an instance of HostCollection
        :returns: a subdomain of a domain in the other
        '''
        
        for sub, _super in product(self.hostnames, other.hostnames):
            if sub.is_subdomain(_super):
                yield sub
                
    def __iter__(self):
        for ip in self.ip_addresses:
            yield ip
            
        for hostname in self.hostnames:
            yield hostname
    
    def contains_match(self, other):
        ''' Test if the other contains a matching value 
        
        :param other: an instance of HostCollection
        :returns: True if any match between the collections is detected
        '''
        if any(ip in self.ip_addresses for ip in other.ip_addresses):
            return True
        
        return any(self.get_domain_matches(other))
        
    def difference(self, other):
        ''' Return a new host collection without matches from the other
        
        :param other: an instance of HostCollection
        :returns: new instance of HostCollection
        '''
        
        new  = HostCollection()
        new.ip_addresses = self.ip_addresses - other.ip_addresses
        new.hostnames = self.hostnames - {x for x in self.get_domain_matches(other)}
        
        return new

AddressListItem = namedtuple('AddressListItem', 'value source classification')
        
        
if __name__ == '__main__':
    pass