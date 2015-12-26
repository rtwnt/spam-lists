#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get, post, adapters, Session
from requests.exceptions import (HTTPError, Timeout, ConnectionError, InvalidSchema, InvalidURL,
                                 MissingSchema)
from itertools import izip
from ipaddress import ip_address
from dns import name
from collections import namedtuple
import validators
from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain, from_address as name_from_ip
from urlparse import urlparse
import re

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''
    
class UnathorizedAPIKeyError(SpamBLError):
    ''' Raise when trying to use an unathorized api key '''
    
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
    
    def _do_query(self, host):
        ''' Query DNSBL service for given value
        
        :param host: a host object that can provide a relative domain value representing it
        :returns: an integer representing classification code for given value, if it is listed. Otherwise,
        it returns None
        '''
        
        hostname = host.relative_domain
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
            raise exc_info()[0],  '{}\nSource:{}'.format(str(e), str(self)), exc_info()[2]
        
class IpDNSBL(BaseDNSBL):
    
    def _query(self, ip):
        ''' Query for given ip
        
        :param ip: a value representing ip address
        :returns: a return code from the service if it lists the ip, otherwise None
        '''
        
        return self._do_query(IpAddress(ip))

class DomainDNSBL(BaseDNSBL):
    
    def _query(self, hostname):
        ''' Query the service for given hostname
        
        :param hostname: a string value representing a hostname
        :returns: a return code from the service if the hostname is listed on it, otherwise None
        '''
        
        return self._do_query(Hostname(hostname))

class GeneralDNSBL(BaseDNSBL):
    
    def _query(self, host_value):
        ''' Query the service for given host
        
        :param host: a value representing a host: an ip address or a hostname
        :returns: a return code from the service if the host is listed on it, otherwise None
        '''
        
        return self._do_query(host(host_value))

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
        
    def _query(self, host_value, classification = False):
        ''' Query the client for data of given host
        
        :param host: a valid host string
        :param classification: if True: hpHosts is queried also for classification for given host, if listed
        :returns: content of response to GET request to hpHosts for data on the given host
        '''
        
        host_value = host(host_value)
        url = 'http://verify.hosts-file.net/?v={0}&s={1}'.format(self.app_id, host_value)
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
    ''' Provides a container for ip addresses and domain names.
    
    May be used as a local whitelist or blacklist.
    '''
    
    def __init__(self, hosts=()):
        ''' Create new instance
        
        :param hosts: a sequence of ip adresses and hostnames
        '''
        
        self.hosts = set()
        
        for host in hosts:
            self.add(host)
            
    def __contains__(self, host_value):
        ''' Test membership of the host in the collection
        
        :param host: a value representing ip address or a hostname
        :returns: True if given ip address or hostame match at least one value in the
        collection
        :raises ValueError: if the host is not a valid ip address or hostname
        '''
        
        host_obj = host(host_value)
        return any(map(host_obj.is_match, self.hosts))
        
    def add(self, host_value):
        ''' Add the given value to collection
        
        :param host: an ip address or a hostname
        :raises ValueError: raised when the given value is not a valid ip address nor a hostname
        '''
        
        self.hosts.add(host(host_value))

AddressListItem = namedtuple('AddressListItem', 'value source classification')

class Host(object):
    ''' Base host class '''
    def is_match(self, other):
        ''' Check if the other object matches this instance
        
        The rules of matching are implemented in
        _is_match method of subclasses of Host
        
        :param other: other object to which we compare this instance
        :returns: True if the objects match
        '''
        
        if isinstance(other, self.__class__):
            
            return self._is_match(other)
        
        return False
    
    def __str__(self):
        return str(self._value)
    
    def _is_match(self, other):
        
        raise NotImplementedError
    
class Hostname(Host):
    def __init__(self, value):
        ''' Create a new instance of Hostname
        
        :param value: a string representing a hostname
        :raises ValueError: if value parameter is not a string
        '''
        value  = str(value)
        if not validators.domain(value):
            raise ValueError, "'{}' is not a valid hostname".format(value), exc_info()[2]
        
        self._value = name.from_text(value).relativize(name.root)
        
    @property
    def relative_domain(self):
        ''' Return a relative domain representing the value
        
        :returns: the _value property of the object
        '''
        return self._value
    
    def _is_match(self, other):
        ''' Test if the object matches the other
        
        :param other: the object to which we compare this instance
        :returns: True if the _value is subdomain of other._value
        :raises AttributeError, TypeError: if the other object does not
        contain _value, or _value is not of required type
        '''
        
        return self._value.is_subdomain(other._value)
    
class IpAddress(Host):
    def __init__(self, value):
        ''' Create a new instance of IpAddress
        
        :param value: a value representing ip address
        :raises AddressValueError: if the value is an instance of bytes (python3)
        or str (python 2)
        :raises ValueError: if the value is not a valid ip v4 or ip v6 address
        '''
        
        self._value = ip_address(value)
        
    @property
    def relative_domain(self):
        ''' Get a relative domain name representing the ip address
        
        :returns: the reverse pointer relative to the common root
        depending on the version of ip address stored in _value
        '''
        
        root = ipv4_reverse_domain if self._value.version == 4 else ipv6_reverse_domain
        
        return name_from_ip(str(self._value)).relativize(root)
    
    def _is_match(self, other):
        ''' Test if this object matches the other
        
        :returns: True if both objects have equal _value properties
        :raises AttributeError: if the other object does not have _value attribute
        '''
        return self._value == other._value
    
    
def host(value):
    ''' Create an instance of IpAddress or Hostname from a given value
    
    :param value: an ip address or a hostname
    :returns: an instance of a subclass of Host, either an ip address or a hostname
    :raises ValueError: if the value is not a valid ip address or hostname
    '''

    data = [value]
    
    for f in IpAddress, Hostname:
        try:
            return  f(value)
        
        except ValueError as e:
            data.append(str(e))
    
    msg_tpl = "The value '{}' is not a valid host:\n* {}\n* {}"
    raise ValueError, msg_tpl.format(*data)

url_regex = re.compile(r'^[a-z0-9\.\-\+]*://' #scheme
                       r'(?:\S+(?::\S*)?@)?' #authentication
                       r'(?:[^/:]+|\[[0-9a-f:\.]+\])' # host
                       r'(?::\d{2,5})?' # port
                       r'(?:[/?#][^\s]*)?' # path, query or fragment
                       r'$', re.IGNORECASE)

def is_valid_url(value):
    ''' Check if given value is valid url string
    
    :param value: a value to test
    :returns: True if the value is valid url string
    '''
    host_validators = validators.ipv4, validators.ipv6, validators.domain
    
    match = url_regex.match(value)
    
    host = urlparse(value).hostname
    
    return (match and any(f(host) for f in host_validators))
    
def request_session(max_retries):
    ''' Get a request session
    
    :param max_retries: maximum number of retries configured for 
    the session
    :returns: a requests.Session instance
    '''
    
    adapter = adapters.HTTPAdapter(max_retries=max_retries)
    session = Session()
    
    for s in 'http://', 'https://':
        session.mount(s, adapter)
        
    return session

class RedirectUrlResolver(object):
    '''Responsible for listing valid response addresses for given urls'''
    
    def __init__(self, session = Session()):
        ''' Create a new instance
        
        :param session: a requests.Session instance used for resolving redirects
        '''
        
        self.session = session
        
    def get_first_response(self, url):
        ''' Get the first response from a chain
        
        :param url: a url value
        :returns: an object representing the first response in
        the response history for given url
        :raises ValueError: if the parameter is not a valid url value
        '''
        try:
            return self.session.head(url)
            
        except (ConnectionError, InvalidSchema):
            if not is_valid_url(url):
                raise ValueError, '{} is not a valid url'.format(url), exc_info()[2]
        except (InvalidURL, MissingSchema) as e:
            raise ValueError, str(e), exc_info()[2]
        except Timeout:
            pass
        
    def __call__(self, url):
        ''' Get urls of all redirects following request with the given url
        
        :param url: a url value
        :returns: valid redirection addresses. If a request
        for an address fails, and the address is a valid url string, it's included as the
        last returned value. If the value is invalid, no further values are returned.
        :raises ValuError: if the argument is not a valid url value
        '''
        response = self.get_first_response(url)
        if response:
            try:
                for response in self.session.resolve_redirects(response, response.request):
                    yield response.url
                    
            except InvalidURL: pass
                
            except (Timeout, ConnectionError, InvalidSchema):
                last_url = response.headers['location']
                
                if is_valid_url(last_url):
                    yield last_url
    
if __name__ == '__main__':
    pass