#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get, post, Session
from requests.exceptions import HTTPError, Timeout, ConnectionError, InvalidSchema, InvalidURL
from itertools import izip
from ipaddress import ip_address
from dns import name
from collections import namedtuple
import validators
from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain, from_address as name_from_ip
from urlparse import urlparse
import re
import functools

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''
    
class UnathorizedAPIKeyError(SpamBLError):
    ''' Raise when trying to use an unathorized api key '''
    
def accepts_valid_urls(f):
    @functools.wraps(f)
    def wrapper(client, urls):
        '''Run the function and return its return value
         if all given urls are valid - otherwise raise ValueError
        :param client:  a client of a service
        listing hosts or urls
        :param urls: an iterable containing urls
        :returns: a return value of the function f
        :raises ValueError: if the iterable contains invalid urls
        '''
        invalid_urls = filter(lambda u: not is_valid_url(u), urls)
        if invalid_urls:
            msg = 'The values: {} are not valid urls'.format(','.join(invalid_urls))
            raise ValueError, msg
        
        return f(client, urls)
    
    return wrapper
    
class UrlHostTester(object):
    ''' A class containing methods used to test urls with
    their hosts as criteria '''
    
    @accepts_valid_urls
    def any_match(self, urls):
        ''' 
        Check if any of given urls has a listed host
        
        :param urls: an iterable containing urls
        :returns: True if any host is listed
        '''
        
        return any(urlparse(u).hostname in self for u in urls)
    
    @accepts_valid_urls
    def lookup_matching(self, urls):
        '''
        Get objects representing hosts in given urls that match listed hosts
        
        :param urls: an iterable containing urls
        :returns: items representing hosts matching the listed ones
        '''
        
        hosts = (urlparse(u).hostname for u in urls)
        
        for h in hosts:
            item = self.lookup(h)
            if item is not None:
                yield item
    
class DNSBL(UrlHostTester):
    ''' Represents a DNSBL service '''
    def __init__(self, identifier, query_suffix, classification_resolver, host_factory):
        ''' Create new DNSBL object
        
        :param identifier: a value designating DNSBL service provider: its name or url address.
        :param query_suffix: a suffix added to DNSBL query address
        :param classification_resolver: item classes associated with DNSBL query return codes
        :param host_factory: a callable object that returns an object representing host and providing
        method for getting a relative domain pertaining to it.
        '''
        
        self._identifier = identifier

        self._query_suffix = name.from_text(query_suffix)
        self._get_classification = classification_resolver
        self.host_factory = host_factory
    
    def _query(self, host):
        ''' Query DNSBL service for given value
        
        :param host: a host value
        :returns: an integer representing classification code for given value, if it is listed. Otherwise,
        it returns None
        '''
        
        host = self.host_factory(host)
        
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
        
        :param host: a host value
        :returns: an instance of AddressListItem representing given
        host
        :raises UnknownCodeError: if return code does not
        map to any taxonomic unit present in _get_classification
        '''
        
        return_code = self._query(host)
        
        if not return_code:
            return None
        
        try:
            classification = self._get_classification(return_code)
            
            return AddressListItem(str(host), self, classification)
        
        except UnknownCodeError as e:
            raise exc_info()[0],  '{}\nSource:{}'.format(str(e), str(self)), exc_info()[2]
        
class BaseClassificationCodeResolver(object):
    ''' A class responsible for providing classification 
    for given return code '''
    
    def __init__(self, classification):
        ''' Create new instance
        
        :param classification: a dictionary mapping integer codes 
        to taxonomical units
        '''
        self._classification = classification
        
    def _get_single_class(self, index):
        ''' Get one taxonimical unit from the classification
        
        :param index: a value to which a classification may be assigned
        :return: a taxonomical unit assigned to the code
        :raises UnknownCodeException: when there is no taxonomical unit
        for given code in the instance
        '''
        _class = self._classification.get(index)
        
        if _class is None:
            msg = 'The classification code {} was not recognized'.format(index)
            raise UnknownCodeError(msg)
        
        return _class
        
    def __call__(self, code):
        
        raise NotImplementedError

class SimpleClassificationCodeResolver(BaseClassificationCodeResolver):
    ''' A classification resolver recognizing only 
    code values that are stored as indexes of taxonomical units '''
    
    def __call__(self, code):
        ''' Get classification for given code
        
        :param code: a value to which a taxonomical unit may be assigned
        :return: a tuple containing taxonomical unit assigned to the code,
        if it exists
        :raises UnknownCodeError: when there is no classification
        for given code
        '''
        
        return self._get_single_class(code),
        
class SumClassificationCodeResolver(BaseClassificationCodeResolver):
    ''' A classification resolver that recognizes arguments in form
    of both the same codes as stored in the instance and integers
    that can be represented as a sum of different indexes stored in
    the instance'''
    
    def _get_codes(self, code):
        ''' Get codes from given index
        
        The valid codes are different powers of 2. This method transforms
        given integer to a binary string. A reversed value limited to digits
        of binary number is extracted from it, and each of its characters
        is enumerated. If it's not 0, it represents one of the powers
        of 2 whose sums result in index
        
        :param code: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns a list of powers of 2 whose sum is equal to index
        '''
        
        return (2**y for y, x in enumerate(bin(code)[:1:-1]) if int(x))
    
    def __call__(self, code):
        ''' Get classification for given code
        
        :param index: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns: a tuple containing taxonomical units
        :raises: UnknownCodeError, if the code or one of the elements
        of the sum is not present in the instance
        '''
        classifications = []
        
        for code in self._get_codes(code):
            _class = self._get_single_class(code)
            classifications.append(_class)
            
        return tuple(classifications)
    
class HpHosts(UrlHostTester):
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
        
        valid_host = host(host_value)
        
        if validators.ipv6(str(valid_host)):
            msg_template = 'Error for argument: {}. HpHosts does not support ipv6'
            raise ValueError, msg_template.format(valid_host)
        
        url = 'http://verify.hosts-file.net/?v={}&s={}'.format(self.app_id, valid_host)
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
            classification = tuple(elements[1:])
            
            return AddressListItem(host, self, classification)
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
                
    @accepts_valid_urls
    def any_match(self, urls):
        ''' Check if the service recognizes any of given urls as spam
        
        :param urls: a sequence of urls to be tested
        :returns: True if any of the urls was recognized as spam
        '''
        
        return any(self._query(urls))
    
    @accepts_valid_urls
    def lookup_matching(self, urls):
        ''' Get items for all listed urls
        
        :param urls: a sequence of urls to be tested
        :returns: a tuple containing listed url objects
        '''
        
        for url_list, response in self._query(urls):
            classification_set = response.content.splitlines()
            
            for url, _class in izip(url_list, classification_set):
                if _class != 'ok':
                    classification = tuple(_class.split(','))
                    yield AddressListItem(url, self, classification)
    

class HostCollection(UrlHostTester):
    ''' Provides a container for ip addresses and domain names.
    
    May be used as a local whitelist or blacklist.
    '''
    
    def __init__(self, identifier, classification, hosts=()):
        ''' Create new instance
        
        :param identifier: an identifier of this instance of host collection
        :param classification: a tuple containing strings representing
        types of items, assigned to each element of the collection
        :param hosts: a sequence of ip adresses and hostnames
        '''
        
        self.identifier = identifier
        self.classification = classification
        
        self.hosts = set()
        
        for host in hosts:
            self.add(host)
            
    def __contains__(self, host_value):
        ''' Test membership of the host in the collection
        
        :param host: a value representing ip address or a hostname
        :returns: True if given ip address or hostame is subdomain or an
        identical value to at least one value in the collection
        :raises ValueError: if the host is not a valid ip address or hostname
        '''
        
        host_obj = host(host_value)
        
        test = lambda u: host_obj.is_subdomain(u) or host_obj == u
        
        return any(map(test, self.hosts))
    
    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get urls with hosts matching items stored in the collection
        
        :param urls: an iterable containing url addresses to filter
        :returns: a list containing matching urls
        :raises ValueError: when any of given urls is not valid
        '''
        is_match = lambda u: urlparse(u).hostname in self
        return filter(is_match, urls)
    
    def lookup(self, host_value):
        '''
        Return an object representing a parent of given value or the exact value, if
        it there is one in the collection
        
        :param host: a value representing ip address or a hostname, or
        a parent domain of hostname
        :returns: AddressListItem for the given value, if it has been added to
        the collection. Otherwise, return None
        :raises ValueError: if the host is not avalid ip address or hostname
        '''
        host_obj = host(host_value)
        
        for h in self.hosts:
            if host_obj.is_subdomain(h) or host_obj == h:
                return AddressListItem(str(h), self, 
                                       self.classification)
        
    def add(self, host_value):
        ''' Add the given value to collection
        
        :param host: an ip address or a hostname
        :raises ValueError: raised when the given value is not a valid ip address nor a hostname
        '''
        host_obj = host(host_value)
        
        for h in self.hosts:
            if host_obj.is_subdomain() or host_obj == h:
                return
            
            if h.is_subdomain(host_obj):
                self.hosts.remove(h)
                break;
            
        self.hosts.add(host_obj)

AddressListItem = namedtuple('AddressListItem', 'value source classification')

class Host(object):
    ''' Base host class '''
    
    def __str__(self):
        return str(self._value)
    
    def _test_other_value(self, function, other):
        '''
        Perform test on _value property of
        the other using function
        
        :param other: the other object
        :return: value returned by function
        '''
        try:
            return function(other._value)
        
        except AttributeError:
            return False
        
    def is_subdomain(self, other):
        
        raise NotImplementedError
    
    def __eq__(self, other):
        '''
        Test if the object and the other are equal
        
        :param other: other object
        :returns: True if the objects have equal _value
        :raise TypeError: if the _value does not
        have __eq__ method
        '''
        
        return self._test_other_value(self._value.__eq__, other)
    
    def __ne__(self, other):
        '''
        Test if the object and the other are not equal
        
        :param other: other object
        :returns: True if the objects don't have equal _value
        :raise TypeError: if the _value does not
        have __eq__ method
        '''
        
        return not self == other
    
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
    
    def is_subdomain(self, other):
        ''' Test if the object is a subdomain of the
        other
        
        :param other: the object to which we compare this instance
        :returns: True if the _value is subdomain of other._value
        :raises TypeError: if _value doesn't have is_subdomain method
        '''
        
        return self._test_other_value(self._value.is_subdomain, other)
    
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
    
    def is_subdomain(self, other):
        ''' Check if the given object is a subdomain of the other
        
        :param other: another host
        :returns: False, because ip address is not a domain
        '''
        
        return False
    
    
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

class RedirectUrlResolver(object):
    
    def __init__(self, requests_session = Session()):
        '''
        Constructor
        
        :param requests_session: a session object implementing
        methods:
        * head(url) (for HEAD request)
        * resolve_redirects(response, request)
        '''
        
        self.session = requests_session
        
    def get_first_response(self, url):
        ''' Get the first response to HEAD request for given url
        
        :param url: a url value
        :returns: If no exception was raised, it returns 
        an object representing the first response in the response history 
        for given url.
        
        Otherwise, None is returned.
        
        :raises ValueError: if the parameter is not a valid url value
        '''
        
        if not is_valid_url(url):
            raise ValueError, '{} is not a valid url'.format(url)
        
        try:
            return self.session.head(url)
        
        except (ConnectionError, InvalidSchema, Timeout):
            return None
        
    def get_redirect_urls(self, url):
        ''' Get valid location header values from
        responses for given url
        
        :param url: a url value
        :returns: valid redirection addresses. If a request
        for an address fails, and the address is still a valid url string, 
        it's included as the last yielded value. If it's not, the previous value
        is the last one.
        :raises ValuError: if the argument is not a valid url
        '''
        
        response = self.get_first_response(url)
        
        if response:
            try:
                for response in self.session.resolve_redirects(response, response.request):
                    yield response.url
                    
            except InvalidURL: pass
                
            except (Timeout, ConnectionError, InvalidSchema) as e:
                last_url = response.headers['location']
                
                if isinstance(e, Timeout) or is_valid_url(last_url):
                    yield last_url
        
                    
class BaseUrlTester(object):
    ''' A base for classes responsible for url testing '''
    
    _redirect_url_resolver = None
    
    def __init__(self, client, redirect_session = None):
        ''' Create a new instance
        
        :param client: a client of service responsible
        for testing criteria of recognizing url as spam
        :param redirect_session: requests.Session instance used for redirect
        url resolution
        '''
        
        self.client = client
        
        if redirect_session is not None:
            self.redirect_url_resolver.session = redirect_session
        
    @property
    def redirect_url_resolver(self):
        ''' Get redirect url resolver
        
        :returns: an instance of RedirecUrlResolver set for this object
        '''
        if self._redirect_url_resolver is None:
            self._redirect_url_resolver = RedirectUrlResolver()
            
        return self._redirect_url_resolver
    
    def _get_redirect_urls(self, urls):
        ''' Get unique redirect urls for given urls
        
        :param urls: original urls
        :returns: valid url addresses of redirects
        '''
        seen = set(urls)
        
        for u in urls:
            redirect_urls = self.redirect_url_resolver.get_redirect_urls(u)
            
            for ru in redirect_urls:
                if ru in seen:
                    break
                
                seen.add(ru)
                yield ru
               
    def _get_urls_to_test(self, urls, resolve_redirects=False):
        ''' From given urls, get all url addresses to test
        
        :param urls: a sequence of url values
        :param resolve_redirects: if True, url addresses of redirections will also
        be returned
        :returns: url addresses to test
        '''
        urls = set(urls)
        
        for u in urls:
            if not is_valid_url(u):
                raise ValueError, '{} is not a valid url'.format(u)
            
            yield u
            
        if resolve_redirects:
            for ru in self._get_redirect_urls(urls):
                yield ru
                
if __name__ == '__main__':
    pass