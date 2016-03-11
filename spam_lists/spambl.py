#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exc_info
from dns.resolver import query, NXDOMAIN
from requests import get, post, Session
from requests.exceptions import HTTPError, Timeout, ConnectionError, InvalidSchema, InvalidURL
from itertools import izip, chain
import ipaddress
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
    def wrapper(client, urls, *args, **kwargs):
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
        
        return f(client, urls, *args, **kwargs)
    
    return wrapper

class HostList(object):
    ''' A class of clients for local or remote host list services '''
    
    def __init__(self, host_factory):
        ''' Constructor
        
        :param host_factory: a function responsible for
        creating valid host objects. It may raise ValueError
        (or its subclasses) if a value passed to it is not
        a valid host of type accepted by the factory.
        '''
        
        self._host_factory = host_factory
        
    def _contains(self, host_value):
        ''' Check if the service lists an item
        matching given host value
        
        :param host_value: a host value
        :returns: True if the service lists a matching
        value
        '''
        raise NotImplementedError
        
    def _get_match_and_classification(self, host_value):
        ''' Get a listed value that matches
        given host value and its classification
        
        :param host_value: a host value
        :returns: a tuple containing listed item and its classification as
        a tuple containing all classification groups to which the item belongs
        '''
        raise NotImplementedError
        
    def __contains__(self, host_value):
        ''' Check if given host value is listed by the service
        
        :param host_value: a value of the host of a type
        that can be listed by the service
        :returns: True if the host is listed
        '''
        host_object = self._host_factory(host_value)
        return self._contains(host_object)
    
    def lookup(self, host_value):
        ''' Get an object representing a host value
        matched by this host
        
        :param host_value: a value of the host of a type
        that can be listed by the service
        :returns: an instance of AddressListItem representing
        a matched value
        '''
        host_object = self._host_factory(host_value)
        host_item, classification = self._get_match_and_classification(host_object)
        
        if host_item is not None:
            return AddressListItem(str(host_item), self, classification)
        return None
        
    
class UrlHostTester(object):
    ''' A class containing methods used to test urls with
    their hosts as criteria '''
    
    def __contains__(self, other):
        raise NotImplementedError
    
    def lookup(self, other):
        raise NotImplementedError
    
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
                
    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get urls with hosts matching listed ones
        
        :param urls: an iterable containing url addresses to filter
        :returns: a list containing matching urls
        :raises ValueError: when any of given urls is not valid
        '''
        is_match = lambda u: urlparse(u).hostname in self
        return (u for u in urls if is_match(u))
    
class DNSBL(HostList, UrlHostTester):
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
        self._host_factory = host_factory
        
        super(DNSBL, self).__init__(host_factory)
    
    def _query(self, host_object):
        ''' Query DNSBL service for given value
        
        :param host_object: an object representing host, created by _host_factory
        :returns: an integer representing classification code for given value, if it is listed. Otherwise,
        it returns None
        '''
        host_to_query = host_object.relative_domain
        query_name = host_to_query.derelativize(self._query_suffix)
        
        try:
            response = query(query_name)
            last_octet = response[0].to_text().split('.')[-1]
            
            return int(last_octet)
                
        except NXDOMAIN:
            return None
        
    def __str__(self):
        return str(self._identifier)
        
    def _contains(self, host_object):
        
        return bool(self._query(host_object))
    
    def _get_match_and_classification(self, host_object):
        
        return_code = self._query(host_object)
        
        if not return_code:
            return None, None
        
        try:
            classification = self._get_classification(return_code)
            
            return host_object, classification
        
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
    
class HpHosts(HostList, UrlHostTester):
    ''' hpHosts client '''
    
    identifier = ' http://www.hosts-file.net/'
    _LISTED = 'Listed'
    
    def __init__(self, client_name):
        '''
        Constructor
        
        :param client_name: name of client using the service
        '''
        
        self.app_id = client_name
        
        super(HpHosts, self).__init__(host)
        
    def _query(self, host_object, classification = False):
        ''' Query the client for data of given host
        
        :param host_object: an object representing a host value
        :param classification: if True: hpHosts is queried also for classification for given host, if listed
        :returns: content of response to GET request to hpHosts for data on the given host
        '''
        
        if validators.ipv6(str(host_object)):
            msg_template = 'Error for argument: {}. HpHosts does not support ipv6'
            raise ValueError, msg_template.format(host_object)
        
        url = 'http://verify.hosts-file.net/?v={}&s={}'.format(self.app_id, host_object)
        url = url + '&class=true' if classification else url
        
        return get(url).content
    
    def _contains(self, host_object):
        
        return self._LISTED in self._query(host_object)
    
    def _get_match_and_classification(self, host_object):
        
        data = self._query(host_object, True)
        
        if self._LISTED in data:
            elements = data.split(',')
            classification = tuple(elements[1:])
            
            return host_object, classification
        return None, None
        

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
    
    def _get_classification_per_matching(self, urls):
        ''' Get classification for all matching urls
        
        :param urls: a sequence of urls to test
        :return: a tuple containing matching url and classification
        string pertaining to it
        '''
        for url_list, response in self._query(urls):
            classification_set = response.content.splitlines()
            
            for url, _class in izip(url_list, classification_set):
                if _class != 'ok':
                    yield url, _class
    
    @accepts_valid_urls
    def lookup_matching(self, urls):
        ''' Get items for all listed urls
        
        :param urls: a sequence of urls to be tested
        :returns: a tuple containing listed url objects
        '''
        
        for url, _class in self._get_classification_per_matching(urls):
            classification = tuple(_class.split(','))
            yield AddressListItem(url, self, classification)
                    
    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get all listed urls
        
        :param urls: a sequence of urls to be tested
        :returns: spam urls
        '''
        
        for url, _ in self._get_classification_per_matching(urls):
            yield url
    

class HostCollection(HostList, UrlHostTester):
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
        
        for host_value in hosts:
            self.add(host_value)
            
        super(HostCollection, self).__init__(host)
            
    def _contains(self, host_object):
        
        test = lambda u: host_object.is_subdomain(u) or host_object == u
        return any(map(test, self.hosts))
    
    def _get_match_and_classification(self, host_object):
        
        for h in self.hosts:
            if host_object.is_subdomain(h) or host_object == h:
                return h, self.classification
        return None, None
        
    def add(self, host_value):
        ''' Add the given value to collection
        
        :param host: an ip address or a hostname
        :raises ValueError: raised when the given value is not a valid ip address nor a hostname
        '''
        host_obj = self._host_factory(host_value)
        
        for h in self.hosts:
            if host_obj.is_subdomain() or host_obj == h:
                return
            
            if h.is_subdomain(host_obj):
                self.hosts.remove(h)
                break;
            
        self.hosts.add(host_obj)

AddressListItem = namedtuple('AddressListItem', 'value source classification')

class Hostname(name.Name):
    def __init__(self, value):
        ''' Create a new instance of Hostname
        
        :param value: a string representing a hostname
        :raises ValueError: if value parameter is not a string or
        not a valid domain
        '''
        value  = str(value)
        if not validators.domain(value):
            raise ValueError, "'{}' is not a valid hostname".format(value), exc_info()[2]
        
        super(Hostname, self).__init__(value.split('.'))
        
    @property
    def relative_domain(self):
        ''' Return a relative domain representing the host
        
        :returns: this instance
        '''
        return self
    
    def is_subdomain(self, other):
        ''' Test if the object is a subdomain of the
        other
        
        :param other: the object to which we compare this instance
        :returns: True if this instance is a subdomain of the other
        '''
        try:
            return name.Name.is_subdomain(self, other)
            
        except AttributeError:
            return False
    
    
class IPAddress(object):
    
    reverse_domain = None
    
    @property
    def relative_domain(self):
        ''' Get a relative domain name representing the ip address
        
        :returns: the reverse pointer relative to the common root
        depending on the version of ip address represented by this object
        '''
        
        return name_from_ip(str(self)).relativize(self.reverse_domain)
    
    def is_subdomain(self, other):
        ''' Check if this object is a subdomain of the other
        
        :param other: another host
        :returns: False, because ip address is not a domain
        '''
        
        return False
    
class IPv4Address(ipaddress.IPv4Address, IPAddress):
    reverse_domain = ipv4_reverse_domain
    
class IPv6Address(ipaddress.IPv6Address, IPAddress):
    reverse_domain = ipv6_reverse_domain

def get_create_host(*factories):
    '''
    Get an instance of create_host function
    that uses given factories
    
    :param factories: functions responsible for constructing
    objects representing hostnames and ip addresses
    :returns: create_host function with the factories in its
    scope
    '''
    def create_host(value):
        ''' Create an instance of host object for given value, using
        the available factories.
        
        :param value: a value to be passed as argument to factories
        :returns: an object representing value, created by one of the factories.
        It's a return value of the first factory that could create it for the given argument
        :raises ValueError: if the value is not a valid input for any factory used
        by this function
        '''
        
        data = [value]
        
        for f in factories:
            try:
                return  f(value)
            
            except ValueError as e:
                data.append(str(e))
                
        msg_tpl = "Failed to create a host object for '{}', raising the following\
         errors in the process:"+"\n".join(data)
        raise ValueError, msg_tpl.format(value)
    return create_host

host = get_create_host(IPv4Address, IPv6Address, Hostname)

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

class UrlTesterChain(object):
    '''
    A url tester using a sequence of other url testers
    '''
    
    def __init__(self, *url_testers):
        '''
        Constructor
        
        :param url_testers: a list of objects having any_match(urls) and lookup_matching(urls)
        methods
        '''
        
        self.url_testers = list(url_testers)
        
    def any_match(self, urls):
        ''' Check if any of given urls is a match
        
        :param urls: a sequence of urls to be tested
        :returns: True if any of the urls is a match
        '''
        
        return any(t.any_match(urls) for t in self.url_testers)
    
    def lookup_matching(self, urls):
        '''
        Get objects representing match criteria (hosts, whole urls, etc) for
        given urls
        
        :param urls: an iterable containing urls
        :returns: items representing match criteria
        '''
        
        for tester in self.url_testers:
            for item in tester.lookup_matching(urls):
                yield item
                
    def filter_matching(self, urls):
        ''' Get those of given ruls that match listing criteria 
        (hosts, whole urls, etc.)
        
        :param urls: an iterable containing urls
        :returns: matching urls
        '''
        seen = set()
        urls = set(urls)
        for tester in self.url_testers:
            urls = urls - seen
            for u in tester.filter_matching(urls):
                if u not in seen:
                    seen.add(u)
                    yield u
                    
class UrlsAndLocations(object):
    ''' 
    An iterable returning given urls and
    their redirect urls
    '''
    
    @accepts_valid_urls
    def __init__(self, urls, redirect_resolver=RedirectUrlResolver()):
        ''' Constructor
        
        :param urls: a sequence of urls
        :param redirect resolver: an object that has get_redirect_urls method
        :raises ValueError: if the urls argument contains an invalid url
        '''
        
        self._redirect_resolver = redirect_resolver
        self._all_resolved = False
        
        self._initial_urls = set(urls)
        self._cached_urls = list(self._initial_urls)
        
    def __iter__(self):
        ''' Get iterator that returns all urls acquired so far (initial urls
        provided when creating the instance + redirect urls).
        
        If the url resolution was not completed, the methods
        performs further resolution when necessary
        '''
        
        if self._all_resolved:
            return iter(self._cached_urls)
        
        return chain(self._cached_urls, self._get_redirect_urls())
    
    def _get_redirect_urls(self):
        '''
        Get redirect urls for all initial urls
        
        Each value yielded by the function is cached, so it
        can be reused in next loop.
        
        :returns: redirect url value returned
        by _redirect_resolver for given initial url, if it
        was not cached before
        '''
        for url in self._initial_urls:
            for redirect_url in self._redirect_resolver.get_redirect_urls(url):
                if redirect_url not in self._cached_urls:
                    self._cached_urls.append(redirect_url)
                    yield redirect_url
        self._all_resolved = True
                
if __name__ == '__main__':
    pass