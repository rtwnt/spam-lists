# -*- coding: utf-8 -*-

'''
This module contains classes of objects serving as clients
for remote and local spam listing services
'''

from sys import exc_info
from urlparse import urlparse
from itertools import izip

import validators
from requests import get, post
from requests.exceptions import HTTPError
from dns import name
from dns.resolver import NXDOMAIN, query

from .validation import accepts_valid_urls, accepts_valid_host
from .structures import AddressListItem, host
from .exceptions import UnathorizedAPIKeyError, UnknownCodeError, InvalidHostError


class HostList(object):
    ''' A class of clients for local or remote host list services '''
    
    def __init__(self, host_factory):
        ''' Constructor
        
        :param host_factory: a function responsible for
        creating valid host objects. It may raise InvalidHostError
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
        
    @accepts_valid_host
    def __contains__(self, host_value):
        ''' Check if given host value is listed by the service
        
        :param host_value: a string representing a valid host
        :returns: True if the host is listed
        :raises InvalidHostError: if the argument is not a valid host string
        '''
        try:
            host_object = self._host_factory(host_value)
            
        except InvalidHostError:
            return False
        
        return self._contains(host_object)
    
    @accepts_valid_host
    def lookup(self, host_value):
        ''' Get an object representing a host value
        matched by this host
        
        :param host_value: a value of the host of a type
        that can be listed by the service
        :returns: an instance of AddressListItem representing
        a matched value
        :raises InvalidHostError: if the argument is not a valid host string
        '''
        try:
            host_object = self._host_factory(host_value)
            
        except InvalidHostError:
            return None
        
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
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        
        return any(urlparse(u).hostname in self for u in urls)
    
    @accepts_valid_urls
    def lookup_matching(self, urls):
        '''
        Get objects representing hosts in given urls that match listed hosts
        
        :param urls: an iterable containing urls
        :returns: items representing hosts matching the listed ones
        :raises InvalidURLError: if there are any invalid urls in the sequence
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
        :raises InvalidURLError: if there are any invalid urls in the sequence
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
        :raises InvalidURLError: if there are any invalid urls in the sequence
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
        :returns: objects representing listed urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        
        for url, _class in self._get_classification_per_matching(urls):
            classification = tuple(_class.split(','))
            yield AddressListItem(url, self, classification)
                    
    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get all listed urls
        
        :param urls: a sequence of urls to be tested
        :returns: spam urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
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
        :raises InvalidHostError: raised when the given value is not a valid ip address nor a hostname
        '''
        host_obj = self._host_factory(host_value)
        
        for h in self.hosts:
            if host_obj.is_subdomain() or host_obj == h:
                return
            
            if h.is_subdomain(host_obj):
                self.hosts.remove(h)
                break

        self.hosts.add(host_obj)