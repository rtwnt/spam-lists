# -*- coding: utf-8 -*-

'''
This module contains classes of objects serving as clients
for remote and local spam listing services
'''
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import zip, str, range, object
from dns import name
from dns.resolver import NXDOMAIN, query
from future.moves.urllib.parse import urlparse
from future.utils import raise_from
from requests import get, post
from requests.exceptions import HTTPError

from .exceptions import UnathorizedAPIKeyError, UnknownCodeError, \
    InvalidHostError
from .structures import AddressListItem, hostname_or_ip, non_ipv6_host
from .validation import accepts_valid_urls, accepts_valid_host


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
        result = self._get_match_and_classification(
            host_object
        )
        host_item, classification = result
        if host_item is not None:
            return AddressListItem(
                host_item.to_unicode(),
                self,
                classification
            )
        return None

    @accepts_valid_urls
    def any_match(self, urls):
        ''' Check if any of given urls has a listed host

        :param urls: an iterable containing urls
        :returns: True if any host is listed
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        return any(urlparse(u).hostname in self for u in urls)

    @accepts_valid_urls
    def lookup_matching(self, urls):
        '''Get objects representing hosts in given urls
        that match listed hosts

        :param urls: an iterable containing urls
        :returns: items representing hosts matching the listed ones
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        hosts = (urlparse(u).hostname for u in urls)
        for val in hosts:
            item = self.lookup(val)
            if item is not None:
                yield item

    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get urls with hosts matching listed ones

        :param urls: an iterable containing url addresses to filter
        :returns: a list containing matching urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        def is_match(url):
            return urlparse(url).hostname in self
        return (u for u in urls if is_match(u))


class DNSBL(HostList):
    ''' Represents a DNSBL service '''
    def __init__(
            self,
            identifier,
            query_suffix,
            classification_map,
            host_factory):
        ''' Create new DNSBL object

        :param identifier: a value designating DNSBL service provider:
        its name or url address.
        :param query_suffix: a suffix added to DNSBL query address
        :param classification_map: item classes associated with
        DNSBL query return codes
        :param host_factory: a callable object that returns an object
         representing host and providing method for getting a relative
         domain pertaining to it.
        '''
        self._identifier = identifier
        self._query_suffix = name.from_text(query_suffix)
        self._classification_map = classification_map
        self._host_factory = host_factory
        super(DNSBL, self).__init__(host_factory)

    def _query(self, host_object):
        ''' Query DNSBL service for given value

        :param host_object: an object representing host,
         created by _host_factory
        :returns: an instance of dns.resolver.Answer for
         given value, if it is listed. Otherwise, it returns None
        '''
        host_to_query = host_object.relative_domain
        query_name = host_to_query.derelativize(self._query_suffix)
        try:
            return query(query_name)
        except NXDOMAIN:
            return None

    def __str__(self):
        return str(self._identifier)

    def _contains(self, host_object):
        return bool(self._query(host_object))

    def _get_entry_classification(self, code):
        return [self._classification_map[code]]

    def _get_match_and_classification(self, host_object):
        answers = self._query(host_object)
        if answers is None:
            return None, None
        try:
            classification = set()
            for answer in answers:
                last_octet = answer.to_text().split('.')[-1]
                classes = self._get_entry_classification(int(last_octet))
                classification.update(classes)
            return host_object, classification
        except KeyError as ex:
            msg_tpl = "The code '{}' has no corresponding classification value"
            msg = msg_tpl.format(ex.args[0])
            raise_from(UnknownCodeError(msg), ex)


def get_powers_of_2(_sum):
    ''' Get powers of with a given sum

    This function transforms given integer to a binary string.
    A reversed value limited to digits of binary number is extracted
    from it, and each of its characters is enumerated.

    Each digit is tested for not being 0. If the test passes, the index
    associated with the digit is used as an exponent to get the next
    value in the sequence to be returned.

    :param _sum: a sum of all elements of the sequence to be returned
    :returns: a list of powers of two whose sum is given
    '''
    return [2**y for y, x in enumerate(bin(_sum)[:1:-1]) if int(x)]


class BitmaskingDNSBL(DNSBL):
    ''' A class representing DNSBL services mapping listed items to
    sums of classification codes

    Each classification code is a power of two.

    '''
    def _get_entry_classification(self, code):
        codes = get_powers_of_2(code)
        return [cl for c in codes for cl
                in DNSBL._get_entry_classification(self, c)]


class HpHosts(HostList):
    ''' hpHosts client '''
    identifier = ' http://www.hosts-file.net/'
    _NOT_LISTED = 'Not Listed'

    def __init__(self, client_name):
        '''Constructor

        :param client_name: name of client using the service
        '''
        self.app_id = client_name
        super(HpHosts, self).__init__(non_ipv6_host)

    def _query(self, host_object, classification=False):
        ''' Query the client for data of given host

        :param host_object: an object representing a host value
        :param classification: if True: hpHosts is queried also
         for classification for given host, if listed
        :returns: content of response to GET request to hpHosts
         for data on the given host
        '''
        template = 'http://verify.hosts-file.net/?v={}&s={}'
        url = template.format(self.app_id, host_object.to_unicode())
        url = url + '&class=true' if classification else url
        return get(url).text

    def _contains(self, host_object):
        return self._NOT_LISTED not in self._query(host_object)

    def _get_match_and_classification(self, host_object):
        data = self._query(host_object, True)
        if self._NOT_LISTED in data:
            return None, None
        elements = data.split(',')
        classification = set(elements[1:])
        return host_object, classification


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
            template = (
                'https://sb-ssl.google.com/safebrowsing/api/lookup'
                '?client={0}&key={1}&appver={2}&pver={3}'
            )
            self._request_address_val = template.format(
                self.client_name,
                self.api_key,
                self.app_version,
                self.protocol_version
            )
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
        except HTTPError as error:
            if response.status_code == 401:
                msg = 'The API key is not authorized'
                raise_from(UnathorizedAPIKeyError(msg), error)
            else:
                raise
        return response

    def _query(self, urls):
        ''' Test urls for being listed by the service

        :param urls: a sequence of urls  to be tested
        :returns: a tuple containing chunk of urls and a response pertaining
          to them if the code of response was 200, which means at least one
          of the queried URLs is matched in either the phishing, malware,
           or unwanted software lists.
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

    def _get_match_and_classification(self, urls):
        ''' Get classification for all matching urls

        :param urls: a sequence of urls to test
        :return: a tuple containing matching url and classification
        string pertaining to it
        '''
        for url_list, response in self._query(urls):
            classification_set = response.text.splitlines()
            for url, _class in zip(url_list, classification_set):
                if _class != 'ok':
                    yield url, _class

    @accepts_valid_urls
    def lookup_matching(self, urls):
        ''' Get items for all listed urls

        :param urls: a sequence of urls to be tested
        :returns: objects representing listed urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        for url, _class in self._get_match_and_classification(urls):
            classification = set(_class.split(','))
            yield AddressListItem(url, self, classification)

    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get all listed urls

        :param urls: a sequence of urls to be tested
        :returns: spam urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        for url, _ in self._get_match_and_classification(urls):
            yield url


class BaseHostCollection(HostList):
    ''' Base class for containers storing ip addresses
    and domain names
    '''
    def __init__(self, identifier, classification, hosts=None):
        ''' Create new instance

        :param identifier: an identifier of this instance of host collection
        :param classification: a list or tuple containing strings representing
        types of items, assigned to each element of the collection
        :param hosts: an object storing ip adresses and hostnames. It
        must be iterable and have .add and .remove methods.
        '''
        self.identifier = identifier
        self.classification = set(classification)
        self.hosts = hosts if hosts is not None else []
        super(BaseHostCollection, self).__init__(hostname_or_ip)

    def __len__(self):
        return len(self.hosts)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.__class__(
                self.identifier,
                self.classification,
                self.hosts[index]
            )
        return self._host_factory(self.hosts[index])

    def _contains(self, host_object):
        match = self._get_match(host_object)
        return match is not None

    def _get_match_and_classification(self, host_object):
        match = self._get_match(host_object)
        _class = None if match is None else self.classification
        return match, _class

    def add(self, host_value):
        ''' Add the given value to collection

        :param host: an ip address or a hostname
        :raises InvalidHostError: raised when the given value
        is not a valid ip address nor a hostname
        '''
        host_obj = self._host_factory(host_value)
        if self._get_match(host_obj) is not None:
            return
        self._add_new(host_obj)


class HostCollection(BaseHostCollection):
    ''' Provides a container for ip addresses and domain names.

    May be used as a local whitelist or blacklist.
    '''
    def _get_match(self, host_object):
        for val in self:
            if host_object.is_match(val):
                return val

    def _add_new(self, host_obj):
        ''' Add a new host to the collection

        A new host is defined as a value not currently listed
        (in case of both hostnames and ip) or not currently
        covered by another value (in case of hostnames, which
        could be covered by their parent domain).

        Before a new hostname can be added, all its subdomains
        already present in the collection must be removed.

        :param host_obj: an object representing value to be added.
        It is assumed that, during execution of this method,
        the value to be added is not currently listed.
        '''
        for i, listed_obj in enumerate(self):
            if listed_obj.is_subdomain(host_obj):
                self.hosts.pop(i)
        self.hosts.append(host_obj.to_unicode())
