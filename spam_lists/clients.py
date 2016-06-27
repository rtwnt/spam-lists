# -*- coding: utf-8 -*-

'''
This module contains classes of clients of online services that
can be queried to check if a given hostname, IP address or URL
is recognized as spam.

It also contains instances of those of the classes that represent clients
of services that can be ready for use without providing custom, user-specific
data, like API codes or application identifiers.
'''
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import zip, str, range, object
from dns import name
from dns.resolver import NXDOMAIN, query
from future.utils import raise_from
from requests import get, post
from requests.exceptions import HTTPError

from .exceptions import UnathorizedAPIKeyError, UnknownCodeError
from .host_list import HostList
from .structures import (
    AddressListItem, non_ipv6_host, ip_address, registered_domain,
    registered_domain_or_ip
)

from .validation import accepts_valid_urls


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


SPAMHAUS_XBL_CLASSIFICATION = (
    'CBL (3rd party exploits such as proxies, trojans, etc.)'
)
SPAMHAUS_PBL_CLASSIFICATION = (
    'End-user Non-MTA IP addresses set by ISP outbound mail policy'
)

SPAMHAUS_ZEN_CLASSIFICATION = {
    2: (
        'Direct UBE sources, spam operations & spam services'
    ),
    3: (
        'Direct snowshoe spam sources detected via automation'
    ),
    4: SPAMHAUS_XBL_CLASSIFICATION,
    5: SPAMHAUS_XBL_CLASSIFICATION,
    6: SPAMHAUS_XBL_CLASSIFICATION,
    7: SPAMHAUS_XBL_CLASSIFICATION,
    10: SPAMHAUS_PBL_CLASSIFICATION,
    11: SPAMHAUS_PBL_CLASSIFICATION
}

SPAMHAUS_ZEN = DNSBL(
    'spamhaus_zen',
    'zen.spamhaus.org',
    SPAMHAUS_ZEN_CLASSIFICATION,
    ip_address
)


SPAMHAUS_DBL_CLASSIFICATION = {
    2: 'spam domain',
    4: 'phishing domain',
    5: 'malware domain',
    6: 'botnet C&C domain',
    102: 'abused legit spam',
    103: 'abused spammed redirector domain',
    104: 'abused legit phishing',
    105: 'abused legit malware',
    106: 'abused legit botnet C&C',
}

SPAMHAUS_DBL = DNSBL(
    'spamhaus_dbl',
    'dbl.spamhaus.org',
    SPAMHAUS_DBL_CLASSIFICATION,
    registered_domain
)

SURBL_MULTI_CLASSIFICATION = {
    2: 'deprecated (previously SpamCop web sites)',
    4: 'listed on WS (will migrate to ABUSE on 1 May 2016)',
    8: 'phishing',
    16: 'malware',
    32: 'deprecated (previously AbuseButler web sites)',
    64: 'spam and other abuse sites: (previously jwSpamSpy + Prolocation'
        ' sites, SpamCop web sites, AbuseButler web sites)',
    128: 'Cracked sites'
}

SURBL_MULTI = BitmaskingDNSBL(
    'surbl_multi',
    'multi.surbl.org',
    SURBL_MULTI_CLASSIFICATION,
    registered_domain_or_ip
)
