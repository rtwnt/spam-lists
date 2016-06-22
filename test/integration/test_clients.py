# -*- coding: utf-8 -*-
'''
This module contains integration tests for supported
third party services

The purpose of the tests is to signal changes in the services that
require changes in the implementation of their clients.
'''
from __future__ import unicode_literals

import os.path

from builtins import object  # pylint: disable=redefined-builtin
import tldextract
from validators import ipv6

from spam_lists.clients import (
    SPAMHAUS_ZEN, SPAMHAUS_ZEN_CLASSIFICATION, SPAMHAUS_DBL,
    SPAMHAUS_DBL_CLASSIFICATION, SURBL_MULTI, SURBL_MULTI_CLASSIFICATION
)
from spam_lists.clients import HpHosts, GoogleSafeBrowsing
from spam_lists.structures import AddressListItem
from test.compat import unittest


def ip_or_registered_domain(host):
    registered_domain = tldextract.extract(host).registered_domain
    return host if not registered_domain else registered_domain


def url_from_host(host):
    if ipv6(host):
        host = '['+host+']'
    return 'http://'+host


def get_classification(classification, return_codes):
    return set(v for k, v in list(classification.items()) if k in return_codes)


class UrlTesterClientTestMixin(object):
    '''  A class containing integration test methods for
    url tester clients

    :var tested_client: an instance of client to be tested
    :var urls_without_listed: urls without values listed by the service
    to be queried
    :var urls_with_listed: urls with values listed by the service
    to be queried
    :var listed_url: a url listed (or: with a host listed) by the service
    to be queried
    :var listed_item: an instance of AddressListItem representing
    an item listed by the service to be queried
    '''
    def test_any_match_for_not_listed(self):
        actual = self.tested_client.any_match(self.urls_without_listed)
        self.assertFalse(actual)

    def test_any_match_for_listed(self):
        actual = self.tested_client.any_match(self.urls_with_listed)
        self.assertTrue(actual)

    def test_filter_matching_not_listed(self):
        generator = self.tested_client.filter_matching(
            self.urls_without_listed
        )
        actual = list(generator)
        self.assertCountEqual([], actual)

    def test_filter_matching_for_listed(self):
        expected = [self.listed_url]
        filter_matching = self.tested_client.filter_matching
        actual = list(filter_matching(self.urls_with_listed))
        self.assertCountEqual(expected, actual)

    def test_lookup_matching_not_listed(self):
        generator = self.tested_client.lookup_matching(
            self.urls_without_listed
        )
        actual = list(generator)
        self.assertCountEqual([], actual)

    def test_lookup_matching_for_listed(self):
        expected = [self.listed_item]
        lookup_matching = self.tested_client.lookup_matching
        actual = list(lookup_matching(self.urls_with_listed))
        self.assertCountEqual(expected, actual)


class HostListClientTestMixin(UrlTesterClientTestMixin):
    '''  A class containing integration test methods for
    host list clients

    :var listed: an item listed by a service to be queried
    :var not_listed: an item not listed by a service to be queried
    :var tested_client: an instance of client to be tested
    :var urls_without_listed: urls without values listed by the service
    to be queried
    :var urls_with_listed: urls with values listed by the service
    to be queried
    :var listed_url: a url listed (or: with a host listed) by the service
    to be queried
    :var listed_item: an instance of AddressListItem representing
    an item listed by the service to be queried
    '''
    @classmethod
    def setUpClass(cls):
        cls.listed_url = url_from_host(cls.listed)
        cls.not_listed_url = url_from_host(cls.not_listed)
        cls.urls_with_listed = cls.not_listed_url, cls.listed_url
        cls.urls_without_listed = (
            cls.not_listed_url,
            url_from_host(cls.not_listed_2)
        )
        cls.listed_item = AddressListItem(
            ip_or_registered_domain(cls.listed),
            cls.tested_client,
            cls.classification
        )

    def test__contains__for_not_listed(self):
        actual = self.not_listed in self.tested_client
        self.assertFalse(actual)

    def test_contains_for_listed(self):
        actual = self.listed in self.tested_client
        self.assertTrue(actual)

    def test_lookup_for_not_listed(self):
        actual = self.tested_client.lookup(self.not_listed)
        self.assertIsNone(actual)

    def test_lookup_for_listed(self):
        actual = self.tested_client.lookup(self.listed)
        self.assertEqual(self.listed_item, actual)


REASON_TO_SKIP = (
    'These tests are expected to fail frequently for users of public'
    ' DNS resolvers:'
    ' https://www.spamhaus.org/faq/section/DNSBL%20Usage#261'
)


# @unittest.skip(REASON_TO_SKIP)
class SpamhausZenTest(HostListClientTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    tested_client = SPAMHAUS_ZEN
    listed = '127.0.0.2'
    not_listed = '127.0.0.1'
    not_listed_2 = '8.8.8.8'
    classification = get_classification(
        SPAMHAUS_ZEN_CLASSIFICATION,
        [2, 4, 10]
    )


# @unittest.skip(REASON_TO_SKIP)
class SpamhausDBLTest(HostListClientTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    tested_client = SPAMHAUS_DBL
    listed = 'dbltest.com'
    not_listed = 'example.com'
    not_listed_2 = 'google.com'
    classification = get_classification(
        SPAMHAUS_DBL_CLASSIFICATION,
        [2]
    )


class SURBLTest(HostListClientTestMixin):
    tested_client = SURBL_MULTI
    classification = get_classification(
        SURBL_MULTI_CLASSIFICATION,
        [2, 4, 8, 16, 32, 64]
    )


class SURBLMultiIPTest(SURBLTest, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    listed = '127.0.0.2'
    not_listed = '127.0.0.1'
    not_listed_2 = '8.8.8.8'


class SURBLMultiDomainTest(SURBLTest, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    listed = 'surbl-org-permanent-test-point.com'
    not_listed = 'test.com'
    not_listed_2 = 'google.com'

HP_HOSTS = HpHosts('spam-lists-test-suite')


class HpHostsIPTest(HostListClientTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    listed = '174.36.207.146'
    not_listed = '64.233.160.0'
    not_listed_2 = '2001:ddd:ccc:123::55'
    tested_client = HP_HOSTS
    classification = set()


class HpHostsDomainTest(HostListClientTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    listed = 'ecardmountain.com'
    not_listed = 'google.com'
    not_listed_2 = 'microsoft.com'
    tested_client = HP_HOSTS
    classification = set(['EMD'])


GSB_API_KEY_FILE = os.path.join(
    os.path.dirname(__file__),
    'google_safe_browsing_api_key.txt'
)
try:
    with open(GSB_API_KEY_FILE, 'r') as key_file:
        SAFE_BROWSING_API_KEY = key_file.readline().rstrip()
except IOError:
    SAFE_BROWSING_API_KEY = None


REASON_TO_SKIP_GSB_TEST = (
    'No api key provided. Provide the key in file: {}'.format(GSB_API_KEY_FILE)
    )


@unittest.skipIf(not SAFE_BROWSING_API_KEY, REASON_TO_SKIP_GSB_TEST)
class GoogleSafeBrowsingTest(UrlTesterClientTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    listed_url = 'http://www.gumblar.cn/'
    not_listed_url = 'http://www.google.com/'
    not_listed_url_2 = 'https://github.com/'
    urls_with_listed = not_listed_url, listed_url
    urls_without_listed = not_listed_url, not_listed_url_2

    @classmethod
    def setUpClass(cls):
        cls.tested_client = GoogleSafeBrowsing(
            'spam-lists-test-suite',
            '0.5',
            SAFE_BROWSING_API_KEY
        )
        cls.listed_item = AddressListItem(
            cls.listed_url,
            cls.tested_client,
            set(['malware'])
        )


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
