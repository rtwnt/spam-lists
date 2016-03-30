# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os.path

from builtins import object
import tldextract
from validators import ipv6

from spam_lists.clients import spamhaus_zen, spamhaus_zen_classification, \
spamhaus_dbl, spamhaus_dbl_classification, surbl_multi, \
surbl_multi_classification
from spam_lists.service_models import HpHosts, GoogleSafeBrowsing
from spam_lists.structures import AddressListItem
from test.compat import unittest


def ip_or_registered_domain(host):
    registered_domain = tldextract.extract(host).registered_domain
    return host if not registered_domain else registered_domain


def url_from_host(host):
    if ipv6(host):
        host = '['+host+']'
    return 'http://'+host


def get_expected_classification(classification, return_codes):
    return set(v for k, v in list(classification.items()) if k in return_codes)
    

class UrlTesterClientTestMixin(object):
    def test_any_match_for_not_listed(self):
        actual = self.tested_client.any_match(self.urls_without_listed)
        self.assertFalse(actual)    
    
    def test_any_match_for_listed(self):
        actual = self.tested_client.any_match(self.urls_with_listed)
        self.assertTrue(actual)
        
    def test_filter_matching_for_not_listed(self):
        generator = self.tested_client.filter_matching(
                                                       self.urls_without_listed
                                                       )
        actual = list(generator)
        self.assertCountEqual([], actual)
        
    def test_filter_matching_for_listed(self):
        expected = [self.listed_url]
        actual = list(self.tested_client.filter_matching(self.urls_with_listed))
        self.assertCountEqual(expected, actual)
        
    def test_lookup_matching_for_not_listed(self):
        generator = self.tested_client.lookup_matching(
                                                       self.urls_without_listed
                                                       )
        actual = list(generator)
        self.assertCountEqual([], actual)
        
    def test_lookup_matching_for_listed(self):
        expected = [self.listed_item]
        actual = list(self.tested_client.lookup_matching(self.urls_with_listed))
        self.assertCountEqual(expected, actual)


class HostListClientTestMixin(UrlTesterClientTestMixin):
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

reason_to_skip = (
                  'These tests are expected to fail frequently for users of'
                  ' public DNS resolvers:'
                  ' https://www.spamhaus.org/faq/section/DNSBL%20Usage#261'
                  )


@unittest.skip(reason_to_skip)
class SpamhausZenTest(HostListClientTestMixin, unittest.TestCase):
    tested_client = spamhaus_zen
    listed = '127.0.0.2'
    not_listed = '127.0.0.1'
    not_listed_2 = '8.8.8.8'
    classification = get_expected_classification(
                                                 spamhaus_zen_classification,
                                                 [2, 4, 10]
                                                 )
    

@unittest.skip(reason_to_skip)
class SpamhausDBLTest(HostListClientTestMixin, unittest.TestCase):
    tested_client = spamhaus_dbl
    listed = 'dbltest.com'
    not_listed = 'example.com'
    not_listed_2 = 'google.com'
    classification = get_expected_classification(
                                                 spamhaus_dbl_classification,
                                                 [2]
                                                 )


expected_surbl_classification = get_expected_classification(
                                                            surbl_multi_classification,
                                                            [2, 126]
                                                            )

class SURBLTest(HostListClientTestMixin):
    tested_client = surbl_multi
    classification = get_expected_classification(
                                                 surbl_multi_classification,
                                                 [2, 4, 8, 16, 32, 64]
                                                 )

class SURBLMultiIPTest(SURBLTest, unittest.TestCase):
    listed = '127.0.0.2'
    not_listed = '127.0.0.1'
    not_listed_2 = '8.8.8.8'
    
class SURBLMultiDomainTest(SURBLTest, unittest.TestCase):
    listed = 'surbl-org-permanent-test-point.com'
    not_listed = 'test.com'
    not_listed_2 = 'google.com'
    
hp_hosts = HpHosts('spam-lists-test-suite')


class HpHostsIPTest(HostListClientTestMixin, unittest.TestCase):
    listed = '174.36.207.146'
    not_listed = '64.233.160.0'
    not_listed_2 = '2001:ddd:ccc:123::55'
    tested_client = hp_hosts
    classification = set()


class HpHostsDomainTest(HostListClientTestMixin, unittest.TestCase):
    listed = 'ecardmountain.com'
    not_listed = 'google.com'
    not_listed_2 = 'microsoft.com'
    tested_client = hp_hosts
    classification = set(['EMD'])
    
gsb_api_key_file = os.path.join(
                                os.path.dirname(__file__), 
                                'google_safe_browsing_api_key.txt'
                                )
try:
    with open(gsb_api_key_file, 'r') as key_file:
        safe_browsing_api_key = key_file.readline().rstrip()
        
except IOError:
    safe_browsing_api_key = None

reason_to_skip_gsb_test = (
                           'No api key provided. Provide the key in'
                           ' file: {}'.format(gsb_api_key_file)
                           )

@unittest.skipIf(not safe_browsing_api_key, reason_to_skip_gsb_test)
class GoogleSafeBrowsingTest(UrlTesterClientTestMixin, unittest.TestCase):
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
                                       safe_browsing_api_key
                                       )
        
        cls.listed_item = AddressListItem(
                                    cls.listed_url,
                                    cls.tested_client,
                                    set(['malware'])
                                    )
    


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()