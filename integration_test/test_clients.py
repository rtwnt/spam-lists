# -*- coding: utf-8 -*-

import unittest

import tldextract
from validators import ipv6

from spam_lists.clients import spamhaus_zen, spamhaus_zen_classification,\
spamhaus_dbl, spamhaus_dbl_classification, surbl_multi,\
surbl_multi_classification
from spam_lists.structures import AddressListItem
from spam_lists.service_models import HpHosts

def ip_or_registered_domain(host):
    registered_domain = tldextract.extract(host).registered_domain
    return host if not registered_domain else registered_domain


def url_from_host(host):
    if ipv6(host):
        host = '['+host+']'
    return u'http://'+host


def get_expected_classification(classification, return_codes):
    return set(v for k, v in classification.items()
               if k in return_codes)
    

class UrlTesterClientTest(object):
    def test_any_match_for_not_listed(self):
        actual = self.tested_client.any_match(self.urls_without_listed)
        self.assertFalse(actual)    
    
    def test_any_match_for_listed(self):
        actual = self.tested_client.any_match(self.urls_with_listed)
        self.assertTrue(actual)
        
    def test_filter_matching_for_not_listed(self):
        actual = list(self.tested_client.filter_matching(self.urls_without_listed))
        self.assertItemsEqual([], actual)
        
    def test_filter_matching_for_listed(self):
        expected = [self.listed_url]
        actual = list(self.tested_client.filter_matching(self.urls_with_listed))
        self.assertItemsEqual(expected, actual)
        
    def test_lookup_matching_for_not_listed(self):
        actual = list(self.tested_client.lookup_matching(self.urls_without_listed))
        self.assertItemsEqual([], actual)
        
    def test_lookup_matching_for_listed(self):
        expected = [self.listed_item]
        actual = list(self.tested_client.lookup_matching(self.urls_with_listed))
        self.assertItemsEqual(expected, actual)


class HostListClientTest(UrlTesterClientTest):
    @classmethod
    def setUpClass(cls):
        cls.listed_url = url_from_host(cls.listed)
        cls.not_listed_url = url_from_host(cls.not_listed)
        cls.urls_with_listed = cls.not_listed_url, cls.listed_url
        cls.urls_without_listed = cls.not_listed_url, url_from_host(
                                                                    cls.not_listed_2
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
class SpamhausZenTest(HostListClientTest, unittest.TestCase):
    tested_client = spamhaus_zen
    listed = u'127.0.0.2'
    not_listed = u'127.0.0.1'
    not_listed_2 = u'8.8.8.8'
    classification = get_expected_classification(
                                                 spamhaus_zen_classification,
                                                 [2, 4, 10]
                                                 )
    

@unittest.skip(reason_to_skip)
class SpamhausDBLTest(HostListClientTest, unittest.TestCase):
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

class SURBLTest(HostListClientTest):
    tested_client = surbl_multi
    classification = get_expected_classification(
                                                 surbl_multi_classification,
                                                 [2, 4, 8, 16, 32, 64]
                                                 )

class SURBLMultiIPTest(SURBLTest, unittest.TestCase):
    listed = u'127.0.0.2'
    not_listed = u'127.0.0.1'
    not_listed_2 = u'8.8.8.8'
    
class SURBLMultiDomainTest(SURBLTest, unittest.TestCase):
    listed = 'surbl-org-permanent-test-point.com'
    not_listed = 'test.com'
    not_listed_2 = 'google.com'
    
hp_hosts = HpHosts('spam-lists-test-suite')


class HpHostsIPTest(HostListClientTest, unittest.TestCase):
    listed = u'174.36.207.146'
    not_listed = u'64.233.160.0'
    not_listed_2 = u'2001:ddd:ccc:123::55'
    tested_client = hp_hosts
    classification = set()


class HpHostsDomainTest(HostListClientTest, unittest.TestCase):
    listed = 'ecardmountain.com'
    not_listed = 'google.com'
    not_listed_2 = 'microsoft.com'
    tested_client = hp_hosts
    classification = set(['EMD'])


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()