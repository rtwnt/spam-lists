# -*- coding: utf-8 -*-

import unittest

import tldextract

from spam_lists.structures import AddressListItem

def ip_or_registered_domain(host):
    registered_domain = tldextract.extract(host).registered_domain
    return host if not registered_domain else registered_domain


def url_from_host(host):
    return u'http://'+host


def get_expected_classification(classification, return_codes):
    return set(v for k, v in classification.items()
               if k in return_codes)
    

class ClientTest(object):
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


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()