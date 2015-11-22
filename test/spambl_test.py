#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, DNSBLService, BaseDNSBLClient, 
                     DNSBLContentError, DNSBLTypeError, GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection)
from mock import Mock, patch
from ipaddress import ip_address as IP
from itertools import cycle, izip
from __builtin__ import classmethod

from urlparse import urlparse, parse_qs
from requests import HTTPError
from dns import name
import re

class HpHostsTest(unittest.TestCase):
    ''' Tests HpHosts methods '''
    
    classification = '[TEST]'
    hosts_listed = 't1.pl', 't2.com', 't3.com.pl', '255.255.0.1', '2001:DB8:abc:123::42'
    hosts_not_listed = 'at.pl', 'lorem.com', 'impsum.com', '200.170.0.1'
    
    @classmethod
    def setUpClass(cls):
        cls.hp_hosts = HpHosts('spambl_test_suite')
        cls.setUpMockedGet()
        
    @classmethod
    def get(cls, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        content = 'Not listed'
        
        if params['s'][0] in cls.hosts_listed:
            c = cls.classification if 'class' in params else ''
            content = ','.join(('Listed', c))
            
        response = Mock(spec=['content'])
        response.content = content
        
        return response
        
    @classmethod
    def setUpMockedGet(cls):
        cls.patcher = patch('spambl.get')
        cls.mocked_get = cls.patcher.start()
        cls.mocked_get.side_effect = cls.get
    
    def testContains(self):
        ''' Test __contains__ method '''
        
        for host in self.hosts_listed:
            self.assertTrue(host in self.hp_hosts)
        
        for host in self.hosts_not_listed:
            self.assertFalse(host in self.hp_hosts)
                
    def testLookup(self):
        ''' Test lookup method'''
        
        for host in self.hosts_listed:
            self.assertEqual(self.hp_hosts.lookup(host).host, host)
            
        for host in self.hosts_not_listed:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()

class DNSBLServiceTest(unittest.TestCase):
    
    code_item_class = {1: 'Class #1', 2: 'Class #2'}
    hosts_listed = 't1.pl', 't2.com', 't3.com.pl'
    hosts_not_listed = 'lorem.pl', 'ipsum.com'
    test_suffix = 'test.suffix'
    
    @classmethod
    def setUpClass(cls):
        
        cls.dnsbl_service = DNSBLService('test_service', 'test.suffix', cls.code_item_class, True, True)
        
        cls.setUpMockedQuery()
        
    @classmethod
    def query(cls, query_name):
        host = re.sub(r'.'+cls.test_suffix+'$', '', query_name)
        
        if host in cls.host_return_codes:
            return_code = cls.host_return_codes[host]
            
            answer = Mock()
            answer.to_text.return_value = '127.0.0.%d' % return_code
            return [answer]
        
        raise NXDOMAIN('test NXDOMAIN exception')
    
    @classmethod
    def setUpMockedQuery(cls):
        cls.patcher = patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
        return_codes = cycle(cls.code_item_class.keys())
        
        cls.host_return_codes = {n: next(return_codes) for n in cls.hosts_listed}
        
        cls.mocked_query.side_effect = cls.query
        
    def testGetClassification(self):
        ''' Test get_classification method of DNSBL instance '''
        
        for key, value in self.code_item_class.iteritems():
            actual = self.dnsbl_service.get_classification(key)
            self.assertEqual(actual, value)
        
        self.assertRaises(UnknownCodeError, self.dnsbl_service.get_classification, 4)
        
    def testQuery(self):
        ''' Test query method
        
        The method is tested against a set of host values, which are expected to be recognized
        as spam or not, depending on configuration of side effect of mocked query function.
        
        :param mocked_query: a patched instance of query function
        '''
        
        for host in self.hosts_listed:
            
            self.assertEqual(self.dnsbl_service.query(host), self.host_return_codes[host])
        
        for host in self.hosts_not_listed:
            self.assertEqual(self.dnsbl_service.query(host), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
class BaseDNSBLClientTest(unittest.TestCase):
    
    test_lists_attr_name = 'test_lists_attr'
    
    def setUp(self):
        self.base_dnsbl_client = BaseDNSBLClient()
        
        self.base_dnsbl_client._required_content_in = lambda e: getattr(e, self.test_lists_attr_name) == True
        
    def getDNSBLMock(self, required_property = True, query_return_value = None):
        ''' Create a Mock instance for dnsbl service object
        
        :param required_property: boolean value set to value of the required property
        to which BaseDNSBLClient._LISTS_ATTR_NAME is set
        :returns: an instance of Mock with all necessary attributes
        '''
        
        dnsbl = Mock()
        setattr(dnsbl, self.test_lists_attr_name, bool(required_property))
        dnsbl.query.return_value = query_return_value
        
        return dnsbl
        
    def testAddDNSBL(self):
        ''' Test add_dnsbl method '''
        
        valid_dnsbl = self.getDNSBLMock()
        self.base_dnsbl_client.add_dnsbl(valid_dnsbl)
        self.assertEqual(self.base_dnsbl_client.dnsbl_services[0], valid_dnsbl)
         
        invalid_dnsbl = self.getDNSBLMock(False)
        self.assertRaises(DNSBLContentError, self.base_dnsbl_client.add_dnsbl, invalid_dnsbl)
        
        no_dnsbl = Mock(spec=[])
        self.assertRaises(DNSBLTypeError, self.base_dnsbl_client.add_dnsbl, no_dnsbl)
        
    def testContains(self):
        ''' Test __contains__ method '''
        return_value = 3
        test_host = 'test'
        
        dnsbl = self.getDNSBLMock(query_return_value = return_value)
        self.base_dnsbl_client.dnsbl_services.append(dnsbl)
        
        self.assertTrue(test_host in self.base_dnsbl_client)
        
        dnsbl.query.return_value = None
        
        self.assertEqual(next(self.base_dnsbl_client._get_item_data(test_host)), ())
        self.assertFalse(test_host in self.base_dnsbl_client)
        
    def makeAssertionsForLookup(self, return_values):
        ''' Test lookup method using dnsbl mocks
        
        The method tests type of returned value, return codes and sources assigned to each item.
        
        :param return_values: a sequence of integers representing return codes of each 
        dnsbl service in response to test host value
        '''
        
        dnsbls = [self.getDNSBLMock(query_return_value = r) for r in return_values]
        
        self.base_dnsbl_client.dnsbl_services = dnsbls
        result = self.base_dnsbl_client.lookup('test')
        
        self.assertIsInstance(result, tuple)
        
        actual = [o._return_code for o in result]
        expected = [r for r in return_values if r]
        
        self.assertEqual(actual, expected)
        
        actual = [o.source for o in result]
        expected = [d for d, n in izip(dnsbls, return_values) if n]
        
        self.assertEqual(actual, expected)
        
    def testLookup(self):
        ''' Test lookup method '''
        
        return_value_sets = (1, 2, None, 3, None), (1,), (None,), (1, 2, 3), (None, None, None)
        
        for _set in return_value_sets:
            self.makeAssertionsForLookup(_set)
        
class GoogleSafeBrowsingTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.valid_key = 'test.key'
        
        cls.google_safe_browsing = GoogleSafeBrowsing('test_client', '0.1', cls.valid_key)
        cls.invalid_key_gbs = GoogleSafeBrowsing('test_client', '0.1', 'invalid.key')
        
        cls.setUpUrls()
        cls.setUpPost()
        
    @classmethod    
    def setUpUrls(cls):
        hosts = 't1.pl', 't2.com', 't3.com.pl', IP(u'255.255.0.1'), IP(u'2001:DB8:abc:123::42')
        classifications = 'phishing', 'malware', 'unwanted'
        classification_ranges = cycle(range(1, len(classifications)))
        
        cls.spam_urls_classification = dict()
        
        for n, k in izip(hosts, classification_ranges):
            cls.spam_urls_classification['http://{}'.format(n)] = ','.join(classifications[:k])
            
        cls.non_spam_urls = tuple('http://{}'.format(n) for n in ('nonspam1.com', 'nonspam2.com'))
        cls.all_urls = tuple(cls.spam_urls_classification.keys()) + cls.non_spam_urls
        
    @classmethod
    def setUpPost(cls):
        
        cls.patcher = patch('spambl.post')
        cls.mocked_post = cls.patcher.start()        
        cls.mocked_post.side_effect = cls.post
        
    @classmethod
    def post(cls, request_address, request_body):
        urls = request_body.splitlines()[1:]
        
        results = []
        for u in urls:
            a = cls.spam_urls_classification[u] if u in cls.spam_urls_classification else 'ok'
            results.append(a)
            
        return cls.getPostResponse(request_address, results)
    
    @classmethod
    def getPostResponse(cls, request_address, results):
        
        response = Mock(spec=['content', 'raise_for_status', 'status_code'])
        
        response.status_code = 204
        
        if any((n != 'ok' for n in results)):
            response.status_code = 200
            response.content = '\n'.join(results)
            
        parsed_url = urlparse(request_address)
        params = parse_qs(parsed_url.query)
        
        if params['key'][0] != cls.valid_key:
            response.status_code = 401
            response.raise_for_status.side_effect = HTTPError('Test http error')
            
        return response
        
        
    def testContainsAny(self):
        
        url_result_1 = self.spam_urls_classification.keys(), True
        url_result_2 = self.all_urls, True
        url_result_3 = self.non_spam_urls, False
         
        for urls, expected_result in (url_result_1, url_result_2, url_result_3):
            actual_result = self.google_safe_browsing.contains_any(urls)
            
            self.assertEqual(actual_result, expected_result)
            self.assertRaises(UnathorizedAPIKeyError, self.invalid_key_gbs.contains_any, urls)
            
    def testLookup(self):
        
        results_1 = self.google_safe_browsing.lookup(self.spam_urls_classification.keys())
        
        for i, item in enumerate(results_1):
            self.assertEqual(item.host, self.spam_urls_classification.keys()[i])
            self.assertEqual(item.source, self.google_safe_browsing)
            self.assertEqual(item.classification, self.spam_urls_classification[item.host].split(','))
            
        results_2 = self.google_safe_browsing.lookup(self.all_urls)
        
        for i, item in enumerate(results_2):
            self.assertEqual(item.host, self.spam_urls_classification.keys()[i])
            self.assertEqual(item.source, self.google_safe_browsing)
            self.assertEqual(item.classification, self.spam_urls_classification[item.host].split(','))
        
        results_3 = self.google_safe_browsing.lookup(self.non_spam_urls)
        
        self.assertEqual(results_3, tuple())

    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        
class HostCollectionTest(unittest.TestCase):
    
    def setUp(self):
        self.host_collection = HostCollection()
        self.hostname_strings = 'google.com', 'test1.pl'
        self.ip_address_strings = u'127.0.0.1', u'2001:DB8:abc:123::42'
        
        self.not_listed = 'a.com', u'255.0.0.1'
        self.all_host_strings = self.hostname_strings + self.ip_address_strings
        
    def testAddHostnames(self):
        for h in self.hostname_strings:
            self.host_collection.add(h)
            
        self.assertItemsEqual(self.host_collection.hostnames, {name.from_text(h) for h in self.hostname_strings})
            
    def testAddIps(self):
        for ip in self.ip_address_strings:
            self.host_collection.add(ip)
            
        self.assertItemsEqual(self.host_collection.ip_addresses, {IP(ip) for ip in self.ip_address_strings})
        
    def testAddInvalidHost(self):
        test_host = '-k.'
        
        self.assertRaises(ValueError, self.host_collection.add, test_host)
        
    def testContainsMatch(self):
        
        for host in self.all_host_strings:
            self.host_collection.add(host)
            
        matching = HostCollection(self.all_host_strings+self.not_listed)
        
        self.assertTrue(self.host_collection.contains_match(matching))
        
        non_empty_not_matching = HostCollection(self.not_listed)
        
        self.assertFalse(self.host_collection.contains_match(non_empty_not_matching))
        
        empty = HostCollection()
        
        self.assertFalse(self.host_collection.contains_match(empty))
        
    def testDifference(self):
        
        for host in self.all_host_strings:
            self.host_collection.add(host)
            
        matching = HostCollection(self.all_host_strings+self.not_listed)
        non_empty_not_matching = HostCollection(self.not_listed)
        empty = HostCollection()
        
        ''' matching - set up '''
        actual = matching.difference(self.host_collection)
        expected = non_empty_not_matching
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
        '''set up - matching'''
        actual = self.host_collection.difference(matching)
        expected = empty
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
        ''' set up - empty '''
        
        actual = self.host_collection.difference(empty)
        expected = self.host_collection
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
        
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()