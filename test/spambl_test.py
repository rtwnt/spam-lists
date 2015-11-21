#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, DNSBLService, BaseDNSBLClient, 
                     DNSBLContentError, DNSBLTypeError, GoogleSafeBrowsing, UnathorizedAPIKeyError)
from mock import Mock, patch
from ipaddress import ip_address as IP
from itertools import cycle, izip
from __builtin__ import classmethod

from urlparse import urlparse, parse_qs
from requests import HTTPError


hostnames  = 't1.pl', 't2.com', 't3.com.pl'
ips = IP(u'255.255.0.1'), IP(u'2001:DB8:abc:123::42')

host_collection = Mock()
host_collection.ips = ips
host_collection.hostnames = hostnames

empty_host_collection = Mock()
empty_host_collection.ips = ()
empty_host_collection.hostnames = ()
        
class HpHostsTest(unittest.TestCase):
    ''' Tests HpHosts methods '''
    
    classification = '[TEST]'
    
    @classmethod
    def setUpClass(cls):
        cls.hp_hosts = HpHosts('spambl_test_suite')
        
        cls.patcher = patch('spambl.get')
        cls.mocked_get = cls.patcher.start()
        
    def prepareGetReturnValue(self, listed, classification = False):
        ''' Set up return value of get 
        
        :param listed: if True, the content will contain 'Listed' string, else it will contain 'Not listed'
        :param classification: if True, a classification will be added to the content
        '''
        
        if listed:
            c = self.classification if classification else ''
            content = ','.join(('Listed', c))
        else:
            content = 'Not listed'
            
        self.mocked_get.return_value.content = content
    
    def testContains(self):
        ''' Test __contains__ method '''
        
        for listed in True, False:
            self.prepareGetReturnValue(listed)
            
            for k in ips:
                self.assertEqual(k in self.hp_hosts, listed)
                
    def testLookup(self):
        ''' Test lookup method'''
        
        self.prepareGetReturnValue(True, True)
         
        for host in ips + hostnames:
            self.assertEqual(self.hp_hosts.lookup(host).host, host)
            
        self.prepareGetReturnValue(False)
        
        for host in ips + hostnames:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()

class DNSBLServiceTest(unittest.TestCase):
    
    code_item_class = {1: 'Class #1', 2: 'Class #2'}
    
    @classmethod
    def setUpClass(cls):
        
        cls.dnsbl_service = DNSBLService('test_service', 'test.suffix', cls.code_item_class, True, True)
        
        cls.patcher = patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
    def setUpQuerySideEffect(self, nxdomain = False):
        ''' Prepare side effects of mocked query function for tests
        
        :param nxdomain: if True, the side effect of calling query is set to be a sequence of
        return values, otherwise it is raising NXDOMAIN exception
        '''
        
        side_effect = NXDOMAIN('test NXDOMAIN exception')
        
        if not nxdomain:
            return_values = []
        
            for n in self.code_item_class:
                m = Mock()
                m.to_text.return_value = '127.0.0.%d' % n
                return_values.append([m])
            
            side_effect = cycle(return_values)
                
        self.mocked_query.side_effect = side_effect
        
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
        inverted_ips =  '1.0.255.255', '2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.2.1.0.c.b.a.0.8.b.d.0.1.0.0.2'
        values = hostnames + inverted_ips
        
        self.setUpQuerySideEffect()
        
        return_code_iterator = cycle(self.code_item_class.keys())
        
        for v in values:
            self.assertEqual(self.dnsbl_service.query(v), next(return_code_iterator))
        
        self.setUpQuerySideEffect(True)
        
        for v in values:
            self.assertEqual(self.dnsbl_service.query(v), None)
            
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
        
        hosts = hostnames + ips
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
        
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()