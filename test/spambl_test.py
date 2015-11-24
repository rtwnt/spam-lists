#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, DNSBLService, BaseDNSBLClient, 
                     DNSBLContentError, DNSBLTypeError, GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     CodeClassificationMap, SumClassificationMap)
from mock import Mock, patch, MagicMock
from ipaddress import ip_address as IP
from itertools import cycle, izip, combinations, product
from __builtin__ import classmethod

from urlparse import urlparse, parse_qs
from requests import HTTPError
from dns import name

def relative_name(hostname):
    ''' Create an object representing partially qualified domain name 
    for given hostname
    
    :param host: a hostname
    :returns: dns.name.Name instance relative to the root
    '''
    return name.from_text(hostname).relativize(name.root) 

class DNSBLServiceTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        
        cls.host_return_code = {'t1.pl': 1, 't2.com': 2, 't3.com.pl': 3, 't4.com': 7, 't5.pl': 11}
        cls.correct_return_codes = 1, 2, 3

        query_domain = 'test.query.domain'
        
        cls.query_domain = name.from_text(query_domain)
        
        cls.setUpNames() 
        cls.setUpDNSBLService(query_domain)
        cls.setUpMockedQuery()
        
    @classmethod
    def setUpNames(cls):
        ''' Prepare all instances of dns.name.Name objects that
        will be passed as arguments to tested methods, along with
        associated return codes
        '''
        
        cls.name_known_code = dict()
        cls.unknown_code_names = []
        
        for h, c in cls.host_return_code.iteritems():
            hostname = relative_name(h)
            
            if c in cls.correct_return_codes:
                cls.name_known_code[hostname] = c
                
            else:
                cls.unknown_code_names.append(hostname)
                
        cls.not_listed_names = [relative_name(n) for n in ('lorem.pl', 'ipsum.pl')]
        
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Perapre DNSBLService instance to be tested
        
        :param query_domain: a parent domain of dns query
        '''
        
        code_item_class = MagicMock()
        code_item_class.__getitem__.side_effect = cls.get_classification
        
        cls.dnsbl_service = DNSBLService('test_service', query_domain, code_item_class, True, True)
        
    @classmethod
    def setUpMockedQuery(cls):
        cls.patcher = patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
        cls.mocked_query.side_effect = cls.query
        
    @classmethod
    def query(cls, query_name):
        ''' Perform dns query using this mocked implementation
        
        :param query_name: name of queried domain
        :returns: an instance of Mock representing response to the
        query, as required by DNSBLService
        '''
        
        host = str(query_name.relativize(cls.query_domain))
        
        return_code = cls.host_return_code .get(host)
        if return_code:
            answer = Mock()
            answer.to_text.return_value = '127.0.0.%d' % return_code
            return [answer]
        
        raise NXDOMAIN('test NXDOMAIN exception')
        
    @classmethod
    def get_classification(cls, index):
        ''' Get classification for given code
        
        This is a method providing side effects for mocked
        classification map instance
        
        :param index: an integer value intended as representing a classification value
        :returns: a taxonomical unit
        ''' 
        
        if index in cls.correct_return_codes:
            return 'CLASS {}'.format(index)
        
        raise UnknownCodeError('Unknown code raised by test')
            
    def testGetClassificationForListedHosts(self):
        ''' Listed hosts should be classified according to the return code
        the service assigns to them and a map of classification in the DNSBLService object '''
        
        for host, return_code in self.name_known_code.iteritems():
            
            actual = self.dnsbl_service.get_classification(host)
            expected = self.get_classification(return_code)
            self.assertEqual(actual, expected)
            
    def testGetClassificationForNotListedHosts(self):
        ''' For not listed hosts, the expected classification is always None '''
        
        for host in self.not_listed_names:
            actual = self.dnsbl_service.get_classification(host)
            self.assertIsNone(actual)
            
    def testGetClassificationForUnknownClassHosts(self):
        ''' Some changes to the service may introduce new return codes assigned
        to hosts listed in them. These return codes refer to classifications that
        must be included in the spambl module, so detecting them should
        cause an error '''
            
        for host in self.unknown_code_names:
            self.assertRaises(UnknownCodeError, self.dnsbl_service.get_classification, host)
            
        
    def testContainsForListedHosts(self):
        ''' __contains__ must return True for listed hosts '''
        
        for host in self.name_known_code.keys() + self.unknown_code_names:
            self.assertTrue(host in self.dnsbl_service)
            
    def testContainsForNotListedHosts(self):
        ''' __contains__ must return False for not listed hosts '''
        
        for host in self.not_listed_names:
            self.assertFalse(host in self.dnsbl_service)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        
class CodeClassificationMapTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.code_item_class = {1: 'Class #1', 2: 'Class #2'}
        cls.invalid_keys = 3, 4
        
        cls.map = CodeClassificationMap(cls.code_item_class)
        
        
    def testGetItemForValidKeys(self):
        ''' For a listed key, __getitem__ should return expected classification '''
        
        for key in self.code_item_class:
            self.assertEqual(self.map[key], self.code_item_class[key])
            
    def testGetItemForInvalidKeys(self):
        ''' For a not listed key, __getitem__ should raise an UnknownCodeError '''
            
        for key in self.invalid_keys:
            self.assertRaises(UnknownCodeError, self.map.__getitem__, key)
            
class SumClassificationMapTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        
        cls.code_item_class = {2: 'Class #1', 4: 'Class #2'}
    
        cls.invalid_keys = 8, 16, 17, 21
        
        cls.map = SumClassificationMap(cls.code_item_class)
            
            
    def testGetItemForASimpleValidKey(self):
        ''' For a simple listed key, __getitem__ should return an expected classification'''
        for key in self.code_item_class:
            self.assertEqual(self.map[key], tuple([self.code_item_class[key]]))
            
    def testGetItemForAnInvalidKey(self):
        ''' For a non-listed key, __getitem__ should raise UnknownCodeError '''
        for key in self.invalid_keys:
            self.assertRaises(UnknownCodeError, self.map.__getitem__, key)
    
    def testGetItemForASumOfValidKeys(self):
        ''' For a sum of valid keys, __getitem__ should return a tuple of expected classifications '''
        for key_1, key_2 in combinations(self.code_item_class.keys(), 2):
            
            expected  = tuple([x for n, x in self.code_item_class.iteritems() if n in (key_1, key_2)])
            self.assertEqual(self.map[key_1+key_2], expected)
        
    def testGetItemForASumWithAnInvalidKey(self):
        ''' For a sum of keys, including at least one invalid, __getitem__ should
        raise UnknownCodeError
        '''
        for key_1, key_2 in product(self.code_item_class.keys(), self.invalid_keys):
            
            self.assertRaises(UnknownCodeError, self.map.__getitem__, key_1+key_2)
            
class BaseDNSBLClientTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.test_lists_attr_name = 'test_lists_attr'
        cls.hosts_listed = map(relative_name, ('a.com', 'b.com', 'c.com'))
        cls.hosts_not_listed = map(relative_name, ('lorem.com', 'ipsum.pl'))
        cls.classification = 'TEST CLASS'
    
    def setUp(self):
        self.base_dnsbl_client = BaseDNSBLClient()
        
        self.base_dnsbl_client._required_content_in = lambda e: getattr(e, self.test_lists_attr_name) == True
        
        empty_dnsbl = self.getEmptyDNSBLMock()
        
        dnsbls = [self.getDNSBLMockListingHosts() for _ in range(1)]
        dnsbls.append(empty_dnsbl)
        
        self.base_dnsbl_client.dnsbl_services = dnsbls
        
    def getDNSBLMockForAdd(self, required_property = True):
        ''' Create a Mock instance for dnsbl service object
        
        :param required_property: boolean value set to value of the required property
        to which BaseDNSBLClient._LISTS_ATTR_NAME is set
        :returns: an instance of Mock with all necessary attributes
        '''
        
        dnsbl = Mock()
        setattr(dnsbl, self.test_lists_attr_name, bool(required_property))
        
        return dnsbl
    
    def query(self, host):
        
        if host in self.hosts_listed:
            return self.return_code
        return
    
    def contains(self, host):
        ''' Test membership
        An implementation for side effect of mocked dnsbl.__contains__ method
        
        :param host: a host value used in test
        '''
        
        return host in self.hosts_listed
    
    def get_classification(self, host):
        
        ''' Get classification for given host
        An implementation for side effect of mocked dnsbl.get_classification method
        
        :param host: a host value used in test
        '''
        
        if host in self.hosts_listed:
            return self.classification
        
        return
    
    def getDNSBLMockListingHosts(self):
        ''' Get dnsbl mock that lists hosts specified in self.hosts_listed '''
        
        dnsbl = MagicMock()
        dnsbl.__contains__.side_effect = self.contains
        dnsbl.get_classification.side_effect = self.get_classification
        
        return dnsbl
    
    def getEmptyDNSBLMock(self):
        
        dnsbl = MagicMock()
        dnsbl.__contains__.return_value = False
        dnsbl.get_classification.return_value = None
        
        return dnsbl
        
    def testAddDNSBLForValidDNSBL(self):
        ''' Adding dnsbl objects that satisfy the content requirement of
        DNSBLClientinstance should be successful '''
        
        valid_dnsbl = self.getDNSBLMockForAdd()
        self.base_dnsbl_client.add_dnsbl(valid_dnsbl)
        self.assertTrue(valid_dnsbl in self.base_dnsbl_client.dnsbl_services)
        
    def testAddDNSBLForInvalidDNSBL(self):
        ''' Trying to add a dnsbl service that does not satify the requirements
        should result in an error '''
        
        invalid_dnsbl = self.getDNSBLMockForAdd(False)
        self.assertRaises(DNSBLContentError, self.base_dnsbl_client.add_dnsbl, invalid_dnsbl)
        
    def testAddDNSBLForNoDNSBL(self):
        ''' Trying to add an object that does not even has interface required to test
        if it fulfils the content requirements should result in another error '''
        
        no_dnsbl = Mock(spec=[])
        self.assertRaises(DNSBLTypeError, self.base_dnsbl_client.add_dnsbl, no_dnsbl)
        
    def testContainsForListedHosts(self):
        ''' For listed hosts, __contains__ should return True'''
        for host in self.hosts_listed:
            self.assertTrue(host in self.base_dnsbl_client)
            
    def testContainsForNotListedHosts(self):
        ''' For not listed hosts, __contains__ should return False'''
        for host in self.hosts_not_listed:
            self.assertFalse(host in self.base_dnsbl_client)
            
    def testLookupForListedHosts(self):
        ''' For listed hosts, lookup should return a tuple containing
        objects representing these hosts '''
        for host in self.hosts_listed:
            lookup_results = self.base_dnsbl_client.lookup(host)
            for obj in lookup_results:
                self.assertEqual(obj.classification, self.classification)
                self.assertEqual(obj.host, host)
                
    def testLookupForNotListedHosts(self):
        ''' For not listed hosts, lookup should return an empty tuple '''
        for host in self.hosts_not_listed:
            lookup_results = self.base_dnsbl_client.lookup(host)
            self.assertEqual(lookup_results, tuple())
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
        ''' Perform GET request using this mocked implementation
        
        :param url: address of resource
        :returns: an instance of Mock representing response object,
        as required by HpHosts class
        '''
        
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
        ''' Perform POST request using this mocked implementation
        
        :param request_address: address of the resource to be queried
        :param request_body: content of the request
        :returns: an instance of Mock representing response object, as
        requred by GoogleSafeBrowsing class
        '''
        urls = request_body.splitlines()[1:]
        
        results = []
        for u in urls:
            a = cls.spam_urls_classification[u] if u in cls.spam_urls_classification else 'ok'
            results.append(a)
            
        return cls.getPostResponse(request_address, results)
    
    @classmethod
    def getPostResponse(cls, request_address, results):
        ''' Prepare Mock instance representing response object
        
        :param request_address: address of the request
        :param results: results of the request, to be put in the response body
        :returns: an instance of Mock representing response object
        '''
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