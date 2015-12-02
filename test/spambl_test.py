#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, BaseDNSBL, 
                    IpDNSBL,
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     CodeClassificationMap, SumClassificationMap)
from mock import Mock, patch, MagicMock
from ipaddress import ip_address as IP
from itertools import cycle, izip, combinations, product
from __builtin__ import classmethod

from urlparse import urlparse, parse_qs
from requests import HTTPError
from dns import name
from dns import reversename
from dns.exception import SyntaxError

def relative_name(hostname):
    ''' Create an object representing partially qualified domain name 
    for given hostname
    
    :param host: a hostname
    :returns: dns.name.Name instance relative to the root
    '''
    return name.from_text(hostname).relativize(name.root) 
        
class BaseDNSBLTest(unittest.TestCase):
    
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Perapre BaseDNSBL instance to be tested
        
        :param query_domain: a parent domain of dns query
        '''
        
        cls.dnsbl_service = BaseDNSBL('test_service', query_domain, cls.getCodeItemClassMock())
    
    @classmethod
    def setUpClass(cls):
        
        cls.setUpData()
        query_domain = 'test.query.domain'
        
        cls.query_domain = name.from_text(query_domain)
        
        cls.setUpDNSBLService(query_domain)
        cls.setUpMockedQuery()
        
    @classmethod
    def getCodeItemClassMock(cls):
        code_item_class = MagicMock()
        code_item_class.__getitem__.side_effect = cls.get_classification
        
        return code_item_class
        
    @classmethod
    def setUpData(cls):
        cls.listed_hostname_strs = u't1.pl', u't2.com', u't3.com.pl', u't4.com', u't5.pl'
        cls.listed_ip_strs = u'255.0.120.1', u'2001:db8:abc:123::42'
        
        cls.listed_hostnames = map(relative_name, cls.listed_hostname_strs)
        cls.listed_ips = map(IP, cls.listed_ip_strs)
        
        cls.listed_hostname_strs_unknown_class = u'test1.pl', u'test2.pl'
        cls.listed_hostname_unknown_class = map(relative_name, cls.listed_hostname_strs_unknown_class)
        
        cls.listed_ip_strs_unknown_class = u'120.150.120.1', u'2001:db7:abc:144::22'
        cls.listed_ip_unknown_class = map(IP, cls.listed_ip_strs_unknown_class)
        
        
        cls.not_listed_hostname_strs = u'lorem.pl', u'ipsum.com'
        cls.not_listed_hostnames = map(relative_name, cls.not_listed_hostname_strs)
        
        cls.not_listed_ip_strs = u'200.0.121.1', u'2001:db8:abc:124::41'
        cls.not_listed_ips = map(IP, cls.not_listed_ip_strs)
        
        cls.correct_return_codes = 1, 2, 3
        cls.incorrect_return_codes = 7, 11
        
    @classmethod
    def get_return_code(cls, host):
        
        listed_hostnames = cls.listed_hostname_strs + cls.listed_ip_strs
        with_incorrect_codes = cls.listed_hostname_strs_unknown_class + cls.listed_ip_strs_unknown_class
        
        try:
            i = listed_hostnames.index(unicode(host))
            
            return cls.correct_return_codes[i % len(cls.correct_return_codes)]
            
        except ValueError:
            try:
                n = with_incorrect_codes.index(unicode(host))
                
                return cls.incorrect_return_codes[n % len(cls.incorrect_return_codes)]
            
            except ValueError:
                return None
        
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
        query, as required by BaseDNSBL
        '''
        
        host = query_name.relativize(cls.query_domain)
        ip_reverse_domains = reversename.ipv4_reverse_domain, reversename.ipv6_reverse_domain
        
        for root in ip_reverse_domains:

            reverse_pointer = host.derelativize(root)
            try:
                host = reversename.to_address(reverse_pointer)
            except SyntaxError:
                continue
            else:
                break
            
        return_code = cls.get_return_code(host)
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
    
    def doTestContains(self, hosts, expected):
        ''' Perform test of __contains__ method of dnsbl class '''
        
        _assert = self.assertTrue if expected else self.assertFalse
        
        for h in hosts:
            _assert(h in self.dnsbl_service)
            
    def doTestContainsHostname(self, hosts, expected):
        ''' Perform test of contains_hostname method of dnsbl class '''
        
        _assert = self.assertTrue if expected else self.assertFalse
        
        for h in hosts:
            _assert(self.dnsbl_service.contains_hostname(h))
            
    def doTestContainsIp(self, hosts, expected):
        ''' Perform test of contains_ip method of dnsbl class '''
        
        _assert = self.assertTrue if expected else self.assertFalse
        
        for h in hosts:
            _assert(self.dnsbl_service.contains_ip(h))
    
    def doTestNotImplementedOperation(self, function, data):
        ''' Perform test of method that is not implemented in tested class '''
        
        for h in data:
            self.assertRaises(NotImplementedError, function, h)
      
    def testContainsForListedHostnameStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.__contains__
        self.doTestNotImplementedOperation(method, self.listed_hostname_strs)
          
    def testContainsForNotListedHostnameStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.__contains__
        self.doTestNotImplementedOperation(method, self.not_listed_hostname_strs)
        
    def testContainsForListedHostnames(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.contains_hostname
        self.doTestNotImplementedOperation(method, self.listed_hostnames)
             
    def testContainsForNotListedHostnames(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.contains_hostname
        self.doTestNotImplementedOperation(method, self.not_listed_hostnames)
        
    def testContainsForListedIpStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.__contains__
        self.doTestNotImplementedOperation(method, self.listed_ip_strs)
             
    def testContainsForNotListedIpStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.__contains__
        self.doTestNotImplementedOperation(method, self.not_listed_ip_strs)
        
    def testContainsForListedIps(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.contains_ip
        self.doTestNotImplementedOperation(method, self.listed_ips)
             
    def testContainsForNotListedIps(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.contains_ip
        self.doTestNotImplementedOperation(method, self.not_listed_ips)
        
    def testLookupForListedHostnameStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.listed_hostname_strs)
            
    def testLookupForNotListedHostnameStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.not_listed_hostname_strs)
            
    def testLookupForHostnameStringsWithIncorrectCodes(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.listed_hostname_strs_unknown_class)
            
    def testLookupForListedIpStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.listed_ip_strs)
            
    def testLookupForNotListedIpStrings(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.not_listed_ip_strs)
            
    def testLookupForListedIpStringsWithIncorrectCodes(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup
        self.doTestNotImplementedOperation(method, self.listed_ip_unknown_class)
            
    def testLookupHostnameForListedHostnames(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_hostname
        self.doTestNotImplementedOperation(method, self.listed_hostnames)
            
    def testLookupHostnameForNotListedHostnames(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_hostname
        self.doTestNotImplementedOperation(method, self.not_listed_hostnames)
            
    def testLookupHostnameForListedHostnamesWithIncorrectCodes(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_hostname
        self.doTestNotImplementedOperation(method, self.listed_hostname_unknown_class)
            
    def testLookupIpForListedIps(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_ip
        self.doTestNotImplementedOperation(method, self.listed_ips)
             
    def testLookupIpForNotListedIps(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_ip
        self.doTestNotImplementedOperation(method, self.not_listed_ips)
            
    def testLookupIpForListedIpsWithIncorrectCodes(self):
        ''' Calling this method should result in NotImplementedError '''
        
        method = self.dnsbl_service.lookup_ip
        self.doTestNotImplementedOperation(method, self.listed_ip_unknown_class)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
class IpDNSBLTest(BaseDNSBLTest):
    
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Perapre IpDNSBL instance to be tested
        
        :param query_domain: a parent domain of dns query
        '''
        
        cls.dnsbl_service = IpDNSBL('test_service', query_domain, cls.getCodeItemClassMock())
        
    def testContainsForListedIpStrings(self):
        ''' __contains__ must return True for listed ip strings '''
         
        self.doTestContains(self.listed_ip_strs, True)
             
    def testContainsForNotListedIpStrings(self):
        ''' __contains__ must return False for not listed ip strings '''
         
        self.doTestContains(self.not_listed_ip_strs, False)
        
    def testContainsForListedIps(self):
        ''' __contains__ must return True for listed ip objects '''
         
        self.doTestContainsIp(map(IP, self.listed_ip_strs), True)
             
    def testContainsForNotListedIps(self):
        ''' __contains__ must return False for not listed ip objects '''
         
        self.doTestContainsIp(map(IP, self.not_listed_ip_strs), False)
            
    def testLookupForListedIpStrings(self):
        ''' lookup method must return object with value equal to
        ip strings it was passed '''
        
        for h in self.listed_ip_strs:
            actual = self.dnsbl_service.lookup(h)
            self.assertEqual(actual.value, h)
            
    def testLookupForNotListedIpStrings(self):
        ''' lookup method must return None for not listed ip strings'''
        
        for h in self.not_listed_ip_strs:
            actual = self.dnsbl_service.lookup(h)
            self.assertEqual(actual, None)
            
    def testLookupForListedIpStringsWithIncorrectCodes(self):
        ''' lookup method must raise an exception when passed an
        ip address string associated with an unknown return code '''
        
        for h in self.listed_ip_strs_unknown_class:
            self.assertRaises(UnknownCodeError, self.dnsbl_service.lookup, h)
    
    def testLookupIpForListedIps(self):
        ''' lookup method must return object with value equal to string value
        of listed ip object it was passed '''
        
        for h in self.listed_ips:
            actual = self.dnsbl_service.lookup_ip(h)
            self.assertEqual(actual.value, str(h))
             
    def testLookupIpForNotListedIps(self):
        ''' lookup method must return None for not listed ip object it was passed '''
        
        for h in self.not_listed_ips:
            actual = self.dnsbl_service.lookup_ip(h)
            self.assertEqual(actual, None)
            
    def testLookupIpForListedIpsWithIncorrectCodes(self):
        ''' lookup method must raise an exception for an ip object representing value
        associated with unknown return code '''
        
        for h in self.listed_ip_unknown_class:
            self.assertRaises(UnknownCodeError, self.dnsbl_service.lookup_ip, h)
            
        
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
            
class HpHostsTest(unittest.TestCase):
    ''' Tests HpHosts methods '''
    
    @classmethod
    def setUpClass(cls):
        cls.hp_hosts = HpHosts('spambl_test_suite')
        cls.setUpData()
        cls.setUpMockedGet()
        
    @classmethod
    def setUpData(cls):
        cls.classification = '[TEST]'
        
        listed_hostnames = map(relative_name, ('t1.pl', 't2.com', 't3.com.pl'))
        listed_ips = map(IP, (u'255.255.0.1', u'2001:DB8:abc:123::42'))
        
        cls.hosts_listed = listed_hostnames + listed_ips
        
        not_listed_hostnames = map(relative_name, ('at.pl', 'lorem.com', 'impsum.com'))
        not_listed_ips = map(IP, [u'211.170.0.1'])
        
        cls.hosts_not_listed = not_listed_hostnames + not_listed_ips
        
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
        
        if params['s'][0] in [str(n) for n in cls.hosts_listed]:
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
    
    def testContainsForListedHosts(self):
        ''' For listed hosts, __contains__ should return True'''
        
        for host in self.hosts_listed:
            self.assertTrue(host in self.hp_hosts)
            
    def testContainsForNotListedHosts(self):
        ''' For not listed hosts, __contains__ should return False '''
        
        for host in self.hosts_not_listed:
            self.assertFalse(host in self.hp_hosts)
                
    def testLookupForListedHosts(self):
        ''' For listed hosts, lookup should return an object representing it'''
        
        for host in self.hosts_listed:
            self.assertEqual(self.hp_hosts.lookup(host).value, host)
            
    def testLookupForNotListedHosts(self):
        ''' For not listed hosts, lookup should return None '''
            
        for host in self.hosts_not_listed:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
class GoogleSafeBrowsingTest(unittest.TestCase):    
    @classmethod
    def setUpClass(cls):
        cls.valid_key = 'test_key'
        
        cls.google_safe_browsing = GoogleSafeBrowsing('test_client', '0.1', cls.valid_key)
        cls.invalid_key_gbs = GoogleSafeBrowsing('test_client', '0.1', 'invalid_key')
        
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
            
            
        cls.spam_urls = cls.spam_urls_classification.keys()
            
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
            
    def doContainsTestExpectingTrue(self, url_sequence):
        ''' Perform a test of __contains__ method of GoogleSafeBrowsing
        instance when expecting True as a result '''
        result = self.google_safe_browsing.contains_any(url_sequence)
        self.assertTrue(result)
    
    def testContainsAnyForAllSpamUrls(self):
        ''' contains_any should return True for a sequence of spam urls '''
        self.doContainsTestExpectingTrue(self.spam_urls)
        
    def testContainsAnyForMixedData(self):
        ''' contains_any should return True for a sequence containing both spam and non-spam urls '''
        self.doContainsTestExpectingTrue(self.all_urls)
        
    def testContainsAnyForNonSpamUrls(self):
        ''' contains_any should return False for a sequence containing non-spam urls'''
        result = self.google_safe_browsing.contains_any(self.non_spam_urls)
        self.assertFalse(result)
        
    def doLookupTestExpectingSpamUrls(self, url_sequence):
        ''' Perform tests of lookup method when expecting
        a sequence of objects representing spam urls as result '''
        
        result = self.google_safe_browsing.lookup(url_sequence)
        
        for item in result:
            self.assertIn(item.value, self.spam_urls_classification)
            self.assertEqual(item.source, self.google_safe_browsing)
            self.assertEqual(item.classification, self.spam_urls_classification[item.value].split(','))
        
            
    def testLookupForSpamUrls(self):
        ''' lookup should return a sequence  of objects representing 
        all urls when called with sequence of spam urls as argument '''
        
        self.doLookupTestExpectingSpamUrls(self.spam_urls)
            
    def testLookupForAllUrls(self):
        ''' lookup should return a sequence of objects representing 
        only spam urls when called with sequence of spam and 
        non-spam urls as argument '''
            
        self.doLookupTestExpectingSpamUrls(self.all_urls)
            
    def testLookupForNonSpamUrls(self):
        ''' lookup should return an empty tuple when called for a sequence
        of non spam urls as argument '''
        
        result = self.google_safe_browsing.lookup(self.non_spam_urls)
        
        self.assertEqual(result, tuple())

    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        
class HostCollectionTest(unittest.TestCase):
    
    def setUp(self):
        self.listed_hostnames = u'google.com', u'test1.pl'
        self.listed_ips = u'127.0.0.1', u'2001:db8:abc:123::42'
        
        self.not_listed_hosts = u'a.com', u'255.0.0.1'
        
        self.listed_hosts = self.listed_hostnames + self.listed_ips
        
        self.host_collection_A = HostCollection(self.listed_hosts)
        
        self.matching_A = HostCollection(self.listed_hosts+self.not_listed_hosts)
        self.not_matching_a = HostCollection(self.not_listed_hosts)
        self.empty = HostCollection()
        
    def testAddHostnames(self):
        ''' Adding a valid hostname should result in inclusion of a
        Name object representing it in the collection '''
        
        for h in self.listed_hostnames:
            self.host_collection_A.add(h)
            self.assertIn(relative_name(h), self.host_collection_A.hostnames)
            
    def testAddIps(self):
        ''' Adding a valid ip address should result in inclusion of a
        valid ip address object representing it in the collection '''
        
        for ip in self.listed_ips:
            self.host_collection_A.add(ip)
            self.assertIn(IP(ip), self.host_collection_A.ip_addresses)
            
    def testAddInvalidHost(self):
        ''' Adding an invalid host should result in an error '''
        
        test_host = '-k.'
        self.assertRaises(ValueError, self.host_collection_A.add, test_host)
        
    def testContainsMatchForMatchingHostCollection(self):
        ''' contains_match should return True for a HostCollection
        that includes matching values '''
        
        self.assertTrue(self.host_collection_A.contains_match(self.matching_A))
        
    def testContainsMatchForNotMatchingHostCollection(self):
        ''' contains_match should return False for a HostCollection
        that does not have any values in common with the other '''
        
        self.assertFalse(self.host_collection_A.contains_match(self.not_matching_a))
        
    def testContainsMatchForEmptyHostCollection(self):
        ''' contains_match should return False for an empty
        HostCollection '''
        
        self.assertFalse(self.host_collection_A.contains_match(self.empty))
        
    def testDifferenceForHostCollectionAandMatchingA(self):
        ''' The difference between a host collection and another host
        collection matching some of its elements should be a host
        collection with only elements not matching the second one '''
        
        actual = self.matching_A.difference(self.host_collection_A)
        expected = self.not_matching_a
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
    def testDifferenceForMatchingAandHostCollectionA(self):
        ''' The difference between a host collection and a host
        collection matching it should be empty host collection'''
        actual = self.host_collection_A.difference(self.matching_A)
        expected = self.empty
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
    def testDifferenceForHostCollectionAandEmpty(self):
        ''' The difference between a host collection and an empty host
        collection should be equal to the non-empty host
        collection '''
        actual = self.host_collection_A.difference(self.empty)
        expected = self.host_collection_A
        
        self.assertItemsEqual(actual.hostnames, expected.hostnames)
        self.assertItemsEqual(actual.ip_addresses, expected.ip_addresses)
        
    def testIter(self):
        ''' The __iter__ method should yield all hosts contained
        in HostCollection instance '''
        
        for k in self.host_collection_A:
            self.assertIn(unicode(k), self.listed_hosts)
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()