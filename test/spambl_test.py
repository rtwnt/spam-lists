#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, 
                    IpDNSBL, DomainDNSBL, GeneralDNSBL,
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     CodeClassificationMap, SumClassificationMap, Hostname, IpAddress, host, is_valid_url)
from mock import Mock, patch, MagicMock
from ipaddress import ip_address as IP, ip_address
from itertools import cycle, izip, combinations, product
from __builtin__ import classmethod

from urlparse import urlparse, parse_qs
from requests.exceptions import HTTPError
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

class BaseDNSBLTest(object):
    @classmethod
    def setUpClass(cls, listed_with_known_codes, listed_with_unknown_codes, 
                  not_listed, invalid_arguments):
        
        cls.setUpData(listed_with_known_codes, listed_with_unknown_codes, 
                  not_listed, invalid_arguments)
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
    def setUpData(cls, listed_with_known_codes, listed_with_unknown_codes, 
                  not_listed, invalid_arguments):
        ''' Prepares data used for tests
        
        known return code - a return code value that has been accounted for in
        the instance of code_item_class map used by the service instance
        
        :param listed_with_known_codes: a sequence of hosts that are listed
        by the tested service and have known return codes assigned to them
        :param listed_with_unknown_codes: a sequence of hosts that are listed
        by the tested service, but which should trigger returning an unknown return
        code value when the return code assigned to them is requested
        :param not_listed: a sequence of hosts that could be listed by 
        the tested service (valid hosts), but aren't
        :param invalid_arguments: a sequence of arguments expected to cause a ValueError
        when passed to tested methods
        '''
        
        cls.listed_with_known_codes = listed_with_known_codes
        cls.listed_with_unknown_codes = listed_with_unknown_codes
        cls.not_listed = not_listed
        cls.invalid_arguments = invalid_arguments
        
        cls.listed_hosts = listed_with_known_codes + listed_with_unknown_codes
        
        cls.known_return_codes = 1, 2, 3
        cls.unknown_return_codes = 7, 11
        
    @classmethod
    def get_return_code(cls, host):
        
        try:
            i = cls.listed_with_known_codes.index(unicode(host))
            
            return cls.known_return_codes[i % len(cls.known_return_codes)]
            
        except ValueError:
            try:
                n = cls.listed_with_unknown_codes.index(unicode(host))
                
                return cls.unknown_return_codes[n % len(cls.unknown_return_codes)]
            
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
        
        if index in cls.known_return_codes:
            return 'CLASS {}'.format(index)
        
        raise UnknownCodeError('Unknown code raised by test')
    
    
    def doTestCallForInvalidArgs(self, function):
        ''' Perform test of a function that should raise ValueError for given data '''
        
        for h in self.invalid_arguments:
            self.assertRaises(ValueError, function, h)
        
    def testContainsForInvalidArgs(self):
        ''' The call should raise ValueError '''
        
        self.doTestCallForInvalidArgs(self.dnsbl_service.__contains__)
        
    def testLookupForInvalidArgs(self):
        ''' The call should raise ValueError '''
        
        self.doTestCallForInvalidArgs(self.dnsbl_service.lookup)
            
    def doTestContains(self, hosts, expected):
        ''' Perform test of __contains__ method of dnsbl class '''
        
        _assert = self.assertTrue if expected else self.assertFalse
        
        for h in hosts:
            _assert(h in self.dnsbl_service)
            
    def testContainsForListedValues(self):
        ''' __contains__ should return  true '''
        
        self.doTestContains(self.listed_hosts, True)
        
    def testContainsForNotListedValues(self):
        ''' __contains__ should return  true '''
        
        self.doTestContains(self.not_listed, False)
            
    def testLookupForListedValues(self):
        ''' lookup method must return object with value equal to
        ip strings it was passed '''
        
        for h in self.listed_with_known_codes:
            actual = self.dnsbl_service.lookup(h)
            self.assertEqual(actual.value, h)
            
    def testLookupForNotListedValues(self):
        ''' lookup method must return None  '''
        
        for h in self.not_listed:
            actual = self.dnsbl_service.lookup(h)
            self.assertIsNone(actual)
            
    def testLookupForListedWithUnknownCodes(self,):
        ''' lookup method must raise UnknownCodeError '''
        
        for h in self.listed_with_unknown_codes:
            self.assertRaises(UnknownCodeError, self.dnsbl_service.lookup, h)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
            
class IpDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        
        listed_with_known_codes = u'255.0.120.1', u'2001:db8:abc:123::42'
        listed_with_unknown_codes = u'120.150.120.1', u'2001:db7:abc:144::22'
        not_listed = u'200.0.121.1', u'2001:db8:abc:124::41'
        invalid_arguments = u't1.pl', u't2.com'
        
        super(IpDNSBLTest, cls).setUpClass(listed_with_known_codes, listed_with_unknown_codes, 
                                           not_listed, invalid_arguments)
    
    
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Prepare IpDNSBL instance to be tested
         
        :param query_domain: a parent domain of dns query
        '''
         
        cls.dnsbl_service = IpDNSBL('test_service', query_domain, cls.getCodeItemClassMock())
        
class DomainDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        listed_with_known_codes = u't1.pl', u't2.com', u't3.com.pl', u't4.com', u't5.pl'
        listed_with_unknown_codes = u'test1.pl', u'test2.pl'
        not_listed = u'lorem.pl', u'ipsum.com'
        invalid_arguments = u'255.0.120.1', u'2001:db8:abc:123::42', '-aaa'
        
        super(DomainDNSBLTest, cls).setUpClass(listed_with_known_codes, listed_with_unknown_codes, 
                                           not_listed, invalid_arguments)
    
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Perapre DomainDNSBL instance to be tested
        
        :param query_domain: a parent domain of dns query
        '''
        
        cls.dnsbl_service = DomainDNSBL('test_service', query_domain, cls.getCodeItemClassMock())
            
class GeneralDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        listed_with_known_codes = u't1.pl', u't2.com', u'255.0.120.1', u'2001:db8:abc:123::42'
        listed_with_unknown_codes = u'test1.pl', u'test2.pl', u'120.150.120.1', u'2001:db7:abc:144::22'
        not_listed = u'lorem.pl', u'ipsum.com', u'200.0.121.1', u'2001:db8:abc:124::41'
        invalid_arguments = '-aaaa'
        
        
        super(GeneralDNSBLTest, cls).setUpClass(listed_with_known_codes, listed_with_unknown_codes, 
                                           not_listed, invalid_arguments)
    
    @classmethod
    def setUpDNSBLService(cls, query_domain):
        ''' Prepare GeneralDNSBL instance to be tested
        
        :param query_domain: a parent domain of dns query
        '''
        
        cls.dnsbl_service = GeneralDNSBL('test_service', query_domain, cls.getCodeItemClassMock())
    
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
        
        cls.invalid_hosts = u'266.266.266.266', u'-test.host.pl'
        
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
            
    def testContainsForInvalidHosts(self):
        ''' For invalid hosts, __contains__ should raise a ValueError '''
        for val in self.invalid_hosts:
            self.assertRaises(ValueError, self.hp_hosts.__contains__, val)
                
    def testLookupForListedHosts(self):
        ''' For listed hosts, lookup should return an object representing it'''
        
        for host in self.hosts_listed:
            self.assertEqual(self.hp_hosts.lookup(host).value, host)
            
    def testLookupForNotListedHosts(self):
        ''' For not listed hosts, lookup should return None '''
            
        for host in self.hosts_not_listed:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    def testLookupForInvalidHosts(self):
        ''' For invalid hosts, lookup should raise a ValueError '''
        for val in self.invalid_hosts:
            self.assertRaises(ValueError, self.hp_hosts.lookup, val)
            
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
        self.listed_hosts = self.listed_hostnames + self.listed_ips
        
        self.not_listed_hostnames = u'a.com', u'lorem.pl'
        self.not_listed_ips = u'255.0.0.1', u'2001:db8:abc:124::41'
        self.not_listed_hosts = self.not_listed_hostnames + self.not_listed_ips
        
        self.host_collection_A = HostCollection(self.listed_hosts)
        
        self.matching_A = HostCollection(self.listed_hosts+self.not_listed_hosts)
        self.not_matching_a = HostCollection(self.not_listed_hosts)
        self.empty = HostCollection()
        
    def testAddHostnames(self):
        ''' Adding a valid hostname should result in inclusion of a
        Name object representing it in the collection '''
        
        for h in self.listed_hostnames:
            self.host_collection_A.add(h)
            self.assertTrue(any(str(h) == str(i) for i in self.host_collection_A.hosts))
            
    def testAddIps(self):
        ''' Adding a valid ip address should result in inclusion of a
        valid ip address object representing it in the collection '''
        
        for ip in self.listed_ips:
            self.host_collection_A.add(ip)
            self.assertTrue(any(str(ip) == str(i) for i in self.host_collection_A.hosts))
            
    def testAddInvalidHost(self):
        ''' Adding an invalid host should result in an error '''
        
        test_host = '-k.'
        self.assertRaises(ValueError, self.host_collection_A.add, test_host)
        
    def testContainsForListedIps(self):
        ''' __contains__ must return True for listed ips '''
        for k in self.listed_ips:
            self.assertTrue(k in self.host_collection_A)
            
    def testContainsForNotListedIps(self):
        ''' __contains__ must return False for not listed ips '''
        for k in self.not_listed_ips:
            self.assertFalse(k in self.host_collection_A)
            
    def testContainsForListedHostnames(self):
        ''' __contains__ must return True for listed hostnames '''
        for k in self.listed_hostnames:
            self.assertTrue(k in self.host_collection_A)
            
    def testContainsForNotListedHostnames(self):
        ''' __contains__ must return False for not listed hostnames '''
        for k in self.not_listed_hostnames:
            self.assertFalse(k in self.host_collection_A)
            
    def testContainsForInvalidArguments(self):
        ''' __contains__ must raise ValueError for invalid arguments '''
        for k in ('-k', '999.999.000.111.222'):
            self.assertRaises(ValueError, self.host_collection_A.__contains__, k)
            
class HostnameTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.test_unrelated_domain_str = 'test.unrelated.domain.com'
        cls.unrelated_domain = Hostname(cls.test_unrelated_domain_str)
        
        cls.test_superdomain_str = 'hostname.pl'
        cls.superdomain = Hostname(cls.test_superdomain_str)
        
        cls.test_hostname_str = 'test.'+cls.test_superdomain_str
        cls.hostname = Hostname(cls.test_hostname_str)
        
        cls.test_subdomain_str = 'subomain.of.'+cls.test_hostname_str
        cls.subdomain = Hostname(cls.test_subdomain_str)
        
    def testIsMatchForTheSameHostname(self):
        ''' is_match method should return True for
        identical hostname '''
        
        self.assertTrue(self.hostname.is_match(Hostname(self.test_hostname_str)))
        
    def testIsMatchForASubdomain(self):
        ''' is_match should return False for a subdomain '''
        
        self.assertFalse(self.hostname.is_match(self.subdomain))
        
    def testIsMatchForASuperDomain(self):
        ''' is_match should return True for a superdomain '''
        
        self.assertTrue(self.hostname.is_match(self.superdomain))
        
    def testIsMatchForAnUnrelatedDomain(self):
        ''' is_match should return False for an unrelated domain '''
        
        self.assertFalse(self.hostname.is_match(self.unrelated_domain))
        
    def testIsMatchForADifferentObject(self):
        ''' is_match should return False for an object of different type '''
        
        self.assertFalse(self.hostname.is_match(tuple()))
        

class IpAddressTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        
        cls.ipv4_str = u'255.0.2.1'
        cls.another_ipv4_str = u'127.0.0.1'
        cls.ipv4_relative_domain = relative_name('1.2.0.255')
        cls.ipv4 = IpAddress(cls.ipv4_str)
        
        cls.ipv6_str = u'2001:db8:abc:123::42'
        cls.another_ipv6_str = u'2001:db8:abc:125::45'
        ipv6_rrp_str = '2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.2.1.0.c.b.a.0.8.b.d.0.1.0.0.2'
        cls.ipv6_relative_domain = relative_name(ipv6_rrp_str)
        cls.ipv6 = IpAddress(cls.ipv6_str)
        
    def testRelativeDomainForIpV4(self):
        ''' relative_domain property of IpAddress containing
        ipv4 value should be equal to given domain '''
        
        self.assertEqual(self.ipv4.relative_domain, self.ipv4_relative_domain)
        
    def testRelativeDomainForIpV6(self):
        ''' relative_domain property of IpAddress containing
        ipv6 value should be equal to given domain '''
        
        self.assertEqual(self.ipv6.relative_domain, self.ipv6_relative_domain)
        
    def testIsMatchForTheSameIpV4Address(self):
        ''' is_match for IpAddress objects containing the same IpV4 values
        should return True '''
        
        self.assertTrue(self.ipv4.is_match(IpAddress(self.ipv4_str)))
        
    def testIsMatchForDifferentIpV4Address(self):
        ''' is_match should return False for a value containing a different ipv4 address '''
        
        self.assertFalse(self.ipv4.is_match(IpAddress(self.another_ipv4_str)))
        
    def testIsMatchForIpV6Address(self):
        ''' is_match should return False for an ipv6 value '''
        
        self.assertFalse(self.ipv4.is_match(IpAddress(self.ipv6_str)))
        
    def testIsMatchForAValueOtherThanIpV4Address(self):
        ''' is_match should return False for a value of a different type '''
        
        self.assertFalse(self.ipv4.is_match([]))
        
    def testIsMatchForTheSameIpV6Address(self):
        ''' is_match for IpAddress objects containing the same IpV6 values
        should return True '''
        
        self.assertTrue(self.ipv6.is_match(IpAddress(self.ipv6_str)))
        
    def testIsMatchForDifferentIpV6Address(self):
        ''' is_match should return False for a value containing a different ipv4 address '''
        
        self.assertFalse(self.ipv6.is_match(IpAddress(self.another_ipv6_str)))
        
    def testIsMatchForIpV4Address(self):
        ''' is_match should return False for an ipv4 value '''
        
        self.assertFalse(self.ipv6.is_match(IpAddress(self.ipv4_str)))
        
    def testIsMatchForAValueOtherThanIpV6Address(self):
        ''' is_match should return False for a value of a different type '''
        
        self.assertFalse(self.ipv6.is_match([]))
        
        
class HostTest(unittest.TestCase):
    ''' Tests host function from spambl module '''
    
    @classmethod
    def setUpClass(cls):
        cls.ipv4_str = u'127.0.0.1'
        cls.ipv6_str = u'2001:db8:abc:125::45'
        cls.hostname = 'test.hostname'
        cls.invalid_host = []
        
    def testHostForIpV4Address(self):
        ''' host() for ipv4 address should return an IpAddress instance
        with an expected value of the _value property'''
        
        self.assertEqual(host(self.ipv4_str)._value, ip_address(self.ipv4_str))
        
    def testHostForIpV6Address(self):
        ''' host() for ipv6address should return an IpAddress instance
        with an expected value of the _value property'''
        
        self.assertEqual(host(self.ipv6_str)._value, ip_address(self.ipv6_str))
        
    def testHostForHostname(self):
        ''' host() for hostname should return a Hostname instance
        with an expected value of the _value property'''
        
        self.assertEqual(host(self.hostname)._value, relative_name(self.hostname))
        
    def testHostForInvalidValue(self):
        ''' For an invalid argument, host() should raise a ValueError'''
        
        self.assertRaises(ValueError, host, self.invalid_host)
          
class IsValidUrlTest(unittest.TestCase):
     
    @classmethod
    def setUpClass(cls):
        cls.valid_urls = 'http://test.url.com', 'https://google.com', 
        'https://google.com/',
        'https://test.domain.com/path/element?var=1&var_2=3#fragment', 
        'http://test.domain.com?var_1=1&var_2=2',
        'https://test.domain.com:123', 'https://abc:def@test.domain.com'
        'http://255.0.0.255', 'http://[2001:db8:abc:125::45]'
         
        cls.invalid_urls = 'test.url.com', 'http://266.0.0.266', 'http://127.0.0.1.1', 
        'http://test.domain.com:aaa', 
        'https://testdomaincom', 
        'http://-invalid.domain.com'
         
    def testIsValidUrlForValidUrls(self):
        ''' The function should return True for valid urls '''
         
        for u in self.valid_urls:
            self.assertTrue(is_valid_url(u))
             
    def testAssertValidUrlForInvalidUrls(self):
        ''' The function should return False for invalid urls '''
          
        for u in self.invalid_urls:
            self.assertFalse(is_valid_url(u))
            
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()