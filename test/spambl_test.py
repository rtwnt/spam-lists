#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, 
                    IpDNSBL, DomainDNSBL, GeneralDNSBL,
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     CodeClassificationMap, SumClassificationMap, Hostname, IpAddress, 
                     host, is_valid_url, BaseUrlTester)
from mock import Mock, patch, MagicMock
from ipaddress import ip_address as IP, ip_address
from itertools import cycle, izip, combinations, product

from collections import namedtuple

from urlparse import urlparse, parse_qs
from requests.exceptions import HTTPError, MissingSchema, InvalidSchema, InvalidURL
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

Url = namedtuple('Url', 'value location')

def get_redirect_urls(urls):
    ''' Get a sequence of Url objects,
    each with .location assigned to the next one
    
    :param urls: a sequence of url values
    :returns: a tuple containing instances of urls for given
    arguments
    '''
    
    result = []
    location = None
    
    for u in reversed(urls):
        url = Url(u, location)
        result.insert(0, url)
        location = result[0]
        
    return result


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
            
class BaseUrlTesterTest(unittest.TestCase):
    
    @classmethod
    def getRegisteredRedirects(cls, target_list, urls):
        ''' Get a sequence of urls representing
        a sequence of redirects
        
        Each url is registered, and the last one is
        registered by adding it to specified list
        :param target_list: a list to which final target url is to
        be appended
        :param urls: a sequence of url values
        :returns: a tuple containing Url instances
        '''
        redirect_urls = get_redirect_urls(urls)
        
        target_list.append(redirect_urls[-1])
        
        cls.http_urls.extend(redirect_urls[:-1])
        
        return redirect_urls
    
    @classmethod
    def getRegisteredRedirectsToHttp(cls, *urls):
        return cls.getRegisteredRedirects(cls.http_urls, urls)
        
    @classmethod
    def getRegisteredRedirectsToFtp(cls, *urls):
        return cls.getRegisteredRedirects(cls.ftp_urls, urls)
        
    @classmethod
    def getRegisteredRedirectsToInvalidUrl(cls, *urls):
        return cls.getRegisteredRedirects(cls.invalid_urls, urls)
    
    @classmethod
    def getExpectedRedirectUrls(cls, urls):
        ''' Return a list of redirect urls for all of
        given urls
        
        :param urls: a sequence of Url instances
        :returns: a list of redirect url values expected
        as addresses of responses to all given values
        '''
        redirect_urls = []
        
        for u in urls:
            while u.location:
                if u.location in cls.invalid_urls:
                    break
                
                redirect_urls.append(u.location.value)
                u = u.location
                
        return redirect_urls
    
    @classmethod
    def setUpData(cls):
        
        ''' Types of urls causing different behaviour of valid_redirect_urls '''
        cls.missing_schema_urls = 'test.url1.com', 'test.url2.pl'
        cls.ftp_urls = 'ftp://test.url3.pl', 'ftp://test.url4.com'
        cls.invalid_urls = 'http://266.0.0.1', 'https://127.0.1.1.1', 'http://-test.url5.com'
        cls.http_urls = 'https://final.pl', 'http://125.123.223.1', 'http://[2001:db8:abc:125::45]'
        
        ''' maps of tested urls to their redirect locations '''
        
        
        def response_url_sequences(tag, last_urls):
            ''' Generate sequences of response url addresses to
            be used in testing
            
            :param tag: a tag value used for generating unique http urls
            :param last_urls: a sequence of urls to be put as the last in
            each sequence
            :returns: three response url sequences for each of last_urls:
            one sequence with three elements, one with two, and one
            with just one
            '''
            first = lambda i: 'http://{}.{}.com'.format(i, tag)
            redirect = lambda i: 'http://{}.{}.redirect.com'.format(i, tag)
            
            url_sequences = []
            
            i = 0
            
            for u in last_urls:
                url_sequences += (first(i), redirect(i), u), (first(i+1), u), (u,)
                
                i += 2
                
            return url_sequences
        
        cls.http_last = response_url_sequences('http', cls.http_urls)
        cls.ftp_last = response_url_sequences('ftp', cls.ftp_urls)
        invalid_last = response_url_sequences('invalid', cls.invalid_urls)
        cls.invalid_not_first = filter(lambda a: len(a) > 1, invalid_last)
        
    @classmethod
    def setUpClass(cls):
        cls.setUpData()
        
        session_mock = Mock(spec=['head', 'resolve_redirects'])
        
        session_mock.head.side_effect = cls.head
        session_mock.resolve_redirects.side_effect = cls.resolve_redirects
        
        cls.base_url_tester = BaseUrlTester(session_mock)
        
    @classmethod
    def get_location(cls, url):
        ''' Get content of Location header for response to given url 
        
        :param url: url value
        :returns: a location header value according to 
        the input data provided for the test
        '''
        for history_list in cls.http_last, cls.ftp_last, cls.invalid_not_first:
            for history in history_list:
                try: 
                    return history[history.index(url)+1]
                
                except ValueError: pass
                
                except IndexError:
                    return None
        return None
                
    @classmethod
    def head(cls, url):
        ''' Provides side effect for mocked requests.Session.head '''
        
        if url in cls.missing_schema_urls:
            raise MissingSchema
        
        elif url in cls.ftp_urls:
            raise InvalidSchema
        
        elif url in cls.invalid_urls:
                raise InvalidURL
            
        response = Mock(spec = ['request', 'url', 'headers'])
        response.headers = {}
        location = cls.get_location(url)
        if location:
            response.headers['location'] = location
        
        response.url = url
        return response
            
            
    @classmethod
    def resolve_redirects(cls, response, _):
        ''' Provides side effects for mocked requests.Session.resolve_redirects '''
        while 'location' in response.headers:
            response = cls.head(response.headers['location'])
            yield response
            
    @classmethod
    def get_redirect_slice(cls, histories):
        ''' Get a slice object for accessing expected resolved redirect urls
        appearing in histories listed in data
        
        :param histories: a sequence of histories. Each history is a sequence
        of url addresses of responses in response history of a request with the address
        being the first item of each history in histories
        '''
        
        if histories == cls.invalid_not_first:
            return slice(1, -1)
        return slice(1, None)
    
    def doTestResolveRedirects(self, histories):
        ''' Test resolve_redirects method for given data
        
        :param histories: a sequence of histories. Each history is a sequence
        of url addresses of responses in response history of a request with the address
        being the first item of each history in histories
        '''
        
        redirect_slice = self.get_redirect_slice(histories)

        for history in histories:
            url = history[0]
            expected = history[redirect_slice]
            
            actual_redirects = list(self.base_url_tester.resolve_redirects(url))
            
            self.assertItemsEqual(actual_redirects, expected)
            
    def testResolveRedirectsForTargetFtpUrl(self):
        ''' The responce history is expected to contain all the urls except
        the first one '''
        
        self.doTestResolveRedirects(self.ftp_last)
            
    def testResolveRedirectsForTargetInvalidUrl(self):
        ''' The response history is expected to contain all the addresses
        except the first one and the invalid last one '''
        self.doTestResolveRedirects(self.invalid_not_first)
            
    def testResolveRedirectsForTargetValidHttpUrl(self):
        ''' The response history is expected to contain all the addresses except
        the first one '''
        
        self.doTestResolveRedirects(self.http_last)
        
    def doTestResolveRedirectsForInvalidArguments(self, not_valid_urls):
        ''' Perform test for resolve_redirects for arguments that are not valid urls. 
        ValueError is expected to be raised
        
        :param not_valid_urls: a sequence of invalid url values
        '''
        for u in not_valid_urls:
            self.assertRaises(ValueError, lambda e: tuple(self.base_url_tester.resolve_redirects(e)), u)
        
    def testResolveRedirectsForInvalidUrls(self):
        ''' ValueError is expected to be raised '''
        self.doTestResolveRedirectsForInvalidArguments(self.invalid_urls)
            
    def testResolveRedirectsForMissingSchemaUrls(self):
        ''' ValueError is expected to be raised '''
        self.doTestResolveRedirectsForInvalidArguments(self.missing_schema_urls)
            
    def doTestUrlsToTest(self, histories):
        ''' Perform test of urls_to_test method for
        given list of url address response history 
        
        Test is performed for resolve_redirects = False
        
        :param histories: a sequence of histories. Each history is a sequence
        of url addresses of responses in response history of a request with the address
        being the first item of each history in histories
        '''
        urls = list(set(h[0] for h in histories))
        actual = list(self.base_url_tester.urls_to_test(urls))
        self.assertEqual(urls, actual)
            
    def testUrlsToTestForTargetHttpUrls(self):
        ''' The result is expected to be the same as the arguments '''
        
        self.doTestUrlsToTest(self.http_last)
        
    def testUrlsToTestForTargetFtpUrls(self):
        ''' The result is expected to be the same as the arguments '''
        self.doTestUrlsToTest(self.ftp_last)
        
    def testUrlsToTestForInvalidTargetUrl(self):
        ''' The result is expected to be the same as the arguments '''
        self.doTestUrlsToTest(self.invalid_not_first)
        
        
    def doTestUrlsToTestWithRedirectResolution(self, histories):
        ''' Perform test of urls_to_test method for
        given list of url address response history 
        
        Test is performed for resolve_redirects = True
        
        The actual is expected to contain the same elements as the expected.
        
        Also, urls that appear only as redirects, and not in the url values
        passed to the method, must follow all the urls passed to the
        method in the result
        
        :param histories: a sequence of histories. Each history is a sequence
        of url addresses of responses in response history of a request with the address
        being the first item of each history in histories
        '''
        
        urls = []
        url_set = set()
        redirect_set = set()
        
        redirect_slice = self.get_redirect_slice(histories)
        
        for h in histories:
            url = h[0]
            urls.append(url)
            url_set.add(url)
            redirect_set.update(h[redirect_slice])
            
        expected = url_set | redirect_set
        actual = list(self.base_url_tester.urls_to_test(urls, True))
        self.assertItemsEqual(expected, actual)
        
        redirect_indexes = map(actual.index, redirect_set - url_set)
        url_indexes = map(actual.index, url_set)
        
        for ui, ri in product(url_indexes, redirect_indexes):
            self.assertLess(ui, ri)
            
    def testUrlsToTestForTargetHttpUrlsAndRedirectResolution(self):
        ''' The result is expected to contain all the arguments and
        all redirect locations specified for them '''
        
        self.doTestUrlsToTestWithRedirectResolution(self.http_last)
        
    def testUrlsToTestForTargetFtpUrlsAndRedirectResolution(self):
        ''' The result is expected to contain all the arguments and
        all redirect locations specified for them '''
        
        self.doTestUrlsToTestWithRedirectResolution(self.ftp_last)
        
    def testUrlsToTestForInvalidTargetUrlAndRedirectResolution(self):
        ''' The result if expected to consist of all the arguments and their
        redirect location, except the last, invalid ones '''
        
        self.doTestUrlsToTestWithRedirectResolution(self.invalid_not_first)
        
    def doTestUrlsToTestForInvalidArguments(self, not_valid_urls, resolve_redirects):
        ''' Perform test of urls_to_test method for invalid url values, expecting
        ValueError to be raised 
        
        :param not_valid_urls: a sequence of invalid url values to be passed to urls_to_test
        :param resolve_redirects: if True: the test is performed for resolve_redirects = True
        '''
        
        function = lambda u: tuple(self.base_url_tester.urls_to_test((u,), resolve_redirects))
        
        for n in not_valid_urls:
            self.assertRaises(ValueError, function, n)
        
    def testUrlsToTestForInvalidUrls(self):
        ''' The urls_to_test method is expected to raise ValueError for invalid urls '''
        self.doTestUrlsToTestForInvalidArguments(self.invalid_urls, False)
        
    def testUrlsToTestForInvalidUrlsWithRedirectResolution(self):
        ''' The urls_to_test method is expected to raise ValueError for invalid urls '''
        self.doTestUrlsToTestForInvalidArguments(self.invalid_urls, True)
        
    def testUrlsToTestForMissingSchemaUrls(self):
        ''' The urls_to_test method is expected to raise ValueError for urls missing their schema part'''
        self.doTestUrlsToTestForInvalidArguments(self.missing_schema_urls, False)
        
    def testUrlsToTestForMissingSchemaUrlsWithRedirectResolution(self):
        ''' The urls_to_test method is expected to raise ValueError for urls missing their schema part'''
        self.doTestUrlsToTestForInvalidArguments(self.missing_schema_urls, True)
        
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()