#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, 
                    IpDNSBL, DomainDNSBL, GeneralDNSBL,
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     CodeClassificationMap, SumClassificationMap, Hostname, IpAddress, 
                     host, is_valid_url, BaseUrlTester)
from mock import Mock, patch, MagicMock
from ipaddress import ip_address
from itertools import combinations, product

from collections import namedtuple

from urlparse import urlparse
from requests.exceptions import HTTPError, MissingSchema, InvalidSchema, InvalidURL
from dns import name

def relative_name(hostname):
    ''' Create an object representing partially qualified domain name 
    for given hostname
    
    :param host: a hostname
    :returns: dns.name.Name instance relative to the root
    '''
    return name.from_text(hostname).relativize(name.root) 

class BaseDNSBLTest(object):
    
    valid_hosts = ()
    invalid_hosts = ()
    factory = None
    
    @classmethod
    def setUpClass(cls):
        
        cls.query_domain_str = 'test.query.domain'
        cls.query_domain = name.from_text(cls.query_domain_str)
    
    def setUp(self):
        
        self.classification_map = MagicMock()
        
        self.dnsbl_service = self.factory('test_service', self.query_domain_str, self.classification_map)
        
        dns_answer_mock = Mock()
        self.dns_answer_string = dns_answer_mock.to_text.return_value = '121.0.0.1'
        
        self.patcher = patch('spambl.query')
        self.dns_query_mock = self.patcher.start()
        self.dns_query_mock.return_value = [dns_answer_mock]
    
    def doTestCallForInvalidArgs(self, function):
        ''' Perform test of a function that should raise ValueError for given data '''
        
        for h in self.invalid_hosts:
            self.assertRaises(ValueError, function, h)
        
    def testContainsForInvalidArgs(self):
        ''' The call should raise ValueError '''
        
        self.doTestCallForInvalidArgs(self.dnsbl_service.__contains__)
        
    def testLookupForInvalidArgs(self):
        ''' The call should raise ValueError '''
        
        self.doTestCallForInvalidArgs(self.dnsbl_service.lookup)
            
    def testContainsForListedValues(self):
        ''' __contains__ should return  true '''

        for h in self.valid_hosts:
            self.assertTrue(h in self.dnsbl_service)
        
    def testContainsForNotListedValues(self):
        ''' __contains__ should return  true '''
        
        self.dns_query_mock.side_effect = NXDOMAIN('Test NXDOMAIN')
        
        for h in self.valid_hosts:
            self.assertFalse(h in self.dnsbl_service)
            
    def testLookupForListedValues(self):
        ''' lookup method must return object with value equal to
        ip strings it was passed '''
        
        for h in self.valid_hosts:
            actual = self.dnsbl_service.lookup(h)
            self.assertEqual(actual.value, h)
            
    def testLookupForNotListedValues(self):
        ''' lookup method must return None  '''
        
        self.dns_query_mock.side_effect = NXDOMAIN('Test NXDOMAIN')
        
        for h in self.valid_hosts:
            actual = self.dnsbl_service.lookup(h)
            self.assertIsNone(actual)
            
    def testLookupForListedWithUnknownCodes(self,):
        ''' lookup method must raise UnknownCodeError '''
        
        self.classification_map.__getitem__.side_effect = UnknownCodeError('Unknown code error')
        
        for h in self.valid_hosts:
            self.assertRaises(UnknownCodeError, self.dnsbl_service.lookup, h)
        
    def tearDown(self):
        
        self.patcher.stop()
            
class IpDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    valid_hosts = u'255.0.120.1', u'2001:db8:abc:123::42'
    invalid_hosts = u't1.pl', u't2.com'
    factory = IpDNSBL
        
class DomainDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    valid_hosts = u't1.pl', u't2.com'
    invalid_hosts = u'255.0.120.1', u'2001:db8:abc:123::42', '-aaa'
    factory = DomainDNSBL
            
class GeneralDNSBLTest(BaseDNSBLTest, unittest.TestCase):
    
    valid_hosts = u't1.pl', u'255.0.120.1', u'2001:db8:abc:123::42'
    invalid_hosts = u'266.0.120.1', '/e'
    factory = GeneralDNSBL
    
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
        cls.valid_hosts = 't1.pl', u'255.255.0.1'
        cls.invalid_hosts = u'266.266.266.266', u'-test.host.pl'
        
        cls.hp_hosts = HpHosts('spambl_test_suite')
        
    def setUp(self):
        
        self.response = Mock()
        
        self.patcher = patch('spambl.get')
        self.get_mock = self.patcher.start()
        self.get_mock.return_value = self.response
    
    def testContainsForListedHosts(self):
        ''' For listed hosts, __contains__ should return True'''
        
        self.response.content = 'Listed, [TEST CLASS]'
        
        for host in self.valid_hosts:
            self.assertTrue(host in self.hp_hosts)
            
    def testContainsForNotListedHosts(self):
        ''' For not listed hosts, __contains__ should return False '''
        
        self.response.content = 'Not listed'
        
        for host in self.valid_hosts:
            self.assertFalse(host in self.hp_hosts)
            
    def testContainsForInvalidHosts(self):
        ''' For invalid hosts, __contains__ should raise a ValueError '''
        
        for val in self.invalid_hosts:
            self.assertRaises(ValueError, self.hp_hosts.__contains__, val)
                
    def testLookupForListedHosts(self):
        ''' For listed hosts, lookup should return an object representing it'''
        
        self.response.content = 'Listed, [TEST CLASS]'
        
        for host in self.valid_hosts:
            self.assertEqual(self.hp_hosts.lookup(host).value, host)
            
    def testLookupForNotListedHosts(self):
        ''' For not listed hosts, lookup should return None '''
        
        self.response.content = 'Not listed'
        
        for host in self.valid_hosts:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    def testLookupForInvalidHosts(self):
        ''' For invalid hosts, lookup should raise a ValueError '''
        
        for val in self.invalid_hosts:
            self.assertRaises(ValueError, self.hp_hosts.lookup, val)
            
    def tearDown(self):
        self.patcher.stop()

Url = namedtuple('Url', 'value location')
Url.__new__.__defaults__ = (None,)

def get_redirect_urls(urls):
    ''' Get a sequence of Url objects,
    each with .location assigned to the next one
    
    :param urls: a sequence of url values. If a value has no scheme,
    http is assumed
    :returns: a tuple containing instances of urls for given
    arguments
    '''
    
    result = []
    location = None
    
    for u in reversed(urls):
        if not urlparse(u).scheme:
            u = 'http://'+u
        
        url = Url(u, location)
        result.insert(0, url)
        location = result[0]
        
    return result

class GoogleSafeBrowsingTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.valid_urls = 'http://test.domain1.com', 'https://255.255.0.1', 
        'http://[2001:DB8:abc:123::42]', 'ftp://test.domain2.com'
        
        cls.google_safe_browsing = GoogleSafeBrowsing('test_client', '0.1', 'test_key')
        
    def setUp(self):
        self.patcher = patch('spambl.post')
        self.mocked_post = self.patcher.start()
        
        self.post_response = Mock()
        self.mocked_post.return_value = self.post_response
        
    def doTestForUnathorizedAPIKey(self, function):
        ''' function should raise UnathorizedAPIKeyError '''
        self.post_response.status_code = 401
        self.post_response.raise_for_status.side_effect = HTTPError
        
        self.assertRaises(UnathorizedAPIKeyError, function, self.valid_urls)
        
    def testContainsAnyForUnathorizedAPIKey(self):
        ''' contains_any should raise UnathorizedAPIKeyError '''
        self.doTestForUnathorizedAPIKey(self.google_safe_browsing.contains_any)
        
    def testLookupForUnathorizedAPIKey(self):
        ''' lookup should raise UnathorizedAPIKeyError '''
        self.doTestForUnathorizedAPIKey(self.google_safe_browsing.lookup)
    
    def testContainsAnyForAnySpamUrls(self):
        ''' contains_any should return True for a sequence containing spam urls'''
        
        self.post_response.status_code = 200
        
        actual = self.google_safe_browsing.contains_any(self.valid_urls)
        self.assertTrue(actual)
        
    def testContainsAnyForNonSpamUrls(self):
        ''' contains_any should return False for a sequence of non-spam urls'''
        self.post_response.status_code = 204
        
        actual = self.google_safe_browsing.contains_any(self.valid_urls)
        self.assertFalse(actual)
        
    def testLookupForAnySpamUrls(self):
        ''' lookup should return a sequence  of objects representing 
        all spam urls when called with sequence containing spam urls '''
        
        classifications = {
                           'http://test1.com': 'phishing', 
                           'http://test2.com': 'malware', 
                           'https://123.22.1.11': 'unwanted',
                           'http://[2001:DB8:abc:123::42]': 'phishing, malware',
                           'ftp://test3.com': 'phishing, unwanted', 
                           'http://test.domain.pl': 'malware,unwanted',
                           'http://test.domain2.com': 'phishing, malware, unwanted',
                           'https://domain3.com': 'ok'}
        
        def mocked_post(_, body):
            urls = body.splitlines()[1:]
            
            response = Mock()
            response.status_code = 200
            response.content = '\n'.join(classifications[u] for u in urls)
            
            return response
        
        self.mocked_post.side_effect = mocked_post
        
        actual = self.google_safe_browsing.lookup(classifications.keys())
        
        self.assertTrue(actual)
        
        for item in actual:
            self.assertEqual(item.source, self.google_safe_browsing)
            expected = classifications[item.value].split(',')
            self.assertEqual(item.classification, expected)
        
    def testLookupForNonSpamUrls(self):
        ''' lookup should return an empty tuple when called for a sequence
        of non spam urls as argument '''
        
        self.post_response.status_code = 204
        
        actual = self.google_safe_browsing.lookup(self.valid_urls)
        self.assertFalse(actual)

    def tearDown(self):
        self.patcher.stop()
        
class HostCollectionTest(unittest.TestCase):
    
    def setUp(self):
        self.listed_hosts = 'google.com', 'test1.pl', u'127.0.0.1', u'2001:db8:abc:123::42'
        self.not_listed_hosts = 'a.com', 'lorem.pl', u'255.0.0.1', u'2001:db8:abc:124::41'
        self.invalid_hosts = '-k', u'999.999.000.111.222'
        
        self.host_collection = HostCollection(self.listed_hosts)
        
    def testAddValidHost(self):
        ''' Adding a valid host should result in inclusion of an object representing it in collection '''
        
        for h in self.listed_hosts:
            self.host_collection.add(h)
            actual = any(str(h) == str(i) for i in self.host_collection.hosts)
            self.assertTrue(actual)
            
    def testAddInvalidHost(self):
        ''' Adding an invalid host should result in an error '''
        
        for k in self.invalid_hosts:
            self.assertRaises(ValueError, self.host_collection.add, k)
        
    def testContainsForListedValues(self):
        ''' __contains__ must return True for listed hosts '''
        for k in self.listed_hosts:
            self.assertTrue(k in self.host_collection)
            
    def testContainsForNotListedValues(self):
        ''' __contains__ must return False for not listed hosts '''
        for k in self.not_listed_hosts:
            self.assertFalse(k in self.host_collection)
            
    def testContainsForInvalidArguments(self):
        ''' __contains__ must raise ValueError for invalid arguments '''
        for k in self.invalid_hosts:
            self.assertRaises(ValueError, self.host_collection.__contains__, k)
            
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
    valid_http_urls = []
    valid_non_http_urls = []
    invalid_urls = []
    @classmethod
    def addRedirectUrls(cls, values, target_list = None):
        ''' Get a sequence of urls representing
        a sequence of redirects
        
        Each url is registered, and the last one is
        registered by adding it to specified list
        
        :param target_list: a list to which final target url is to
        be appended. If None, the final url is assumed to be a http url
        and added to proper list
        :param values: a sequence of values to add. If the values do not have
        scheme, http is assumed
        '''
        redirect_urls = get_redirect_urls(values)
        
        if target_list is None:
            target_list = cls.valid_http_urls
        
        target_list.append(redirect_urls[-1])
        
        cls.valid_http_urls.extend(redirect_urls[:-1])
        
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
        ''' Prepare all data to be used in testing
        
        Urls to be used in testing are represented by instances of Url class.
        
        Url objects have two properties:
        * value - which specifies url address represented by the object
        * location - which contains Url object representing address
        to which a request for url address from .value property redirects
        
        Url instances representing invalid url values, urls not supported
        by Requests library, or valid http urls that are to be final
        request targets, receive no location value
        '''
        
        host_sequences = (
                          ('testhost1.com', '220.125.111.8', '266.0.0.1'),
                          ('testhost2.com','[2001:db8:abc:125::45]', '127.0.1.1.1'),
                          ('sub.host3.pl', 'redirect3.pl', '-test.url5.com')
                          )
        
        for hs in host_sequences:
            cls.addRedirectUrls(hs, cls.invalid_urls)
        
        cls.addRedirectUrls(('test.host3.com', '122.144.111.1', 
                             'ftp://ftphost.com'), cls.valid_non_http_urls)
        
        cls.addRedirectUrls(('test.host4.com', '[2001:db8:abc:126::44]', 
                                                    'final.http.host'))
        
        cls.missing_schema_urls = map(Url, ('test.url1.com', 'test.url2.pl'))
        
    @property
    def valid_urls(self):
        return self.valid_http_urls + self.valid_non_http_urls

    @classmethod
    def setUpClass(cls):
        cls.setUpData()
        
        session_mock = Mock(spec=['head', 'resolve_redirects'])
        
        session_mock.head.side_effect = cls.head
        session_mock.resolve_redirects.side_effect = cls.resolve_redirects
        
        cls.base_url_tester = BaseUrlTester(session_mock)
                  
    @classmethod
    def head(cls, url):
        ''' Provides side effect for mocked requests.Session.head '''
        
        url_in = lambda l: url in (u.value for u in l)
        
        if url_in(cls.missing_schema_urls):
            raise MissingSchema
        
        elif url_in(cls.valid_non_http_urls):
            raise InvalidSchema
        
        elif url_in(cls.invalid_urls):
                raise InvalidURL
            
            
        registered = next(u for u in cls.valid_http_urls if u.value == url)
        response = Mock(spec = ['request', 'url', 'headers'])
        response.headers = {}
        
        if registered.location:
            response.headers['location'] = registered.location.value
        
        response.url = url
        
        return response
            
            
    @classmethod
    def resolve_redirects(cls, response, _):
        ''' Provides side effects for mocked requests.Session.resolve_redirects '''
        while 'location' in response.headers:
            response = cls.head(response.headers['location'])
            yield response
            
    def testResolveRedirects(self):
        ''' Each call to resolve_redirects is expected to
        return a sequence containing all url addresses of
        redirects resolved for given urls '''
        
        for url in self.valid_urls:
            
            expected = self.getExpectedRedirectUrls((url,))
            actual = list(self.base_url_tester.resolve_redirects(url.value))
            
            self.assertItemsEqual(actual, expected)
        
    def doTestResolveRedirectsForInvalidArguments(self, not_valid_urls):
        ''' Perform test for resolve_redirects for arguments that are not valid urls.
        ValueError is expected to be raised
        
        :param not_valid_urls: a sequence of invalid url values
        '''
        
        tested_method = self.base_url_tester.resolve_redirects
        function = lambda e: tuple(tested_method(e))
        
        for u in not_valid_urls:
            self.assertRaises(ValueError, function, u.value)
        
    def testResolveRedirectsForInvalidUrls(self):
        ''' ValueError is expected to be raised '''
        self.doTestResolveRedirectsForInvalidArguments(self.invalid_urls)
            
    def testResolveRedirectsForMissingSchemaUrls(self):
        ''' ValueError is expected to be raised '''
        self.doTestResolveRedirectsForInvalidArguments(self.missing_schema_urls)
            
    def testUrlsToTest(self):
        ''' The urls_to_test is expected to return a sequence
        of url values containing the same elements as the sequence
        of url values it received as argument
        
        Test is performed for resolve_redirects = False
        '''
        url_values = [u.value for u in self.valid_urls]
        actual = list(self.base_url_tester.urls_to_test(url_values))
        self.assertItemsEqual(url_values, actual)
        
    def testUrlsToTestWithRedirectResolution(self):
        ''' The urls_to_test is expected to return a sequence of
        values containing the same elements as a sum of:
        
        * a sequence of url values passed to the method
        * a sequence of url addresses of redirects resolved
        for given url values
        
        Test is performed for resolve_redirects = True
        
        Also, urls that appear only as redirects, and not in the url values
        passed to the method, must follow all the urls passed to the
        method in the result
        '''
        
        for u in self.valid_urls:
            urls = u.value,
            url_set = set(urls)
            
            redirects = self.getExpectedRedirectUrls((u,))
            expected_redirects = tuple(set(redirects) - url_set)
            
            expected = urls + expected_redirects
            actual = list(self.base_url_tester.urls_to_test(urls, True))
            
            self.assertItemsEqual(expected, actual)
            
            redirect_indexes = map(actual.index, expected_redirects)
            url_indexes = map(actual.index, url_set)
            
            for ui, ri in product(url_indexes, redirect_indexes):
                self.assertLess(ui, ri)
        
    def doTestUrlsToTestForInvalidArguments(self, not_valid_urls, resolve_redirects):
        ''' Perform test of urls_to_test method for invalid url values, expecting
        ValueError to be raised 
        
        :param not_valid_urls: a sequence of invalid url values to be passed to urls_to_test
        :param resolve_redirects: if True: the test is performed for resolve_redirects = True
        '''
        tested_method = self.base_url_tester.urls_to_test
        
        function = lambda u: tuple(tested_method((u,), resolve_redirects))
        
        for n in not_valid_urls:
            self.assertRaises(ValueError, function, n.value)
        
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