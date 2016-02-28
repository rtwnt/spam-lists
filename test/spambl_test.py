#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, 
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     SimpleClassificationCodeResolver, SumClassificationCodeResolver, Hostname, IpAddress, 
                     host, is_valid_url, RedirectUrlResolver, AddressListItem, DNSBL, accepts_valid_urls)
from mock import Mock, patch, MagicMock

from requests.exceptions import HTTPError, InvalidSchema, InvalidURL,\
    ConnectionError, Timeout
from dns import reversename

from nose_parameterized import parameterized
from urlparse import urlparse, parse_qs
import contextlib
import validators

class AcceptValidUrlsTest(unittest.TestCase):
    
    def setUp(self):
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        
        function = Mock()
        function.__name__ = 'function'
        
        self.client = Mock()
        self.function = function
        self.decorated_function = accepts_valid_urls(self.function)
    
    def tearDown(self):
        self.is_valid_url_patcher.stop()
    
    @parameterized.expand([
                           ('hostname', 'https://valid.com'),
                           ('ipv4_host', 'http://122.34.59.109'),
                           ('ipv6_host', 'http://[2001:db8:abc:123::42]')
                           ])
    def test_accept_valid_urls_for_valid(self, _, url):
        self.decorated_function(self.client, url)
        self.function.assert_called_once_with(self.client, url)
    
    
    @parameterized.expand([
                           ('invalid_hostname', 'http://-abc.com'),
                           ('invalid_schema', 'abc://hostname.com'),
                           ('no_schema', 'hostname.com'),
                           ('invalid_ipv4', 'http://999.999.999.999'),
                           ('invalid_ipv4', 'http://127.0.0.0.1'),
                           ('invalid_ipv6', 'http://[2001:db8:abcef:123::42]'),
                           ('invalid_ipv6', 'http://[2001:db8:abch:123::42]')
                           ])
    def test_accept_valid_urls_for(self, _, url):
        self.is_valid_url_mock.return_value = False
        
        self.assertRaises(ValueError, self.decorated_function, self.client, url)
        self.function.assert_not_called()
        
class DNSBLTest(unittest.TestCase):
    
    valid_input = [('ipv4', u'255.0.120.1'), 
                   ('ipv6', u'2001:db8:abc:123::42'),
                   ('hostname', 'test.pl')]
    
    invalid_input = [('ipv4', u'255.0.120.1.1'), 
                   ('ipv6', u'2001:db8:abcef:123::42'),
                   ('host', '-aaa')]
    
    invalid_url_input = [
                         ('invalid_hostname', 'http://-abc.com'),
                         ('invalid_schema', 'abc://hostname.com'),
                         ('no_schema', 'hostname.com'),
                         ('invalid_ipv4', 'http://999.999.999.999'),
                         ('invalid_ipv4', 'http://127.0.0.0.1'),
                         ('invalid_ipv6', 'http://[2001:db8:abcef:123::42]'),
                         ('invalid_ipv6', 'http://[2001:db8:abch:123::42]')
                         ]
    
    single_valid_url_input = [
                              ('ipv6_url', 'http://[bbb:ccc:ddd:111::22]'),
                              ('ipv4_url', 'http://44.22.99.1'),
                              ('hostname_url', 'http://abc.com')
                              ]
    
    query_domain_str = 'test.query.domain'
    
    def setUp(self):
        
        self.classification_resolver = Mock()
        
        self.host_factory_mock = Mock()
        
        self.dnsbl_service = DNSBL('test_service', self.query_domain_str, 
                                   self.classification_resolver, self.host_factory_mock)
        
        dns_answer_mock = Mock()
        dns_answer_mock.to_text.return_value = '121.0.0.1'
        
        self.dns_query_patcher = patch('spambl.query')
        self.dns_query_mock = self.dns_query_patcher.start()
        self.dns_query_mock.return_value = [dns_answer_mock]
        
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        
    def tearDown(self):
        
        self.dns_query_patcher.stop()
        self.is_valid_url_patcher.stop()
    
    def _test_function_for_invalid(self, function, host):
        
        self.host_factory_mock.side_effect = ValueError
        self.assertRaises(ValueError, function, host)
       
    @parameterized.expand(invalid_input)
    def test_contains_for_invalid(self, _, host):
         
        self._test_function_for_invalid(self.dnsbl_service.__contains__, host)
        
    @parameterized.expand(invalid_input)
    def test_lookup_for_invalid(self, _, host):
        
        self._test_function_for_invalid(self.dnsbl_service.lookup, host)
            
    @parameterized.expand(valid_input)
    def test_contains_for_listed(self, _, host):
        
        self.assertTrue(host in self.dnsbl_service)
        
    @parameterized.expand(valid_input)
    def test_contains_for_not_listed(self, _, host):
        
        self.dns_query_mock.side_effect = NXDOMAIN
        
        self.assertFalse(host in self.dnsbl_service)
    
    @parameterized.expand(valid_input)
    def test_lookup_for_listed(self, _, host):
        
        classifications = ('TEST',)
        self.classification_resolver.return_value = classifications
        
        actual = self.dnsbl_service.lookup(host)
        expected = AddressListItem(host, self.dnsbl_service,
                                   classifications)
        
        self.assertEqual(expected, actual)
            
    @parameterized.expand(valid_input)
    def test_lookup_for_not_listed(self, _, host):
        
        self.dns_query_mock.side_effect = NXDOMAIN
        
        actual = self.dnsbl_service.lookup(host)
        
        self.assertIsNone(actual)
            
    @parameterized.expand(valid_input)
    def test_lookup_for_listed_with_unknown_codes(self, _, host):
        
        self.classification_resolver.side_effect = UnknownCodeError
        
        self.assertRaises(UnknownCodeError, self.dnsbl_service.lookup, host)
        
    def _test_for_any_with_invalid(self, function, invalid_url):
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        urls.append(invalid_url)
        
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        with self.assertRaises(ValueError):
                function(urls)
        
    @parameterized.expand(invalid_url_input)
    def test_any_match_for_any_with(self, _, invalid_url):
        
        function = self.dnsbl_service.any_match
        self._test_for_any_with_invalid(function, invalid_url)
                
    @parameterized.expand(invalid_url_input)
    def test_lookup_matching_for_any_with(self, _, invalid_url):
        
        function = self.dnsbl_service.lookup_matching
        self._test_for_any_with_invalid(function, invalid_url)
        
    @contextlib.contextmanager
    def matching_urls(self, urls):
        '''
        Provide a set up context manager assuming
        given urls are spam urls
        '''
        
        listed_hosts = [urlparse(u).hostname for u in urls]
        host_objects = {h: Mock() for h in listed_hosts}
        host_factory = lambda h: host_objects.get(h, Mock())
        self.host_factory_mock.side_effect = host_factory
        
        expected_query_names = [h.relative_domain.derelativize() 
                                for h in host_objects.values()]
        def dns_query(query_name):
            if query_name in expected_query_names:
                return self.dns_query_mock.return_value
            raise NXDOMAIN
        self.dns_query_mock.side_effect = dns_query
        
        yield
        
        self.host_factory_mock.side_effect = None
        self.dns_query_mock.side_effect = None
        
    @parameterized.expand(single_valid_url_input)
    def test_any_match_returns_true_for(self, _, url):
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]', url]
        with self.matching_urls([url]):
            self.assertTrue(self.dnsbl_service.any_match(urls))
        
    def test_any_match_returns_false(self):
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        
        self.dns_query_mock.side_effect = NXDOMAIN
        
        self.assertFalse(self.dnsbl_service.any_match(urls))
        
    @parameterized.expand([
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('ipv6_url', ['http://[2001:ddd:ccc:111::33]']),
                           ('hostname_url', ['https://abc.com']),
                           ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                           ])
    def test_lookup_matching_for(self, _, spam_urls):
        
        expected_type = ('TEST',)
        self.classification_resolver.return_value = expected_type
        expected_item = lambda h: AddressListItem(h, self.dnsbl_service,
                                                  expected_type)
        expected = [expected_item(urlparse(u).hostname) for u in spam_urls]
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        with self.matching_urls(spam_urls):
            actual = list(self.dnsbl_service.lookup_matching(urls+spam_urls))
        
        self.assertItemsEqual(expected, actual)
    
    @parameterized.expand(single_valid_url_input)
    def test_lookup_matching_with_unknow_codes(self, _, url):
        self.classification_resolver.side_effect = UnknownCodeError
        with self.assertRaises(UnknownCodeError):
            list(self.dnsbl_service.lookup_matching([url]))
    
class BaseClassificationCodeResolverTest(object):
    
    def setUp(self):
        self.code_item_class = {}
        self.resolver = self.factory(self.code_item_class)
        
class SimpleClassificationCodeResolverTest(BaseClassificationCodeResolverTest,
                                           unittest.TestCase):
    
    factory = SimpleClassificationCodeResolver
        
    def test_call_for_valid_key(self):
        
        key = 4
        self.code_item_class.update({key: 'TestClass'})
        
        expected = self.code_item_class[key],
        actual = self.resolver(key)
        
        self.assertEqual(expected, actual)
            
    def test_call_for_invalid_key(self):
        
        self.assertRaises(UnknownCodeError, self.resolver, 4)
            
class SumClassificationCodeResolverTest(BaseClassificationCodeResolverTest, 
                               unittest.TestCase):
    
    factory = SumClassificationCodeResolver
        
    def _set_code_item_class(self, code_class):
        self.code_item_class.update(code_class)
            
    @parameterized.expand([
                           ('simple_valid_key', [2]),
                           ('sum_of_keys', [2, 4, 8])
                           ])
    def test_getitem_for(self, _, keys):
        
        classes = {k: 'Class #{}'.format(k) for k in keys}
        self._set_code_item_class(classes)
        
        expected = tuple(classes.values())
        actual = self.resolver(sum(keys))
        
        self.assertItemsEqual(expected, actual)
        
    @parameterized.expand([
                           ('key', [16]),
                           ('sum_of_keys', [2, 4, 16])
                           ])
    def test_getitem_for_invalid(self, _, keys):
        
        self._set_code_item_class({2: 'Class: 2', 4: 'Class:4'})
        
        self.assertRaises(UnknownCodeError, self.resolver, sum(keys))
            
class HpHostsTest(unittest.TestCase):
    
    _classification = '[TEST CLASS]'
    
    valid_input = [
                   ('ipv4', u'255.255.0.1'),
                   ('hostname', 'test.hostname.pl')
                   ]
                   
    invalid_input = [
                     ('ipv4', u'255.255.0.1.11'),
                     ('ipv6', u'2001:DB8:abcde:123::42'),
                     ('hostname', '-e.pl')
                     ]
    
    invalid_url_input = [
                         ('invalid_hostname', 'http://-abc.com'),
                         ('invalid_schema', 'abc://hostname.com'),
                         ('no_schema', 'hostname.com'),
                         ('invalid_ipv4', 'http://999.999.999.999'),
                         ('invalid_ipv4', 'http://127.0.0.0.1'),
                         ('invalid_ipv6', 'http://[2001:db8:abcef:123::42]'),
                         ('invalid_ipv6', 'http://[2001:db8:abch:123::42]')
                         ]
    
    @classmethod
    def setUpClass(cls):
        
        cls.hp_hosts = HpHosts('spambl_test_suite')
        
    def setUp(self):
        
        self.get_patcher = patch('spambl.get')
        self.get_mock = self.get_patcher.start()
        
        self.host_patcher = patch('spambl.host')
        self.host_mock = self.host_patcher.start()
        
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        
    def tearDown(self):
        self.get_patcher.stop()
        self.host_patcher.stop()
        self.is_valid_url_patcher.stop()
        
    def _set_response_content(self, has_listed):
        
        content = 'Not listed'
        
        if has_listed:
            content = 'Listed,{}'.format(self._classification)
            
        self.get_mock.return_value.content = content
        
    def _test_function_for_invalid(self, function, value):
        
        self.host_mock.side_effect = ValueError
        self.assertRaises(ValueError, function, value)
        
    @parameterized.expand(invalid_input)
    def test_contains_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.hp_hosts.__contains__, value)
        
    @parameterized.expand(invalid_input)
    def test_lookup_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.hp_hosts.lookup, value)
        
    def _test_for_any_with_invalid(self, function, invalid_url):
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        urls.append(invalid_url)
        
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        with self.assertRaises(ValueError):
            function(urls)
        
    @parameterized.expand(invalid_url_input)
    def test_any_match_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.hp_hosts.any_match, invalid_url)
            
    @parameterized.expand(invalid_url_input)
    def test_lookup_matching_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.hp_hosts.lookup_matching, invalid_url)
        
    def _test_function_for_valid_ipv6(self, function):
        
        ipv6 = u'2001:DB8:abc:123::42'
        
        ipv6_host = MagicMock()
        ipv6_host.__str__.return_value = ipv6
        self.host_mock.return_value = ipv6_host
        
        self.assertRaises(ValueError, function, ipv6)
        
    def test_contains_for_valid_ipv6(self):
        
        self._test_function_for_valid_ipv6(self.hp_hosts.__contains__)
        
    def test_lookup_for_valid_ipv6(self):
        
        self._test_function_for_valid_ipv6(self.hp_hosts.lookup)
        
    def test_any_match_for_valid_ipv6(self):
        self._test_function_for_valid_ipv6(self.hp_hosts.any_match)
        
    def test_lookup_matching_for_valid_ipv6(self):
        
        func = lambda u: list(self.hp_hosts.lookup_matching(u))
        self._test_function_for_valid_ipv6(func)
        
    @parameterized.expand(valid_input)
    def test_contains_for_listed(self, _, value):
         
        self._set_response_content(True)
        self.assertTrue(host in self.hp_hosts)
            
    @parameterized.expand(valid_input)
    def test_contains_for_not_listed(self, _, value):
        
        self._set_response_content(False)
        self.assertFalse(host in self.hp_hosts)
                
    @parameterized.expand(valid_input)
    def test_lookup_for_listed(self, _, value):
        
        self._set_response_content(True)
        
        expected = AddressListItem(value, self.hp_hosts,
                                   (self._classification,))
        
        self.assertEqual(self.hp_hosts.lookup(value), expected)
          
    @parameterized.expand(valid_input)  
    def test_lookup_for_not_listed(self, _, value):
        
        self._set_response_content(False)
        self.assertIsNone(self.hp_hosts.lookup(value))
        
    @contextlib.contextmanager
    def matching_urls(self, urls):
        '''
        Provide a set up context manager assuming
        given urls are spam urls
        '''
        
        def host(host_value):
            value = MagicMock()
            value.__str__.return_value = host_value
            return  value
        
        self.host_mock.side_effect = host
        
        listed_hosts = [urlparse(u).hostname for u in urls]
        def get(url):
            query_string = urlparse(url).query
            query_data = parse_qs(query_string)
            
            content = 'Not listed'
            if query_data['s'][0] in listed_hosts:
                content = 'Listed,{}'.format(self._classification)
                
            response = Mock()
            response.content = content
            return response
            
        self.get_mock.side_effect = get
        
        yield
        
        self.get_mock.side_effect = None
        self.host_mock.side_effect = None
        
    @parameterized.expand([
                              ('ipv4_url', 'http://44.22.99.1'),
                              ('hostname_url', 'http://abc.com')
                              ])
    def test_any_match_returns_true_for(self, _, url):
        
        urls = ['http://test.com', 'http://127.33.22.11', url]
        with self.matching_urls([url]):
            self.assertTrue(self.hp_hosts.any_match(urls))
        
    def test_any_match_returns_false(self):
        
        urls = ['http://test.com', 'http://127.33.22.11']
        
        self._set_response_content(False)
        
        self.assertFalse(self.hp_hosts.any_match(urls))
        
    @parameterized.expand([
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('hostname_url', ['https://abc.com']),
                           ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                           ])
    def test_lookup_matching_for(self, _, spam_urls):
        
        expected_item = lambda h: AddressListItem(h, self.hp_hosts,
                                                  (self._classification,))
        expected = [expected_item(urlparse(u).hostname) for u in spam_urls]
        
        urls = ['http://test.com', 'http://127.33.22.11']
        with self.matching_urls(spam_urls):
            actual = list(self.hp_hosts.lookup_matching(urls+spam_urls))
        
        self.assertItemsEqual(expected, actual)

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
        
    def tearDown(self):
        self.patcher.stop()
        
    def _test_for_unathorized_api_key(self, function):
        
        self.post_response.status_code = 401
        self.post_response.raise_for_status.side_effect = HTTPError
        
        self.assertRaises(UnathorizedAPIKeyError, function, self.valid_urls)
        
    def test_contains_any_for_unathorized_api_key(self):
        
        self._test_for_unathorized_api_key(self.google_safe_browsing.contains_any)
        
    def test_lookup_for_unathorized_api_key(self):
        
        function = lambda u: list(self.google_safe_browsing.lookup(u))
        self._test_for_unathorized_api_key(function)
    
    def test_contains_any_for_any_spam_urls(self):
        
        self.post_response.status_code = 200
        
        actual = self.google_safe_browsing.contains_any(self.valid_urls)
        self.assertTrue(actual)
        
    def test_contains_any_for_no_spam_urls(self):
        
        self.post_response.status_code = 204
        
        actual = self.google_safe_browsing.contains_any(self.valid_urls)
        self.assertFalse(actual)
        
    def _set_post_result(self, classification):
        def mocked_post(_, body):
            urls = body.splitlines()[1:]
            classes = [classification.get(u, 'ok') for u in urls]
            
            response = Mock()
            response.status_code = 200
            response.content = '\n'.join(classes)
            
            return response
        
        self.mocked_post.side_effect = mocked_post
        
    @parameterized.expand([
                           ('hostname_urls',
                            { 
                             'http://test1.com': 'phishing',
                             'http://test2.com': 'malware'
                             }),
                           ('ipv4_urls',
                            {
                             'https://123.22.1.11': 'unwanted',
                             'http://66.99.88.121': 'phishing, malware'
                             }),
                           ('ipv6_urls',
                            {
                             'http://[2001:DB8:abc:123::42]': 'phishing, malware',
                             'http://[3731:54:65fe:2::a7]': 'phishing, unwanted'
                             }),
                           ('urls_with_duplicates',
                            {
                             'http://abc.com': 'malware, unwanted',
                             'http://domain.com': 'phishing, malware, unwanted'
                             }, 
                            ['http://abc.com'])
                           ])
    def test_lookup_for_spam(self, _, classification, duplicates = []):
        
        self._set_post_result(classification)
        
        item = lambda url, classes: AddressListItem(url, 
                                                    self.google_safe_browsing, 
                                                    tuple(classes.split(',')))
        
        expected  = [item(u, c) for u, c in classification.items()]
        
        non_spam = ['http://nospam.com', 'https://nospam2.pl', 'https://spamfree.com']
        tested = classification.keys()+ duplicates + non_spam
        actual = list(self.google_safe_browsing.lookup(tested))
        
        self.assertItemsEqual(actual, expected)
        
    def test_lookup_for_no_spam(self):
        ''' lookup should return an empty tuple when called for a sequence
        of non spam urls as argument '''
        
        self.post_response.status_code = 204
        
        actual = list(self.google_safe_browsing.lookup(self.valid_urls))
        self.assertFalse(actual)
        
class HostCollectionTest(unittest.TestCase):
    
    valid_host_parameters = [
                     ('host', 'test1.pl'),
                     ('ipv4', u'127.0.0.1'),
                     ('Ipv6', u'2001:db8:abc:123::42')
                     ]
    
    invalid_host_parameters = [
                           ('host', '-e'),
                           ('Ipv4', u'999.999.000.111.222'),
                           ('Ipv6', u'2001:db8:abcef:124::41')
                           ]
    
    single_valid_url_input = [
                              ('ipv6_url', 'http://[bbb:ccc:ddd:111::22]'),
                              ('ipv4_url', 'http://44.22.99.1'),
                              ('hostname_url', 'http://abc.com')
                              ]
    
    invalid_url_input = [
                         ('invalid_hostname', 'http://-abc.com'),
                         ('invalid_schema', 'abc://hostname.com'),
                         ('no_schema', 'hostname.com'),
                         ('invalid_ipv4', 'http://999.999.999.999'),
                         ('invalid_ipv4', 'http://127.0.0.0.1'),
                         ('invalid_ipv6', 'http://[2001:db8:abcef:123::42]'),
                         ('invalid_ipv6', 'http://[2001:db8:abch:123::42]')
                         ]
    
    def setUp(self):
        
        self.host_patcher = patch('spambl.host')
        self.host_mock = self.host_patcher.start()
        
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        
        self.host_collection = HostCollection('test_host_collection',
                                              ('test_classification',))
        
    def tearDown(self):
        self.host_patcher.stop()
        self.is_valid_url_patcher.stop()
        
    def _test_function_for_invalid(self, function, value):
        
        self.host_mock.side_effect = ValueError
        
        self.assertRaises(ValueError, function, value)
        
    @parameterized.expand(invalid_host_parameters)
    def test_add_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.host_collection.add, value)
        
    @parameterized.expand(invalid_host_parameters)
    def test_contains_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.host_collection.__contains__, value)
        
    @parameterized.expand(invalid_host_parameters)
    def test_lookup_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.host_collection.lookup, value)
        
    def _test_for_any_with_invalid(self, function, invalid_url):
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        urls.append(invalid_url)
        
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        with self.assertRaises(ValueError):
            function(urls)
        
    @parameterized.expand(invalid_url_input)
    def test_any_match_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.host_collection.any_match, invalid_url)
            
    @parameterized.expand(invalid_url_input)
    def test_lookup_matching_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.host_collection.lookup_matching, invalid_url)
        
    @parameterized.expand(valid_host_parameters)
    def test_add_for_valid(self, _, value):
        
        new_item = Mock()
        self.host_mock.return_value = new_item
        
        self.host_collection.add(value)
        
        in_host_collection = new_item in self.host_collection.hosts
        
        self.assertTrue(in_host_collection)
        
    @parameterized.expand(valid_host_parameters)
    def test_contains_for_listed(self, _, value):
        
        self.host_collection.hosts = [Mock()]
        
        self.assertTrue(value in self.host_collection)
        
    @parameterized.expand(valid_host_parameters)
    def test_contains_for_not_listed(self, _, value):
        
        self.assertFalse(value in self.host_collection)
        
    @parameterized.expand(valid_host_parameters)
    def test_lookup_for_listed(self, _, value):
        
        listed = MagicMock()
        listed.__str__.return_value = value
        self.host_collection.hosts = [listed]
        
        expected = AddressListItem(value, self.host_collection,
                                   self.host_collection.classification)
        actual = self.host_collection.lookup(value)
        
        self.assertEqual(expected, actual)
        
    @parameterized.expand(valid_host_parameters)
    def test_lookup_for_not_listed(self, _, value):
        
        self.host_mock.return_value.is_parent_or_the_same.return_value = False
        
        actual = self.host_collection.lookup(value)
        
        self.assertIsNone(actual)
        
    @contextlib.contextmanager
    def matching_urls(self, urls):
        '''
        Provide a set up context manager assuming
        given urls are spam urls
        '''
        
        def host(h):
            host_object = MagicMock()
            host_object.__str__.return_value = h
            host_object.is_subdomain.return_value = False
            host_object.__eq__.return_value = False
            
            test = lambda h2: str(host_object) == str(h2)
            
            if validators.ipv4(h) or validators.ipv6(h):
                host_object.__eq__.side_effect = test
            else:
                host_object.is_subdomain.side_effect = test
                
            return host_object
        
        self.host_mock.side_effect = host
        
        listed_hosts = [urlparse(u).hostname for u in urls]
        self.host_collection.hosts = [host(h) for h in listed_hosts]
        
        yield
        
        self.host_mock.side_effect = None
        self.host_collection.hosts = []
        
    @parameterized.expand(single_valid_url_input)
    def test_any_match_returns_true_for(self, _, url):
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]', url]
        with self.matching_urls([url]):
            self.assertTrue(self.host_collection.any_match(urls))
        
    def test_any_match_returns_false(self):
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        self.assertFalse(self.host_collection.any_match(urls))
        
    @parameterized.expand([
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('ipv6_url', ['http://[2001:ddd:ccc:111::33]']),
                           ('hostname_url', ['https://abc.com']),
                           ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                           ])
    def test_lookup_matching_for(self, _, spam_urls):
        
        expected_item = lambda h: AddressListItem(h, self.host_collection,
                                                  self.host_collection.classification)
        expected = [expected_item(urlparse(u).hostname) for u in spam_urls]
        
        urls = ['http://test.com', 'http://127.33.22.11',
                'http://[2001:db8:abc:123::42]']
        with self.matching_urls(spam_urls):
            actual = list(self.host_collection.lookup_matching(urls+spam_urls))
        
        self.assertItemsEqual(expected, actual)
        
            
class HostnameTest(unittest.TestCase):
    
    non_equal_input = [
                       ('unrelated_domain', Hostname('other.com')),
                       ('a_subdomain', Hostname('subdomain.hostname.pl')),
                       ('non_hostname_object', '123.4.5.11')
                       ]
    
    hostname_pl = Hostname('hostname.pl')
    
    subdomain_hostname_pl = Hostname('subdomain.hostname.pl')
    
    @parameterized.expand([
                           ('hostname', '-e'),
                           ('hostname', '/e'),
                           ('argument', 123)
                           ])
    def test_constructor_for_invalid(self, _, value):
        
        self.assertRaises(ValueError, Hostname, value)
        
    def test_eq_returns_true(self):
        
        h_2 = Hostname(str(self.hostname_pl))
        
        self.assertTrue(self.hostname_pl == h_2)
        
    @parameterized.expand(non_equal_input)
    def test_eq_returns_false_for(self, _, other):
        
        self.assertFalse(self.hostname_pl == other)
        
    @parameterized.expand(non_equal_input)
    def test_ne_returns_true_for(self, _, other):
        
        self.assertTrue(self.hostname_pl != other)
        
    def test_ne_returns_false(self):
        
        h_2 = Hostname(str(self.hostname_pl))
        
        self.assertFalse(self.hostname_pl != h_2)
        
    @parameterized.expand([
                           ('the_same_domain', 'subdomain.hostname.pl'),
                           ('a_superdomain', 'hostname.pl')
                           ])
    def test_is_subdomain_returns_true_for(self, _, other):
        
        h_2 = Hostname(other)
        
        self.assertTrue(self.subdomain_hostname_pl.is_subdomain(h_2))
        
    @parameterized.expand(non_equal_input)
    def test_is_subdomain_returns_false_for(self, _, other):
        
        self.assertFalse(self.hostname_pl.is_subdomain(other))

class IpAddressTest(unittest.TestCase):
    ipv4_1 = IpAddress(u'255.0.2.1')
    ipv4_2 = IpAddress(u'122.44.55.99')
    ipv6_1 = IpAddress(u'2001:db8:abc:123::42')
    ipv6_2 = IpAddress(u'fe80::0202:b3ff:fe1e:8329')
    
    the_same_ip_input = [
                           ('v4', ipv4_1),
                           ('v6', ipv6_1)
                           ]
    
    non_equal_input = [
                       ('different_ips_v4', ipv4_1, ipv4_2),
                       ('different_ips_v4', ipv4_2, ipv4_1),
                       ('ip4_and_ipv6', ipv4_1, ipv6_1),
                       ('different_ips_v6', ipv6_1, ipv6_2),
                       ('different_ips_v6', ipv6_2, ipv6_1),
                       ('Ipv6_and_ipv4', ipv6_1, ipv4_1),
                       ('ipv4_and_non_ip', ipv4_1, 'value'),
                       ('ipv6_and_non_ip', ipv6_1, 'value')
                       ]
    
    @parameterized.expand([
                           ('ipv4', u'299.0.0.1'),
                           ('ipv4', u'99.22.33.1.23'),
                           ('ipv6', u'2001:db8:abc:125::4h'),
                           ('ipv6', u'2001:db8:abcef:125::43'),
                           ('hostname', u'abc.def.gh'),
                           ('non_unicode_ipv4', '299.0.0.1')
                           ])
    def test_constructor_for_invalid(self, _, value):
        
        self.assertRaises(ValueError, IpAddress, value)
        
        
    @parameterized.expand([
                           ('v4', ipv4_1, reversename.ipv4_reverse_domain),
                           ('v6', ipv6_1, reversename.ipv6_reverse_domain)
                           ])
    def test_relative_domain_for_ip(self, _, value, expected_origin):
        
        reversed_name = reversename.from_address(str(value))
        expected = reversed_name.relativize(expected_origin)
        
        self.assertEqual(expected, value.relative_domain)
        
    @parameterized.expand([
                           ('the_same_ipv4', ipv4_1, ipv4_1),
                           ('the_same_ipv6', ipv6_1, ipv6_1)
                           ] + non_equal_input)
    def test_is_subdomain(self, _, value_1, value_2):
        
        self.assertFalse(value_1.is_subdomain(value_2))
        
    @parameterized.expand(the_same_ip_input)
    def test_eq_returns_true_for_the_same_ip(self, _, ip_1):
        
        ip_2 = IpAddress(unicode(ip_1))
        
        self.assertTrue(ip_1 == ip_2)
    
    @parameterized.expand(non_equal_input)
    def test_eq_returns_false_for(self, _, value_1, value_2):
        
        self.assertFalse(value_1 == value_2)
    
    @parameterized.expand(non_equal_input)
    def test_ne_returns_true_for(self, _, value_1, value_2):
        
        self.assertTrue(value_1 != value_2)
    
    @parameterized.expand(the_same_ip_input)
    def test_ne_returns_false_for_the_same_ip(self, _, ip_1):
        
        ip_2 = IpAddress(unicode(ip_1))
        self.assertFalse(ip_1 != ip_2)
        
class HostTest(unittest.TestCase):
    
    def setUp(self):
        
        self.ipaddress_patcher = patch('spambl.IpAddress')
        self.ipaddress_mock = self.ipaddress_patcher.start()
        
        self.hostname_patcher = patch('spambl.Hostname')
        self.hostname_mock = self.hostname_patcher.start()
        
    def tearDown(self):
        self.ipaddress_patcher.stop()
        self.hostname_patcher.stop()
        
    @parameterized.expand([
                           ('v4',  u'127.0.0.1'),
                           ('v6', u'2001:db8:abc:125::45'),
                           ])
    def test_host_for_ip(self, _, value):
        ip_address = Mock()
        self.ipaddress_mock.return_value = ip_address
        
        actual_ip = host(value)
        
        self.assertEqual(ip_address, actual_ip)
        
    def test_host_for_hostname(self):
        
        hostname_str = 'test.hostname'
        
        hostname_mock = Mock()
        self.hostname_mock.return_value = hostname_mock
        
        self.ipaddress_mock.side_effect = ValueError
        
        actual_hostname = host(hostname_str)
        
        self.assertEqual(hostname_mock, actual_hostname)
        
    @parameterized.expand([
                           ('ipv4', u'299.0.0.1'),
                           ('ipv4', u'99.22.33.1.23'),
                           ('ipv6', u'2001:db8:abc:125::4h'),
                           ('ipv6', u'2001:db8:abcef:125::43'),
                           ('hostname', '-e'),
                           ('hostname', '/e')
                           ])
    def test_host_for_invalid(self, _, value):
        
        self.hostname_mock.side_effect = ValueError
        self.ipaddress_mock.side_effect = ValueError
        
        self.assertRaises(ValueError, host, value)
          
class IsValidUrlTest(unittest.TestCase):
    
    @parameterized.expand([
                           ('http_scheme', 'http://test.url.com'),
                           ('https_scheme', 'https://google.com'),
                           ('ftp_scheme', 'ftp://ftp.test.com'),
                           ('numeric_hostname', 'http://999.com'),
                           ('final_slash', 'https://google.com/'),
                           ('path_query_and_fragment', 'https://test.domain.com/path/element?var=1&var_2=3#fragment'),
                           ('query', 'http://test.domain.com?var_1=1&var_2=2'),
                           ('path', 'http://test.domain.com/path'),
                           ('path_and_fragment', 'http://test.domain.com/path#fragment'),
                           ('query_and_fragment', 'http://test.domain.com?var_1=1&var_2=2#fragment'),
                           ('port', 'https://test.domain.com:123'),
                           ('authentication', 'https://abc:def@test.domain.com'),
                           ('ipv4', 'http://255.0.0.255'),
                           ('ipv6', 'http://[2001:db8:abc:125::45]')
                           ])
    def test_is_valid_url_for_url_with(self, _, url):
        self.assertTrue(is_valid_url(url))
             
    @parameterized.expand([
                           ('no_schema', 'test.url.com'),
                           ('invalid_ipv4', 'http://266.0.0.266'),
                           ('invalid_ipv6', 'http://127.0.0.1.1'),
                           ('invalid_port', 'http://test.domain.com:aaa'),
                           ('no_top_level_domain', 'https://testdomaincom'),
                           ('invalid_hostname', 'http://-invalid.domain.com')
                           ])
    def test_is_valid_url_for_invalid_url_with(self, _, url):
        self.assertFalse(is_valid_url(url))
            
class RedirectUrlResolverTest(unittest.TestCase):
    
    valid_urls = ['http://first.com', 'http://122.55.33.21',
    'http://[2001:db8:abc:123::42]']
    
    def setUp(self):
        
        session_mock = Mock()
        
        self.head_mock = session_mock.head
        self.resolve_redirects_mock = session_mock.resolve_redirects
        
        self.resolver = RedirectUrlResolver(session_mock)
        
        self.patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.patcher.start()
        
    def tearDown(self):
        
        self.patcher.stop()
        
    def test_get_first_response_for_invalid_url(self):
        
        self.is_valid_url_mock.return_value = False
        
        self.assertRaises(ValueError, self.resolver.get_first_response, 'http://test.com')
        
    @parameterized.expand([
                           ('ConnectionError', ConnectionError),
                           ('InvalidSchema', InvalidSchema),
                           ('Timeout', Timeout)
                           ])
    def test_get_first_response_for_url_triggering(self, _, exception_type):
        
        self.head_mock.side_effect = exception_type
        self.assertIsNone(self.resolver.get_first_response('http://test.com'))
        
    def test_get_redirect_urls_for_invalid_url(self):
        
        self.is_valid_url_mock.return_value = False
        
        with self.assertRaises(ValueError):
            self.resolver.get_redirect_urls('http://test.com').next()
        
    @parameterized.expand([
                           ('ConnectionError', ConnectionError),
                           ('InvalidSchema', InvalidSchema),
                           ('Timeout', Timeout)
                           ])
    def test_get_redirect_urls_for_first_url_triggering(self, _, exception_type):
        
        self.head_mock.side_effect = exception_type
        
        url_generator = self.resolver.get_redirect_urls('http://test.com')
        
        self.assertFalse(list(url_generator))
            
    def _get_response_mocks(self, urls):
        
        response_mocks = []
        
        for u in urls:
            response = Mock()
            response.url = u
            response_mocks.append(response)
            
        return response_mocks
    
    def _set_session_resolve_redirects_side_effects(self, urls, exception_type=None):
        
        if not (exception_type is None or 
                issubclass(exception_type, Exception)):
            raise ValueError, '{} is not a subclass of Exception'.format(exception_type)
        
        self._response_mocks = self._get_response_mocks(urls)
        
        def resolve_redirects(response, request):
            for r in self._response_mocks:
                yield r
                
            if exception_type:
                raise exception_type
                
        self.resolve_redirects_mock.side_effect = resolve_redirects
        
    def _set_last_response_location_header(self, url):
        
        all_responses = [self.head_mock.return_value] + self._response_mocks
        all_responses[-1].headers = {'location': url}
    
    def _test_get_redirect_urls(self, expected):
        
        url_generator = self.resolver.get_redirect_urls('http://test.com')
        
        self.assertEqual(expected, list(url_generator))
        
    @parameterized.expand([
                           ('no_url', []),
                           ('urls', valid_urls)
                           ])
    def test_get_redirect_urls_yields(self, _, expected):
        
        self._set_session_resolve_redirects_side_effects(expected)
        
        self._test_get_redirect_urls(expected)
        
    @parameterized.expand([
                           ('Timeout', [], Timeout),
                           ('Timeout', valid_urls, Timeout),
                           ('ConnectionError', [], ConnectionError),
                           ('ConnectionError', valid_urls, ConnectionError),
                           ('InvalidSchema', [], InvalidSchema),
                           ('InvalidSchema', valid_urls, InvalidSchema),
                           ])
    def test_get_redirect_urls_until(self, _, expected, exception_type):
        
        self._set_session_resolve_redirects_side_effects(expected, exception_type)
        
        error_source = 'http://triggered.error.com'
        expected.append(error_source)
        
        self._set_last_response_location_header(error_source)
            
        self._test_get_redirect_urls(expected)
        
    @parameterized.expand([
                           ('InvalidURL', [], InvalidURL),
                           ('InvalidURL', valid_urls, InvalidURL),
                           ('ConnectionError', [], ConnectionError),
                           ('ConnectionError', valid_urls, ConnectionError),
                           ('InvalidSchema', [], InvalidSchema),
                           ('InvalidSchema', valid_urls, InvalidSchema),
                           ])
    def test_get_redirect_urls_until_invalid_url_triggers(self, _, expected, exception_type):
        
        is_valid_url = lambda u: u in expected+['http://test.com']
        self.is_valid_url_mock.side_effect = is_valid_url
        
        self._set_session_resolve_redirects_side_effects(expected, exception_type)
        
        self._set_last_response_location_header('http://invalid.url.com')
            
        self._test_get_redirect_urls(expected)
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()