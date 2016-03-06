#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import (UnknownCodeError, NXDOMAIN, HpHosts, 
                    GoogleSafeBrowsing, UnathorizedAPIKeyError, HostCollection,
                     SimpleClassificationCodeResolver, SumClassificationCodeResolver, Hostname, IpAddress, 
                     host, is_valid_url, RedirectUrlResolver, DNSBL, accepts_valid_urls, UrlTesterChain,
    AddressListItem, UrlHostTester)
from mock import Mock, patch, MagicMock

from requests.exceptions import HTTPError, InvalidSchema, InvalidURL,\
    ConnectionError, Timeout
from dns import reversename

from nose_parameterized import parameterized
from urlparse import urlparse, parse_qs

from test.base_test_cases import BaseHostListTest, BaseUrlTesterTest,\
ClientGetExpectedItemsProvider, TestFunctionForInvalidUrlProvider,\
IPv6SupportTest, GeneratedUrlTesterTest, TestFunctionDoesNotHandleProvider

from cachetools import lru_cache
from collections import defaultdict
from random import shuffle

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
        
class UrlHostTesterTest(
                        GeneratedUrlTesterTest,
                        BaseUrlTesterTest,
                        TestFunctionForInvalidUrlProvider,
                        ClientGetExpectedItemsProvider,
                        unittest.TestCase):
    
    def setUp(self):
          
        self.tested_instance = UrlHostTester()
          
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
          
        self.listed_hosts = []
          
        self.contains_patcher = patch('spambl.UrlHostTester.__contains__')
        self.contains_mock = self.contains_patcher.start()
        self.contains_mock.side_effect = lambda h: h in self.listed_hosts
          
        def lookup(h):
            if h in self.listed_hosts:
                return AddressListItem(
                                       h,
                                       self.tested_instance,
                                       self.classification
                                       )
            return None
          
        self.lookup_patcher = patch('spambl.UrlHostTester.lookup')
        self.lookup_mock = self.lookup_patcher.start()
        self.lookup_mock.side_effect = lookup
          
    def tearDown(self):
        self.is_valid_url_patcher.stop()
        self.contains_patcher.stop()
        self.lookup_patcher.stop()
          
    def _set_matching_urls(self, urls):
           
        listed_hosts = [urlparse(u).hostname for u in urls]
        self.listed_hosts = listed_hosts
          
    def _get_expected_items_for_urls(self, urls):
        hosts = [urlparse(u).hostname for u in urls]
        return self._get_expected_items(hosts)
        
class DNSBLTest(
                IPv6SupportTest,
                BaseHostListTest, 
                ClientGetExpectedItemsProvider,
                TestFunctionDoesNotHandleProvider,
                unittest.TestCase
                ):
     
    query_domain_str = 'test.query.domain'
     
    def setUp(self):
         
        self.classification_resolver = Mock()
        self.classification_resolver.return_value = self.classification
         
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = lru_cache()(lambda h: Mock())
         
        self.tested_instance = DNSBL('test_service', self.query_domain_str, 
                                   self.classification_resolver, self.host_factory_mock)
         
        self.dns_query_patcher = patch('spambl.query')
        self.dns_query_mock = self.dns_query_patcher.start()
        self.expected_query_names = []
        def dns_query(query_name):
            if query_name in self.expected_query_names:
                dns_answer_mock = Mock()
                dns_answer_mock.to_text.return_value = '121.0.0.1'
                return [dns_answer_mock]
            raise NXDOMAIN
        self.dns_query_mock.side_effect = dns_query
         
    def tearDown(self):
         
        self.dns_query_patcher.stop()
         
    def _set_matching_hosts(self, hosts):
         
        host_objects = [self.host_factory_mock(h) for h in hosts]
        self.expected_query_names = [h.relative_domain.derelativize() 
                                for h in host_objects]
        
    def _test_function_does_not_handle_unknown_code_error(self, function, *args, **kwargs):
        
        self._test_function_does_not_handle(
                                            UnknownCodeError,
                                            self.classification_resolver,
                                            function,
                                            *args,
                                            **kwargs
                                            )
        
    def test_lookup_does_not_handle_unknown_code_error(self):
        
        host = 'hostwithunknowncode.com'
        self._set_matching_hosts([host])
        self._test_function_does_not_handle_unknown_code_error(
                                                               self.tested_instance.lookup,
                                                               host
                                                               )
        
    def test_lookup_matching_does_not_handle_unknown_code_error(self):
        
        url = 'http://hostwithunknowncode.com'
        self._set_matching_hosts([urlparse(url).hostname])
        
        func = lambda u: list(self.tested_instance.lookup_matching(u))
        self._test_function_does_not_handle_unknown_code_error(
                                                               func,
                                                               [url]
                                                               )
        
class BaseClassificationCodeResolverTest(object):
    
    def setUp(self):
        self.code_item_class = {}
        self.resolver = self.factory(self.code_item_class)
        
class SimpleClassificationCodeResolverTest(
                                           BaseClassificationCodeResolverTest,
                                           unittest.TestCase
                                           ):
    
    factory = SimpleClassificationCodeResolver
        
    def test_call_for_valid_key(self):
        
        key = 4
        self.code_item_class.update({key: 'TestClass'})
        
        expected = self.code_item_class[key],
        actual = self.resolver(key)
        
        self.assertEqual(expected, actual)
            
    def test_call_for_invalid_key(self):
        
        self.assertRaises(UnknownCodeError, self.resolver, 4)
            
class SumClassificationCodeResolverTest(
                                        BaseClassificationCodeResolverTest,
                                        unittest.TestCase
                                        ):
    
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
        
def hp_hosts_host_factory(host_value):
    value = MagicMock()
    value.__str__.return_value = str(host_value)
    return  value

class HpHostsTest(
                  BaseHostListTest,
                  ClientGetExpectedItemsProvider,
                  unittest.TestCase
                  ):
    
    valid_ipv6 = '2001:ddd:ccc:111::33'
    
    @classmethod
    def setUpClass(cls):
         
        cls.tested_instance = HpHosts('spambl_test_suite')
        
    def _set_up_get_mock(self):
        classification = ','.join(self.classification)
        def get(url):
            query_string = urlparse(url).query
            query_data = parse_qs(query_string)
             
            content = 'Not listed'
            if query_data['s'][0] in self.listed_hosts:
                content = 'Listed,{}'.format(classification)
                 
            response = Mock()
            response.content = content
            return response
        
        self.get_patcher = patch('spambl.get')
        self.get_mock = self.get_patcher.start()
        self.get_mock.side_effect = get
        
    def setUp(self):
         
        self.listed_hosts = []
        
        self._set_up_get_mock()
         
        self.host_patcher = patch('spambl.host')
        self.host_factory_mock = self.host_patcher.start()
        self.host_factory_mock.side_effect = hp_hosts_host_factory
         
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
         
    def tearDown(self):
        self.get_patcher.stop()
        self.host_patcher.stop()
        self.is_valid_url_patcher.stop()
         
    def _set_matching_hosts(self, hosts):
        self.listed_hosts.extend(hosts)
    
    def _test_function_raises_value_error_for_valid_ipv6(self, function, ipv6_arg):
        
        self.assertRaises(ValueError, function, ipv6_arg)
        
    def test_contains_raises_value_error_for_valid_ipv6(self):
        
        self._test_function_raises_value_error_for_valid_ipv6(
                                                             self.tested_instance.__contains__,
                                                             self.valid_ipv6
                                                             )
        
    def test_lookup_raises_value_error_for_valid_ipv6(self):
        
        self._test_function_raises_value_error_for_valid_ipv6(
                                                             self.tested_instance.lookup,
                                                             self.valid_ipv6
                                                             )
    def _test_function_raises_value_error_for_valid_ipv6_url(self, function):
        
        url = 'http://[{}]'.format(self.valid_ipv6)
        
        self._test_function_raises_value_error_for_valid_ipv6(
                                                              function,
                                                              [url]
                                                              )
        
    def test_any_match_raises_value_error_for_valid_ipv6_url(self):
        
        self._test_function_raises_value_error_for_valid_ipv6_url(
                                                                  self.tested_instance.any_match
                                                                  )
        
    def test_lookup_matching_raises_value_error_for_valid_ipv6_url(self):
        
        function = lambda u: list(self.tested_instance.lookup_matching(u))
        
        self._test_function_raises_value_error_for_valid_ipv6_url(function)
        
class GoogleSafeBrowsingTest(
                             GeneratedUrlTesterTest,
                             BaseUrlTesterTest,
                             TestFunctionForInvalidUrlProvider,
                             ClientGetExpectedItemsProvider,
                             unittest.TestCase
                             ):
    
    def _get_expected_items_for_urls(self, urls):
        return self._get_expected_items(urls)
    
    @classmethod
    def setUpClass(cls):
        cls.tested_instance = GoogleSafeBrowsing('test_client', '0.1', 'test_key')
        
    def _set_up_post_mock(self):
        
        def post(_, body):
            response = Mock()
            if self._expecting_unathorized_api_key_error:
                response.status_code = 401
                response.raise_for_status.side_effect = HTTPError
                
            else:
                urls = body.splitlines()[1:]
                classes = [('ok' if u not in self._spam_urls else 
                       self.classification[0]) for u in urls]
                response.content = '\n'.join(classes)
                code = 200 if self._spam_urls else 204
                response.status_code = code
            
            return response
        
        self.post_patcher = patch('spambl.post')
        self.mocked_post = self.post_patcher.start()
        self.mocked_post.side_effect = post
        
    def setUp(self):
        self._spam_urls = []
        self._expecting_unathorized_api_key_error = False
        
        self._set_up_post_mock()
        
        self.is_valid_url_patcher = patch('spambl.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        
    def tearDown(self):
        self.post_patcher.stop()
        self.is_valid_url_patcher.stop()
        
    def _set_matching_urls(self, urls):
        self._spam_urls = urls
        
    def _test_for_unathorized_api_key(self, function):
        
        self._expecting_unathorized_api_key_error = True
        
        self.assertRaises(UnathorizedAPIKeyError, function, self.valid_urls)
        
    def test_any_match_for_unathorized_api_key(self):
        
        self._test_for_unathorized_api_key(self.tested_instance.any_match)
        
    def test_lookup_matching_for_unathorized_api_key(self):
        
        function = lambda u: list(self.tested_instance.lookup_matching(u))
        self._test_for_unathorized_api_key(function)
        
def host_collection_host_factory(h):
            host_object = MagicMock()
            host_object.__str__.return_value = h
            host_object.is_subdomain.return_value = False
            host_object.__eq__.return_value = False
            
            test = lambda h2: str(host_object) == str(h2)
            host_object.__eq__.side_effect = test
            host_object.is_subdomain.side_effect = test
                
            return host_object
        
class HostCollectionTest(
                         IPv6SupportTest,
                         BaseHostListTest,
                         ClientGetExpectedItemsProvider,
                         unittest.TestCase
                         ):
     
    valid_urls = ['http://test.com', 'http://127.33.22.11']
     
    def setUp(self):
         
        self.host_patcher = patch('spambl.host')
        self.host_factory_mock = self.host_patcher.start()
         
        self.host_factory_mock.side_effect = lru_cache()(host_collection_host_factory)
         
        self.classification = ('test_classification',)
        self.tested_instance = HostCollection('test_host_collection',
                                              self.classification)
         
    def tearDown(self):
        self.host_patcher.stop()
         
    @parameterized.expand(BaseHostListTest.invalid_host_input)
    def test_add_for_invalid(self, _, value):
         
        self._test_function_for_invalid(self.tested_instance.add, value)
         
    @parameterized.expand(BaseHostListTest.valid_host_input)
    def test_add_for_valid(self, _, value):
         
        self.tested_instance.add(value)
         
        in_host_collection = self.host_factory_mock(value) in self.tested_instance.hosts
         
        self.assertTrue(in_host_collection)
         
    def _set_matching_hosts(self, hosts):
        self.tested_instance.hosts = [self.host_factory_mock(h) for h in hosts]
         
    def _set_matching_urls(self, urls):
         
        listed_hosts = [urlparse(u).hostname for u in urls]
        self._set_matching_hosts(listed_hosts)
        
    @parameterized.expand(GeneratedUrlTesterTest.valid_url_list_input)
    def test_filter_matching_for(self, _, matching_urls):
         
        self._set_matching_urls(matching_urls)
        actual = self.tested_instance.filter_matching(self.valid_urls + matching_urls)
         
        self.assertItemsEqual(matching_urls, actual)
        
@lru_cache()
def get_url_tester_mock(identifier):
    source = Mock()
    source.identifier = identifier
    return source

class UrlTesterChainTest(
                         BaseUrlTesterTest,
                         unittest.TestCase
                         ):
    classification = ('TEST',)
    
    url_to_source_id ={
                       'http://55.44.21.12': ['source_1', 'source_2'],
                       'http://test.com': ['source_3'],
                       'https://abc.com': ['source_1'],
                       'http://[2001:ddd:ccc:111::22]': ['source_1', 'source_2'],
                       'http://[2001:abc:111:22::33]': ['source_3']
                       }
    
    def setUp(self):
        url_testers = []
        
        for _ in range(3):
            tester = Mock()
            tester.any_match.return_value = False
            tester.lookup_matching.return_value = []
            url_testers.append(tester)
        
        self.tested_instance = UrlTesterChain(*url_testers)
    
    def _add_url_tester(self, source_id, matching_urls):
        
        tester = get_url_tester_mock(source_id)
        any_match = lambda u: not set(u).isdisjoint(set(matching_urls))
        tester.any_match.side_effect = any_match
        
        url_items = [self._get_item(u, source_id) for u in matching_urls]
        tester.lookup_matching.return_value = url_items
        
        if not tester in self.tested_instance.url_testers:
            self.tested_instance.url_testers.append(tester)
    
    def _get_item(self, url, source_id):
        return AddressListItem(
                               url,
                               get_url_tester_mock(source_id),
                               self.classification
                               )
    
    def _get_expected_items_for_urls(self, urls):
        
        return [self._get_item(u, i) for u, ids in urls.items() for i in ids]
            
    def _set_matching_urls(self, urls):
        
        by_source_id = defaultdict(list)
        
        for u, ids in urls.items():
            for i in ids:
                by_source_id[i].append(u)
                
        for i, urls in by_source_id.items():
            self._add_url_tester(i, urls)
            
        shuffle(self.tested_instance.url_testers)
    
    def test_any_match_returns_true_for_matching_urls(self):
        
        self._test_any_match_returns_true_for(self.url_to_source_id)
        
    @parameterized.expand([
                             ('no_matching_url', {}),
                             ('matching_urls', url_to_source_id)
                             ])
    def test_lookup_matching_for(self, _, matching_urls):
        
        self._test_lookup_matching_for(matching_urls)
               
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