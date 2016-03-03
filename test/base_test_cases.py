# -*- coding: utf-8 -*-

from spambl import AddressListItem
from nose_parameterized import parameterized
from urlparse import urlparse

class BaseValueTesterTest(object):
    
    classification = ('TEST',)
    
    def _get_expected_items(self, values):
        item = lambda i: AddressListItem(i, self.tested_instance,
                                             self.classification)
        return [item(v) for v in values]


class BaseHostListTest(BaseValueTesterTest):
    ''' A common test case for all classes that represent
    a host list stored locally or by a remote service '''
    
    invalid_host_input = [
                          ('ipv4', u'255.0.120.1.1'),
                          ('ipv6', '2001:db8:abcef:123::42'),
                          ('host', '-aaa')
                          ]
    
    valid_host_input = [
                        ('ipv4', u'255.0.120.1'),
                        ('hostname', 'test.pl')
                        ]
    
    valid_ipv6 = '2001:ddd:ccc:111::33'
    
    __get_expected_items = BaseValueTesterTest._get_expected_items
    
    def _test_function_for_invalid(self, function, value):
        
        self.host_factory_mock.side_effect = ValueError
        self.assertRaises(ValueError, function, value)
        
    @parameterized.expand(invalid_host_input)
    def test_contains_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.tested_instance.__contains__, value)
        
    @parameterized.expand(invalid_host_input)
    def test_lookup_for_invalid(self, _, value):
        self._test_function_for_invalid(self.tested_instance.lookup, value)
        
    def _test_contains_for_listed(self, value):
        
        self._set_matching_hosts(value)
        self.assertTrue(value in self.tested_instance)
        
    def _test_contains_not_for_listed(self, value):
        
        self.assertFalse(value in self.tested_instance)
        
    def _test_lookup_for_listed(self, value):
        
        expected = self.__get_expected_items([value])[0]
        self._set_matching_hosts(value)
        self.assertEqual(self.tested_instance.lookup(value), expected)
        
    def _test_lookup_for_not_listed(self, value):
        
        self.assertIsNone(self.tested_instance.lookup(value))
        
    @parameterized.expand(valid_host_input)
    def test_contains_for_listed(self, _, value):
        self._test_contains_for_listed(value)
            
    @parameterized.expand(valid_host_input)
    def test_contains_for_not_listed(self, _, value):
        self._test_contains_not_for_listed(value)
                
    @parameterized.expand(valid_host_input)
    def test_lookup_for_listed(self, _, value):
        self._test_lookup_for_listed(value)
          
    @parameterized.expand(valid_host_input)  
    def test_lookup_for_not_listed(self, _, value):
        
        self._test_lookup_for_not_listed(value)

class HostListWithoutIpV6SupportTest(BaseHostListTest):
    ''' A test case for classes representing host list that
    raise an error when being queried for valid ip6 addresses '''
    
    def _test_function_raises_ValueError_for_valid_ipv6(self, function):
        
        self.assertRaises(ValueError, function, self.valid_ipv6)
        
    def test_contains_raises_ValueError_for_valid_ipv6(self):
        
        self._test_function_raises_ValueError_for_valid_ipv6(self.tested_instance.__contains__)
        
    def test_lookup_raises_ValueError_for_valid_ipv6(self):
        
        self._test_function_raises_ValueError_for_valid_ipv6(self.tested_instance.lookup)
        
class HostListTest(BaseHostListTest):
    ''' A test case for classes representing host lists
    that have support (or at least: do not raise errors)
    for ip6 addresses '''
    
    def test_contains_for_listed_ipv6(self):
        self._test_contains_for_listed(self.valid_ipv6)
            
    def test_contains_for_not_listed_ipv6(self):
        self._test_contains_not_for_listed(self.valid_ipv6)
        
    def test_lookup_for_listed_ipv6(self):
        self._test_lookup_for_listed(self.valid_ipv6)
          
    def test_lookup_for_not_listed_ipv6(self):
        self._test_lookup_for_not_listed(self.valid_ipv6)
        
class BaseUrlTesterTest(BaseValueTesterTest):
    ''' A common test case for classes supporting
    querying local resources or remote services for
    url addresses '''
    
    invalid_url_input = [
                         ('invalid_hostname', 'http://-abc.com'),
                         ('invalid_schema', 'abc://hostname.com'),
                         ('no_schema', 'hostname.com'),
                         ('invalid_ipv4', 'http://999.999.999.999'),
                         ('invalid_ipv4', 'http://127.0.0.0.1'),
                         ('invalid_ipv6', 'http://[2001:db8:abcef:123::42]'),
                         ('invalid_ipv6', 'http://[2001:db8:abch:123::42]')
                         ]
    
    valid_url_input = [
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('hostname_url', ['https://abc.com']),
                           ]
    
    valid_url_list_input = [
                             ('no_matching_url', []),
                             ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                             ]+valid_url_input
    
    
    valid_ipv6_urls = ['http://[2001:ddd:ccc:111::33]']
    
    valid_urls = ['http://test.com', 'http://127.33.22.11']
        
    @parameterized.expand(invalid_url_input)
    def test_any_match_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.tested_instance.any_match, invalid_url)
            
    @parameterized.expand(invalid_url_input)
    def test_lookup_matching_for_invalid(self, _, invalid_url):
        
        self._test_for_any_with_invalid(self.tested_instance.lookup_matching, invalid_url)
        
    def _test_any_match_returns_true_for(self, matching_urls):
        self._set_matching_urls(*matching_urls)
        self.assertTrue(self.tested_instance.any_match(self.valid_urls + matching_urls))
        
    def _test_any_match_returns_false(self, not_matching_urls):
        self.assertFalse(self.tested_instance.any_match(not_matching_urls))
        
    def _test_lookup_matching_for(self, matching_urls):
        expected = self._get_expected_items(matching_urls)
        
        self._set_matching_urls(*matching_urls)
        actual = list(self.tested_instance.lookup_matching(self.valid_urls + matching_urls))
        
        self.assertItemsEqual(expected, actual)
    
    @parameterized.expand(valid_url_input)
    def test_any_match_returns_true_for(self, _, matching_urls):
        
        self._test_any_match_returns_true_for(matching_urls)
        
    def test_any_match_returns_false(self):
        
        self._test_any_match_returns_false(self.valid_urls)
        
    @parameterized.expand(valid_url_list_input)
    def test_lookup_matching_for(self, _, matching_urls):
        
        self._test_lookup_matching_for(matching_urls)
        
    def _test_for_any_with_invalid(self, function, invalid_url):
        
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        with self.assertRaises(ValueError):
            function(self.valid_urls + [invalid_url])
        
class BaseUrlHostTesterTest(BaseUrlTesterTest):
    ''' A common test case for classes used
    to test hosts of given url addresses for items in
    local or remote lists '''
    
    def _get_expected_items(self, values):
        hosts = [urlparse(u).hostname for u in values]
        return super(BaseUrlHostTesterTest, self)._get_expected_items(hosts)
        
class UrlHostTesterWithoutIpV6SupportTest(BaseUrlHostTesterTest):
    ''' A test case for classes used
    to test hosts of given url addresses for items in
    local or remote lists, if the classes raise an error for given
    valid ip6 addresses'''
    
    def _test_function_raises_ValueError_for_valid_ipv6_url(self, function):
        
        self.assertRaises(ValueError, function, self.valid_ipv6_urls)
        
    def test_any_match_raises_ValueError_for_ipv6(self):
        
        self._test_function_raises_ValueError_for_valid_ipv6_url(self.tested_instance.any_match)
        
    def test_lookup_matching_raises_ValueError_for_ipv6(self):
        function = lambda u: list(self.tested_instance.lookup_matching(u))
        self._test_function_raises_ValueError_for_valid_ipv6_url(function)
        
class UrlTesterTest(BaseUrlTesterTest):
    '''
    A common test case for url testers supporting
    (or at least not raising errors for) ip6 addresses
    '''
    
    def test_any_match_returns_true_for_ipv6(self):
        
        self._test_any_match_returns_true_for(self.valid_ipv6_urls)
        
    def test_any_match_returns_false_for_ipv6(self):
        
        self._test_any_match_returns_false(self.valid_ipv6_urls)
        
    def test_lookup_matching_for_ipv6(self):
        
        self._test_lookup_matching_for(self.valid_ipv6_urls)
        
class UrlHostTesterTest(UrlTesterTest, BaseUrlHostTesterTest):
    ''' A test case for url testers that both support testing
    for urls using ipv6 addresses as their hosts and use
    hosts as criteria for detecting match '''
    
