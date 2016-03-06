# -*- coding: utf-8 -*-

from spambl import AddressListItem
from nose_parameterized import parameterized

class ClientGetExpectedItemsProvider(object):
    '''
    Provides implementation of _get_expected_items
    for test cases testing method of a client
    
    Clients communicate directly with services, remote
    or local, and their instances are provided in
    AddressListItem instances as values of
    their .source property
    '''
    classification = ('TEST',)
    
    def _get_expected_items(self, values):
        item = lambda i: AddressListItem(i, self.tested_instance,
                                             self.classification)
        return [item(v) for v in values]


class BaseHostListTest(object):
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
        
        self._set_matching_hosts([value])
        self.assertTrue(value in self.tested_instance)
        
    def _test_contains_not_for_listed(self, value):
        
        self.assertFalse(value in self.tested_instance)
        
    def _test_lookup_for_listed(self, value):
        
        expected = self._get_expected_items([value])[0]
        self._set_matching_hosts([value])
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

class NoIPv6SupportTest(object):
    ''' A test case for classes representing host list that
    raise an error when being queried for valid IPv6 addresses '''
    
    valid_ipv6 = '2001:ddd:ccc:111::33'
    
    def _test_function_raises_ValueError_for_valid_ipv6(self, function):
        
        self.assertRaises(ValueError, function, self.valid_ipv6)
        
    def test_contains_raises_ValueError_for_valid_ipv6(self):
        
        self._test_function_raises_ValueError_for_valid_ipv6(self.tested_instance.__contains__)
        
    def test_lookup_raises_ValueError_for_valid_ipv6(self):
        
        self._test_function_raises_ValueError_for_valid_ipv6(self.tested_instance.lookup)
        
class IPv6SupportTest(object):
    ''' A test case for classes representing host lists
    that have support (or at least: do not raise errors)
    for IPv6 addresses '''
    
    valid_ipv6 = '2001:ddd:ccc:111::33'
    
    def test_contains_for_listed_ipv6(self):
        self._test_contains_for_listed(self.valid_ipv6)
            
    def test_contains_for_not_listed_ipv6(self):
        self._test_contains_not_for_listed(self.valid_ipv6)
        
    def test_lookup_for_listed_ipv6(self):
        self._test_lookup_for_listed(self.valid_ipv6)
          
    def test_lookup_for_not_listed_ipv6(self):
        self._test_lookup_for_not_listed(self.valid_ipv6)
        
class BaseUrlTesterTest(object):
    ''' A common test case for classes  responsible for
    testing urls for matching criteria supported by the
    classes or services that they represent'''
    
    valid_urls = ['http://test.com', 'http://127.33.22.11']
        
    def _test_any_match_returns_true_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        self.assertTrue(self.tested_instance.any_match(self.valid_urls + list(matching_urls)))
        
    def _test_any_match_returns_false(self, not_matching_urls):
        self.assertFalse(self.tested_instance.any_match(not_matching_urls))
        
    def _test_lookup_matching_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        
        expected = self._get_expected_items_for_urls(matching_urls)
        actual = list(self.tested_instance.lookup_matching(self.valid_urls + list(matching_urls)))
        
        self.assertItemsEqual(expected, actual)
        
    def test_any_match_returns_false(self):
        
        self._test_any_match_returns_false(self.valid_urls)
        
class GeneratedUrlTesterTest(object):
    ''' A class containing data for url tester test generation
    and test methods generated using the data '''
    
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
                           ('ipv6_url', ['http://[2001:ddd:ccc:111::33]'])
                           ]
    
    valid_url_list_input = [
                             ('no_matching_url', []),
                             ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                             ]+valid_url_input
    
    @parameterized.expand(invalid_url_input)
    def test_any_match_for_invalid(self, _, invalid_url):
        
        self._test_function_for_invalid_urls(self.tested_instance.any_match, invalid_url)
            
    @parameterized.expand(invalid_url_input)
    def test_lookup_matching_for_invalid(self, _, invalid_url):
        
        self._test_function_for_invalid_urls(self.tested_instance.lookup_matching, invalid_url)
    
    @parameterized.expand(valid_url_input)
    def test_any_match_returns_true_for(self, _, matching_urls):
        
        self._test_any_match_returns_true_for(matching_urls)
        
    @parameterized.expand(valid_url_list_input)
    def test_lookup_matching_for(self, _, matching_urls):
        
        self._test_lookup_matching_for(matching_urls)
            
class TestFunctionForInvalidUrlProvider(object):
    ''' Provides a common test method for functions
    using spambl.is_valid_url for url validation '''
    
    def _test_function_for_invalid_urls(self, function, invalid_url):
        
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        with self.assertRaises(ValueError):
            function(self.valid_urls + [invalid_url])
            
class TestFunctionDoesNotHandleProvider(object):

    def _test_function_does_not_handle(self, exception_type, exception_origin,
                                       function, *args, **kwargs):
        '''
        Test if a given function does not handle an error raised by a dependency
        
        :param exception_type: a type of exception to be raised
        :param exception_origin: a function raising the error, 
        represented by an instance of Mock
        :param function: a function to be tested
        :param *args: positional arguments to be passed to
        the tested function
        :param **kwargs: keyword arguments to be passed to
        the tested function
        '''
        
        exception_origin.side_effect = exception_type
        
        with self.assertRaises(exception_type):
            function(*args, **kwargs)
    
