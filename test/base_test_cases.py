# -*- coding: utf-8 -*-

from spam_lists.spambl import AddressListItem
from nose_parameterized import parameterized
from types import GeneratorType

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
    
    valid_host_input = [
                        ('ipv4', u'255.0.120.1'),
                        ('hostname', 'test.pl')
                        ]
    
    def _test_function_does_not_handle_value_error(self, function, arg):
        self._test_function_does_not_handle(ValueError,
                                            self.host_factory_mock,
                                            function,
                                            arg
                                            )
    
    @parameterized.expand([
                           ('__contains__'),
                           ('lookup')
                           ])
    def test_value_error_is_not_handled_by(self, function_name):
        
        function = getattr(self.tested_instance, function_name)
        self._test_function_does_not_handle_value_error(
                                            function,
                                            'invalidhost.com'
                                            )
        
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
        
    def _test_filter_matching_for(self, matching_urls):
        
        self._set_matching_urls(matching_urls)
        actual = list(self.tested_instance.filter_matching(self.valid_urls + list(matching_urls)))
         
        self.assertItemsEqual(matching_urls, actual)
        
    def test_any_match_returns_false(self):
        
        self._test_any_match_returns_false(self.valid_urls)
        
class GeneratedUrlTesterTest(object):
    ''' A class containing data for url tester test generation
    and test methods generated using the data '''
    
    valid_url_input = [
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('hostname_url', ['https://abc.com']),
                           ('ipv6_url', ['http://[2001:ddd:ccc:111::33]'])
                           ]
    
    valid_url_list_input = [
                             ('no_matching_url', []),
                             ('two_urls', ['http://55.44.33.21', 'https://abc.com'])
                             ]+valid_url_input
                             
    @parameterized.expand([
                           ('any_match'),
                           ('lookup_matching'),
                           ('filter_matching')
                           ])
    def test_value_error_is_raised_by(self, function_name):
        invalid_url = 'http://invalid.url.com'
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        function = getattr(self.tested_instance, function_name)
        with self.assertRaises(ValueError):
            function(self.valid_urls + [invalid_url])
    
    @parameterized.expand(valid_url_input)
    def test_any_match_returns_true_for(self, _, matching_urls):
        
        self._test_any_match_returns_true_for(matching_urls)
        
    @parameterized.expand(valid_url_list_input)
    def test_lookup_matching_for(self, _, matching_urls):
        
        self._test_lookup_matching_for(matching_urls)
        
    @parameterized.expand(valid_url_list_input)
    def test_filter_matching_for(self, _, matching_urls):
         
        self._test_filter_matching_for(matching_urls)
            
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
            result = function(*args, **kwargs)
            if isinstance(result, GeneratorType):
                list(result)
                
