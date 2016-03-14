# -*- coding: utf-8 -*-


import unittest

from mock import Mock, patch
from cachetools.func import lru_cache
from nose_parameterized import parameterized

from spam_lists.validation import accepts_valid_urls, is_valid_url
from spam_lists.exceptions import InvalidURLError

class ValidationDecoratorTest(object):
    
    def setUp(self):
        self.validity_tester_patcher = patch(self.validity_tester)
        self.validity_tester_mock = self.validity_tester_patcher.start()
        
        function = Mock()
        function.__name__ = 'function'
        
        self.obj = Mock()
        self.function = function
        self.decorated_function = self.decorator(self.function)
    
    def tearDown(self):
        self.validity_tester_patcher.stop()
    
    def _test_wrapper_for_valid(self, value):
        self.decorated_function(self.obj, value)
        self.function.assert_called_once_with(self.obj, value)
    
    def _test_wrapper_for_invalid(self, value):
        self.validity_tester_mock.return_value = False
        
        self.assertRaises(self.exception_type, self.decorated_function, self.obj, value)
        self.function.assert_not_called()

class AcceptValidUrlsTest(ValidationDecoratorTest, unittest.TestCase):
    exception_type = InvalidURLError
    decorator = staticmethod(accepts_valid_urls)
    validity_tester = 'spam_lists.validation.is_valid_url'
    
    @parameterized.expand([
                           ('hostname', ['https://valid.com']),
                           ('ipv4_host', ['http://122.34.59.109']),
                           ('ipv6_host', ['http://[2001:db8:abc:123::42]'])
                           ])
    def test_accept_valid_urls_for_urls_with_valid(self, _, urls):
        self._test_wrapper_for_valid(urls)
    
    
    @parameterized.expand([
                           ('invalid_hostname', ['http://-abc.com']),
                           ('invalid_schema', ['abc://hostname.com']),
                           ('no_schema', ['hostname.com']),
                           ('invalid_ipv4', ['http://999.999.999.999']),
                           ('invalid_ipv4', ['http://127.0.0.0.1']),
                           ('invalid_ipv6', ['http://[2001:db8:abcef:123::42]']),
                           ('invalid_ipv6', ['http://[2001:db8:abch:123::42]'])
                           ])
    def test_accept_valid_urls_for_urls_with(self, _, urls):
        self._test_wrapper_for_invalid(urls)
        
@lru_cache()
def get_url_tester_mock(identifier):
    source = Mock()
    source.identifier = identifier
    return source
          
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

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()