# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from dns.resolver import NXDOMAIN
from future.moves.urllib.parse import urlparse, parse_qs
from nose_parameterized import parameterized
from requests.exceptions import HTTPError

from spam_lists.exceptions import UnathorizedAPIKeyError, UnknownCodeError, \
InvalidURLError, InvalidHostError
from spam_lists.service_models import DNSBL, GoogleSafeBrowsing, \
HostCollection, HostList, HpHosts
from spam_lists.structures import AddressListItem
from test.compat import unittest, Mock, MagicMock, patch, lru_cache
from test.unit.common_definitions import UrlTesterTestBase, \
TestFunctionDoesNotHandleProvider


class UrlTesterTestMixin(UrlTesterTestBase):
    ''' A class providing pre-generated tests for classes
    having any_match, filter_matching and lookup_matching
    methods '''
    
    classification = set(['TEST'])
    
    valid_url_input = [
                           ('ipv4_url', ['http://55.44.33.21']),
                           ('hostname_url', ['https://abc.com']),
                           ('ipv6_url', ['http://[2001:ddd:ccc:111::33]'])
                           ]
    
    valid_url_list_input = [
                             ('no_matching_url', []),
                             ('two_urls', [
                                           'http://55.44.33.21',
                                           'https://abc.com'
                                           ])
                             ]+valid_url_input
                             
    @parameterized.expand([
                           ('any_match'),
                           ('lookup_matching'),
                           ('filter_matching')
                           ])
    @patch('spam_lists.validation.is_valid_url')
    def test_query_for_invalid_url_with(self, function_name, is_valid_url_mock):
        invalid_url = 'http://invalid.url.com'
        is_valid_url_mock.side_effect = lambda u: u != invalid_url
        
        function = getattr(self.tested_instance, function_name)
        with self.assertRaises(InvalidURLError):
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
    
    def _get_expected_items(self, values):
        item = lambda i: AddressListItem(i, self.tested_instance,
                                             self.classification)
        return [item(v) for v in values]
    
def get_hosts(urls):
    
    return [urlparse(u).hostname for u in urls]

class HostListTestMixin(UrlTesterTestMixin):
    ''' A common test case for all classes that represent
    a host list stored locally or by a remote service '''
    
    valid_host_input = [
                        ('ipv4', '255.0.120.1'),
                        ('hostname', 'test.pl'),
                        ('ipv6', '2001:ddd:ccc:111::33')
                        ]
    
    def _set_matching_urls(self, urls):
        self._set_matching_hosts(get_hosts(urls))
        
    def _get_expected_items_for_urls(self, urls):
        return self._get_expected_items(get_hosts(urls))
        
    def _get_result_for_invalid_host(self, function):
        unsupported_host = 'unsupported.com'
        self.host_factory_mock.side_effect = InvalidHostError
        
        return function(unsupported_host)
        
    def test_contains_for_invalid_host(self):
        function = self.tested_instance.__contains__
        actual = self._get_result_for_invalid_host(
                                                             function
                                                             )
        self.assertFalse(actual)
        
    def test_lookup_for_invalid_host(self):
        function = self.tested_instance.lookup
        actual = self._get_result_for_invalid_host(
                                                             function
                                                             )
        self.assertIsNone(actual)
    
    @parameterized.expand([
                           ('__contains__'),
                           ('lookup')
                           ])
    @patch('spam_lists.validation.is_valid_host')
    def test_invalid_host_query_using(
                                         self,
                                         function_name,
                                         is_valid_host_mock
                                         ):
        
        function = getattr(self.tested_instance, function_name)
        invalid_host = 'invalid.com'
        is_valid_host_mock.side_effect = lambda h: h != invalid_host
        
        with self.assertRaises(InvalidHostError):
            function(invalid_host)
        
    @parameterized.expand(valid_host_input)
    def test_contains_for_listed(self, _, value):
        self._set_matching_hosts([value])
        self.assertTrue(value in self.tested_instance)
            
    @parameterized.expand(valid_host_input)
    def test_contains_for_not_listed(self, _, value):
        self.assertFalse(value in self.tested_instance)
                
    @parameterized.expand(valid_host_input)
    def test_lookup_for_listed(self, _, value):
        expected = self._get_expected_items([value])[0]
        self._set_matching_hosts([value])
        self.assertEqual(self.tested_instance.lookup(value), expected)
          
    @parameterized.expand(valid_host_input)  
    def test_lookup_for_not_listed(self, _, value):
        self.assertIsNone(self.tested_instance.lookup(value))


@lru_cache()
def host_list_host_factory(host):
    host_object = MagicMock()
    host_object.to_unicode.return_value = host
    return host_object

#pylint: disable=too-many-public-methods
class HostListTest(HostListTestMixin, unittest.TestCase):
    ''' Tests for HostList class
    
    HostList does not provide implementation of some methods it uses.
    These methods are ought to be implemented by its subclasses. Here,
    we mock these methods so that HostList can be tested.
    
    :var listed_hosts: a list of all host values assumed to be listed for
    a given test
    :var host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_list_host_factory as its implementation
    :var tested_instance: an instance of tested class
    :var _contains_patcher: a patcher for HostList._contains method
    :var _contains_mock: a mock for HostList._contains method.
    :var host_data_getter_patcher: a patcher for 
    HostList._get_match_and_classification method
    :var host_data_getter_mock: a mock for 
    HostList._get_match_and_classification method. Uses
     host_list_host_factory as its implementation.
    '''
    def setUp(self):
        self.listed_hosts = []
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = host_list_host_factory
        self.tested_instance = HostList(self.host_factory_mock)
        
        self._contains_patcher = patch(
                                       'spam_lists.service_models.'
                                       'HostList._contains'
                                       )
        self._contains_mock = self._contains_patcher.start()
        self._contains_mock.side_effect = lambda h: h in self.listed_hosts
        host_data_getter_name = (
                                 'spam_lists.service_models.'
                                 'HostList._get_match_and_classification'
                                 )
        self.host_data_getter_patcher = patch(host_data_getter_name)
        self.host_data_getter_mock = self.host_data_getter_patcher.start()
        
        def _get_match_and_classification(host):
            if host in self.listed_hosts:
                return host, self.classification
            return None, None
        
        self.host_data_getter_mock.side_effect = _get_match_and_classification
        
    def tearDown(self):
        self._contains_patcher.stop()
        self.host_data_getter_patcher.stop()
        
    def _set_matching_hosts(self, matching_hosts):
        
        self.listed_hosts = [self.host_factory_mock(mh) 
                             for mh in matching_hosts]


def create_dns_query_function(expected_query_names):
    def dns_query(query_name):
        if query_name in expected_query_names:
            dns_answer_mock = Mock()
            dns_answer_mock.to_text.return_value = '121.0.0.1'
            return [dns_answer_mock]
        raise NXDOMAIN
    return dns_query
        
class DNSBLTest(
                HostListTestMixin,
                TestFunctionDoesNotHandleProvider,
                unittest.TestCase
                ):
    ''' Tests for DNSBL class
    
    This test case adds additional test method to the ones inherited
    from HostListTestMixin: test_code_error_raised_by, which
    tests methods using return code of a DNSBL service (DNSBL.lookup
    and DNSBL.lookup_matching) for their behaviour for cases of an
    unknown integer code being returned.
    
    :var query_domain_str: a string used as a suffix for DNS queries
    to a service
    :var host_with_unknown_code: a host value used by the additional
    test method (test_code_error_raised_by)
    :var classification_map: a mocked instance of an object
    representing a classification map used by tested instance
    :var host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_list_host_factory as its implementation
    :var tested_instance: an instance of tested class
    :var dns_query_patcher: an object used for patching query function
     used by DNSBL instance.
    :var dns_query_mock: a mocked implementation of the query function
    '''
    query_domain_str = 'test.query.domain'
    host_with_unknown_code = 'hostwithunknowncode.com'
    def setUp(self):
         
        self.classification_map = MagicMock()
        self.classification_map.__getitem__.return_value = self.classification
         
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = host_list_host_factory
         
        self.tested_instance = DNSBL(
                                     'test_service',
                                     self.query_domain_str,
                                     self.classification_map,
                                     self.host_factory_mock
                                     )
         
        self.dns_query_patcher = patch('spam_lists.service_models.query')
        self.dns_query_mock = self.dns_query_patcher.start()
        self.dns_query_mock.side_effect = create_dns_query_function([])
         
    def tearDown(self):
         
        self.dns_query_patcher.stop()
         
    def _set_matching_hosts(self, hosts):
         
        host_objects = [self.host_factory_mock(h) for h in hosts]
        expected_query_names = [h.relative_domain.derelativize() 
                                for h in host_objects]
        side_effect = create_dns_query_function(expected_query_names)
        self.dns_query_mock.side_effect = side_effect
        
    @parameterized.expand([
                           ('lookup', host_with_unknown_code),
                           (
                            'lookup_matching',
                            ['http://'+host_with_unknown_code]
                            )
                           ])
    def test_code_error_raised_by(self, function_name, tested_value):
        function = getattr(self.tested_instance, function_name)
        self._set_matching_hosts([self.host_with_unknown_code])
        self._test_function_does_not_handle(
                                            UnknownCodeError,
                                            self.classification_map.__getitem__,
                                            function,
                                            tested_value
                                            )


def create_hp_hosts_get(classification, listed_hosts):
    ''' Get a function to replace get function used by HpHosts
    
    :param classification: a classification for given hosts
    :param listed_hosts: listed hosts for generating responses
    :returns: a function providing side effects of Mock instance
    for the get function
    '''
    class_str = ','.join(classification)
    def hp_hosts_get(url):
        ''' Get mock representing response object for GET request
        
        :param url: a request address
        :returns: a Mock instance representing response object expected
        by HpHosts
        '''
        query_string = urlparse(url).query
        query_data = parse_qs(query_string)
        
        content = 'Not Listed'
        host = query_data['s'][0]
        
        if host in listed_hosts:
            content = 'Listed,{}'.format(class_str)
            
        response = Mock()
        response.text = content
        return response
    return hp_hosts_get

class HpHostsTest(HostListTestMixin, unittest.TestCase):
    ''' Tests for HpHosts class
    
    :var listed_hosts: a list of host values assumed to be listed
    for tests
    :var get_patcher: an object used for patching get function used
     by HpHosts instance.
    :var tested_instance: an instance of tested class
    :var get_mock: a mocked implementation of the get function. Uses
    a function returned by create_hp_hosts_get for given classification
    and list of hosts
    :var host_factory_mock: a mocked implementation of
     host factory used by tested instance. Uses host_list_host_factory
      as its implementation
    '''
    @classmethod
    def setUpClass(cls):
         
        cls.tested_instance = HpHosts('spambl_test_suite')
        
    def setUp(self):
         
        self.listed_hosts = []
        
        self.get_patcher = patch('spam_lists.service_models.get')
        self.get_mock = self.get_patcher.start()
        self.get_mock.side_effect = create_hp_hosts_get(self.classification, [])
        
        self.host_factory_mock = Mock()
        
        self.tested_instance = HpHosts('spambl_test_suite')
        self.tested_instance._host_factory = self.host_factory_mock
         
        self.host_factory_mock.side_effect = host_list_host_factory
         
    def tearDown(self):
        self.get_patcher.stop()
         
    def _set_matching_hosts(self, hosts):
        side_effect = create_hp_hosts_get(
                                          self.classification, hosts
                                          )
        self.get_mock.side_effect = side_effect

def create_gsb_post(expected_401, spam_urls, classification):
    ''' Get mock for post function used by GoogleSafeBrowsing
    
    :param expected_401: if True, the code of response mock returned
    by the returned function will be 401
    :param spam_urls: a list of urls to be recognized as spam
    :param classification: a classification used for spam urls
    :returns: mocked implementation of post function
    '''
    def post(_, body):
        ''' Get mock of a response to a POST query to GSB lookup API
        
        :param body: a request body
        :returns: a Mock instance representing the response. Properties
        of the object depend on external values provided by the creator
        of the method: expected_401, spam_urls and classification
        ''' 
        response = Mock()
        if expected_401:
            response.status_code = 401
            response.raise_for_status.side_effect = HTTPError
                
        else:
            urls = body.splitlines()[1:]
            classes = ['ok' if u not in spam_urls else
                       ','.join(classification) for u in urls]
            response.text = '\n'.join(classes)
            code = 200 if spam_urls else 204
            response.status_code = code
            
        return response
    return post


#pylint: disable=too-many-public-methods
class GoogleSafeBrowsingTest(UrlTesterTestMixin, unittest.TestCase):
    ''' Tests for GoogleSafeBrowsing class
    
    This class adds an additional test method to the ones provided
    by UrlTesterTestMixin: test_unathorized_query_with. This method
    is used to test methods of GoogleSafeBrowsing class for expected
    behaviour while calling Google Safe Browsing lookup API with
    an unathorized API key
    
    :var tested_instance: an instance of tested class
    :var post_patcher: an object used for patching post function used
    by GoogleSafeBrowsing instance
    :var mocked_post: a mocked implementation of the post function
    for the tested instance. Uses a function returned by
     create_gsb_post function as its implementation.
    '''
    def _get_expected_items_for_urls(self, urls):
        return self._get_expected_items(urls)
    
    @classmethod
    def setUpClass(cls):
        cls.tested_instance = GoogleSafeBrowsing(
                                                 'test_client',
                                                 '0.1',
                                                 'test_key'
                                                 )
        
    def _set_up_post_mock(self, spam_urls, error_401_expected = False):
        side_efect = create_gsb_post(
                                     error_401_expected,
                                     spam_urls,
                                     self.classification
                                     )
        self.mocked_post.side_effect = side_efect
        
    def setUp(self):
        self.post_patcher = patch('spam_lists.service_models.post')
        self.mocked_post = self.post_patcher.start()
        
    def tearDown(self):
        self.post_patcher.stop()
        
    def _set_matching_urls(self, urls):
        self._set_up_post_mock(urls)
        
    @parameterized.expand([
                           ('any_match'),
                           ('lookup_matching'),
                           ('filter_matching')
                           ])
    def test_unathorized_query_with(self, function_name):
        tested_function = getattr(self.tested_instance, function_name)
        called_function = lambda u: list(tested_function(u))
        self._set_up_post_mock([], error_401_expected=True)
        self.assertRaises(
                          UnathorizedAPIKeyError,
                          called_function,
                          self.valid_urls
                          )
        
def host_collection_host_factory(host):
    host_object = host_list_host_factory(host)
    host_object.is_subdomain.return_value = False
    host_object.__eq__.return_value = False
    
    test = lambda h2: host_object.to_unicode() == h2.to_unicode()
    host_object.__eq__.side_effect = test
    host_object.is_subdomain.side_effect = test
    
    return host_object
        
class HostCollectionTest(
                         HostListTestMixin,
                         TestFunctionDoesNotHandleProvider,
                         unittest.TestCase
                         ):
    ''' Tests for HostCollection class
    
    This class adds the following test methods to the ones provided by
     HostListTestMixin:
     * test_add_invalid_host
     * test_add_for_valid
    :var host_factory_patcher: an object used for patching the host
    factory used by HostCollection instances.
    
    The host factory may be used by the HostCollection constructor
     (although its not used in this case), so I chose patching instead
      of injecting a mock of a host factory instance after creating
       a HostCollection instance
    
    :var host_factory_mock: a mocked implementation of
     host factory used by tested instance. Uses
      host_collection_host_factory as its implementation
    :var tested_instance: an instance of tested class
    '''
    valid_urls = ['http://test.com', 'http://127.33.22.11']
    
    def setUp(self):
        self.host_factory_patcher = patch(
                                          'spam_lists.service_models.'
                                          'hostname_or_ip'
                                          )
        self.host_factory_mock = self.host_factory_patcher.start()
        
        side_effect = host_collection_host_factory
        self.host_factory_mock.side_effect = side_effect
        self.tested_instance = HostCollection('test_host_collection',
                                              self.classification)
         
    def tearDown(self):
        self.host_factory_patcher.stop()
        
    def test_add_invalid_host(self):
        function = self.tested_instance.add
        
        self._test_function_does_not_handle(InvalidHostError,
                                            self.host_factory_mock,
                                            function,
                                            'invalidhost.com'
                                            )
         
    @parameterized.expand(HostListTestMixin.valid_host_input)
    def test_add_for_valid(self, _, value):
         
        self.tested_instance.add(value)
         
        in_host_collection = (self.host_factory_mock(value)
                              in self.tested_instance.hosts)
         
        self.assertTrue(in_host_collection)
        
    def test_add_for_subdomain(self):
        ''' A subdomain to a domain already listed in the collection
        is expected to be ignored when added to the collection '''
        initial_hosts = [Mock()]
        self.tested_instance.hosts = set(initial_hosts)
        self.host_factory_mock.side_effect = lambda h: Mock()
        self.tested_instance.add('subdomain.domain.com')
        self.assertCountEqual(initial_hosts, self.tested_instance.hosts)

    def test_add_for_the_same_value(self):
        '''A value being added to the collection is being ignored if it
        already exists in the collection '''
        host_obj = Mock()
        host_obj.is_subdomain.return_value = False
        initial_hosts = [host_obj]
        self.tested_instance.hosts = set(initial_hosts)
        self.host_factory_mock.side_effect = lambda h: host_obj
        self.tested_instance.add('domain.com')
        self.assertCountEqual(initial_hosts, self.tested_instance.hosts)

    def test_add_a_superdomain(self):
        ''' A superdomain of a domain listed in the collection
        is expected to replace its subdomain when added '''
        initial_hosts = [Mock()]
        self.tested_instance.hosts = set(initial_hosts)
        superdomain = Mock()
        superdomain.is_subdomain.return_value = False
        self.host_factory_mock.side_effect = lambda h: superdomain
        self.tested_instance.add('domain.com')
        expected = [superdomain]
        self.assertCountEqual(expected, self.tested_instance.hosts)

    def _set_matching_hosts(self, hosts):
        self.tested_instance.hosts = [self.host_factory_mock(h) for h in hosts]
        


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
