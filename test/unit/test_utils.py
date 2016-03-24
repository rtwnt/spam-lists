# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from collections import defaultdict
from itertools import chain
from random import shuffle

#pylint: disable-msg=redefined-builtin
from builtins import next, range
from nose_parameterized import parameterized
from requests.exceptions import ConnectionError, InvalidSchema, InvalidURL, \
Timeout

from spam_lists.exceptions import InvalidURLError, UnknownCodeError
from spam_lists.structures import AddressListItem
from spam_lists.utils import RedirectUrlResolver, UrlsAndLocations, \
UrlTesterChain
from test.compat import unittest, Mock, patch, lru_cache
from test.unit.common_definitions import UrlTesterTestBase, \
TestFunctionDoesNotHandleProvider


def get_response_mocks(urls):
    response_mocks = []
    for url in urls:
        response = Mock()
        response.url = url
        response_mocks.append(response)
    return response_mocks


def get_session_resolve_redirects(response_mocks, exception_type):
    if not (exception_type is None or
            issubclass(exception_type, Exception)):
        msg = '{} is not a subclass of Exception'.format(exception_type)
        raise ValueError(msg)
        
    # pylint: disable-msg=unused-argument
    def resolve_redirects(response, request):
        for mocked in response_mocks:
            yield mocked
                
        if exception_type:
            raise exception_type
                
    return resolve_redirects


class RedirectUrlResolverTest(unittest.TestCase):
    ''' Tests for RedirectUrlResolver class
    
    :var valid_urls: a list of strings representing valid urls used
     in tests
    :var head_mock: a mocked implementation of head function
    used by the tested class to perform HEAD requests
    :var resolve_redirects_mock: a mock for
    requests.Session.resolve_redirects function. A function returned
     by get_session_resolve_redirects is used as its implementation.
    :var resolver: an instance of RedirectUrlResolver to be tested
    :var patcher: an object used to patch is_valid_url function
    :var is_valid_url_mock: a mocked implementation of
     the is_valid_url function
     :var _response_mocks: a list of mock objects representing
      response objects returned by requests.Session.resolve_redirects.
      get_response_mocks function is used to populate it for given test
    '''
    valid_urls = ['http://first.com', 'http://122.55.33.21',
    'http://[2001:db8:abc:123::42]']
    def setUp(self):
        
        session_mock = Mock()
        
        self.head_mock = session_mock.head
        self.resolve_redirects_mock = session_mock.resolve_redirects
        
        self.resolver = RedirectUrlResolver(session_mock)
        
        self.patcher = patch('spam_lists.utils.is_valid_url')
        self.is_valid_url_mock = self.patcher.start()
        
        self._response_mocks = []
        
    def tearDown(self):
        
        self.patcher.stop()
        
    def test_get_locations_for_invalid(self):
        
        self.is_valid_url_mock.return_value = False
        
        with self.assertRaises(InvalidURLError):
            next(self.resolver.get_locations('http://test.com'))
        
    def _set_up_resolve_redirects(self, urls, exception_type):
        self._response_mocks = get_response_mocks(urls)
        
        side_effect = get_session_resolve_redirects(
                                                    self._response_mocks,
                                                    exception_type
                                                    )
        self.resolve_redirects_mock.side_effect = side_effect
        
    def _set_last_location_header(self, url):
        
        all_responses = [self.head_mock.return_value] + self._response_mocks
        all_responses[-1].headers = {'location': url}
    
    def _test_get_locations(self, expected):
        
        url_generator = self.resolver.get_locations('http://test.com')
        
        self.assertEqual(expected, list(url_generator))
        
    @parameterized.expand([
                           ('no_url', []),
                           ('urls', valid_urls)
                           ])
    def test_get_locations_yields(self, _, expected):
        
        self._set_up_resolve_redirects(expected, None)
        
        self._test_get_locations(expected)
        
    @parameterized.expand([
                           ('initial_url_casuing_timeout', [], Timeout),
                           ('last_url_casuing_timeout', valid_urls, Timeout),
                           ('initial_invalid_url', [], InvalidURL, False),
                           ('last_invalid_url', valid_urls, InvalidURL, False),
                           (
                            'initial_url_causing_connection_error',
                            [],
                            ConnectionError
                            ),
                           (
                            'last_url_causing_connection_error',
                            valid_urls, ConnectionError
                            ),
                           (
                            'initial_invalid_url_causing_connection_error',
                            [],
                            ConnectionError,
                            False
                            ),
                           (
                            'last_invalid_url_causing_connection_error',
                            valid_urls,
                            ConnectionError,
                            False
                            ),
                           ('initial_invalid_schema', [], InvalidSchema),
                           ('last_invalid_schema', valid_urls, InvalidSchema),
                           (
                            'initial_invalid_url_with_invalid_schema',
                            [],
                            InvalidSchema,
                            False
                            ),
                           (
                            'last_invalid_url_with_invalid_schema',
                            valid_urls,
                            InvalidSchema,
                            False
                            )
                           ])
    def test_get_locations_for(self, _, locations,
                               exception_type, triggered_by_valid_url = True):
        expected = list(locations)
        self._set_up_resolve_redirects(expected, exception_type)
        
        error_source = 'http://triggered.error.com'
        if triggered_by_valid_url:
            expected += [error_source]
        else:
            is_valid_url = lambda u: u in expected+['http://test.com']
            self.is_valid_url_mock.side_effect = is_valid_url
        
        self._set_last_location_header(error_source)
        
        self._test_get_locations(expected)


class UrlsAndLocationsTest(unittest.TestCase):
    ''' Tests for UrlsAndLocations class
    
    '''
    valid_urls = ['http://first.com', 'http://122.55.33.21',
    'http://[2001:db8:abc:123::42]']
    url_redirects = {
                     'http://url1.com': [
                                         'http://redirect1.com',
                                         'http://redirect2.com'
                                         ],
                     'http://88.66.55.22': [
                                            'http://abc.com',
                                            'https://def.com'
                                            ],
                     'http://host.com': [
                                         'http://88.66.55.22',
                                         'http://abc.com',
                                         'https://def.com'
                                         ]
                     }
    
    def setUp(self):
        self.is_valid_url_patcher = patch('spam_lists.utils.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        self.redirect_resolver_mock = Mock()
        
    def tearDown(self):
        
        self.is_valid_url_patcher.stop()
        
    def _get_tested_instance(self):
        self._set_redirect_urls(self.url_redirects)
        initial_urls = list(self.url_redirects.keys())
        return UrlsAndLocations(initial_urls, self.redirect_resolver_mock)
    
    def test_init_for_invalid_url(self):
        invalid_url = 'invalid.url.com'
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url

        self.assertRaises(
                          InvalidURLError,
                          UrlsAndLocations,
                          self.valid_urls+[invalid_url]
                          )
        
    def _set_redirect_urls(self, redirect_locations_per_url):
        
        side_effect = lambda u: redirect_locations_per_url.get(u, [])
        self.redirect_resolver_mock.get_locations.side_effect = side_effect
        
    def test_iter_starts_with_input(self):
        urls_and_locations = self._get_tested_instance()
        
        for i, _ in enumerate(urls_and_locations):
            if i == len(list(self.url_redirects.keys())) - 1:
                break
            
        self.redirect_resolver_mock.get_locations.assert_not_called()
        
    def test_iter_has_constant_order(self):
        urls_and_locations = self._get_tested_instance()
        
        first_run_results = list(urls_and_locations)
        second_run_results = list(urls_and_locations)
        
        self.assertSequenceEqual(first_run_results, second_run_results)
        
    def test_iter_returns_no_duplicates(self):
        urls_and_locations = self._get_tested_instance()
        
        expected_items = set(chain(list(self.url_redirects.keys()),
                                   *list(self.url_redirects.values())))
        actual_items = list(urls_and_locations)
            
        self.assertCountEqual(expected_items, actual_items)
        
    def test_iter_returns_cached(self):
        urls_and_locations = self._get_tested_instance()
        
        list(urls_and_locations)
        self.redirect_resolver_mock.get_locations.reset_mock()
        
        list(urls_and_locations)
        self.redirect_resolver_mock.get_locations.assert_not_called()
        
        
@lru_cache()
def get_url_tester_mock(identifier):
    source = Mock()
    source.identifier = identifier
    return source

class UrlTesterChainTest(
                         UrlTesterTestBase,
                         TestFunctionDoesNotHandleProvider,
                         unittest.TestCase
                         ):
    ''' Tests for UrlTesterChain class
    
    This class uses get_url_tester_mock function to populate list of
    url testers used by the tested instance
    
    :var classification: a set of classifications used in tests
    :var tested_instance: an instance of tested class
    '''
    classification = set(['TEST'])
    
    url_to_source_id ={
                       'http://55.44.21.12': [
                                              'source_1',
                                              'source_2'
                                              ],
                       'http://test.com': ['source_3'],
                       'https://abc.com': ['source_1'],
                       'http://[2001:ddd:ccc:111::22]': [
                                                         'source_1',
                                                         'source_2'
                                                         ],
                       'http://[2001:abc:111:22::33]': ['source_3']
                       }
    
    def setUp(self):
        url_testers = []
        
        for _ in range(3):
            tester = Mock()
            tester.any_match.return_value = False
            tester.lookup_matching.return_value = []
            tester.filter_matching.return_value = []
            url_testers.append(tester)
        
        self.tested_instance = UrlTesterChain(*url_testers)
    
    def _add_url_tester(self, source_id, matching_urls):
        
        tester = get_url_tester_mock(source_id)
        any_match = lambda u: not set(u).isdisjoint(set(matching_urls))
        tester.any_match.side_effect = any_match
        
        tester.filter_matching.return_value = list(matching_urls)
        
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
        
        return [self._get_item(u, i) for u, ids
                in list(urls.items()) for i in ids]
            
    def _set_matching_urls(self, urls):
        
        by_source_id = defaultdict(list)
        
        for url, ids in list(urls.items()):
            for i in ids:
                by_source_id[i].append(url)
                
        for i, urls in list(by_source_id.items()):
            self._add_url_tester(i, urls)
            
        shuffle(self.tested_instance.url_testers)
    
    def test_any_match_expecting_true(self):
        
        self._test_any_match_returns_true_for(self.url_to_source_id)
        
    @parameterized.expand([
                             ('no_matching_url', {}),
                             ('matching_urls', url_to_source_id)
                             ])
    def test_lookup_matching_for(self, _, matching_urls):
        
        self._test_lookup_matching_for(matching_urls)
        
    @parameterized.expand([
                             ('no_matching_url', {}),
                             ('matching_urls', url_to_source_id)
                             ])
    def test_filter_matching_for(self, _, matching_urls):
        
        self._test_filter_matching_for(matching_urls)
        
    @parameterized.expand([
                           (
                            'any_match_raises_value_error',
                            'any_match',
                            ValueError
                            ),
                           (
                            'any_match_raises_unknown_code_error',
                            'any_match',
                            UnknownCodeError
                            ),
                           (
                            'lookup_matching_raises_value_error',
                            'lookup_matching',
                            ValueError
                            ),
                           (
                            'lookup_matching_raises_unknown_code_error',
                            'lookup_matching',
                            UnknownCodeError
                            ),
                           (
                            'filter_matching_raises_value_error',
                            'filter_matching',
                            ValueError
                            ),
                           (
                            'filter_matching_raises_unknown_code_error',
                            'filter_matching',
                            UnknownCodeError
                            )
                           ])
    def test_(self, _, function_name, error_type):
        
        function = getattr(self.tested_instance, function_name)
        
        for tester in reversed(self.tested_instance.url_testers):
            error_source = getattr(tester, function_name)
            self._test_function_does_not_handle(
                                                error_type,
                                                error_source,
                                                function,
                                                ['http://triggeringerror.com']
                                                )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()