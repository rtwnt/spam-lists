# -*- coding: utf-8 -*-

import unittest
from itertools import chain
from collections import defaultdict
from random import shuffle

from mock import Mock, patch
from nose_parameterized import parameterized
from cachetools.func import lru_cache
from requests.exceptions import ConnectionError, InvalidSchema, InvalidURL,\
Timeout

from spam_lists.utils import RedirectUrlResolver, UrlsAndLocations, UrlTesterChain
from spam_lists.structures import AddressListItem
from spam_lists.exceptions import InvalidURLError, UnknownCodeError

from test.common_definitions import UrlTesterTestBase, TestFunctionDoesNotHandleProvider

class RedirectUrlResolverTest(unittest.TestCase):
    
    valid_urls = ['http://first.com', 'http://122.55.33.21',
    'http://[2001:db8:abc:123::42]']
    
    def setUp(self):
        
        session_mock = Mock()
        
        self.head_mock = session_mock.head
        self.resolve_redirects_mock = session_mock.resolve_redirects
        
        self.resolver = RedirectUrlResolver(session_mock)
        
        self.patcher = patch('spam_lists.utils.is_valid_url')
        self.is_valid_url_mock = self.patcher.start()
        
    def tearDown(self):
        
        self.patcher.stop()
        
    def test_get_first_response_for_invalid_url(self):
        
        self.is_valid_url_mock.return_value = False
        
        self.assertRaises(InvalidURLError, self.resolver.get_first_response, 'http://test.com')
        
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
        
        with self.assertRaises(InvalidURLError):
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


class UrlsAndLocationsTest(unittest.TestCase):
    
    valid_urls = ['http://first.com', 'http://122.55.33.21',
    'http://[2001:db8:abc:123::42]']
    url_redirects = {
                     'http://url1.com': ('http://redirect1.com', 'http://redirect2.com'),
                     'http://88.66.55.22': ['http://abc.com', 'https://def.com'],
                     'http://host.com': ['http://88.66.55.22', 'http://abc.com', 'https://def.com']
                     }
    
    def setUp(self):
        self.is_valid_url_patcher = patch('spam_lists.utils.is_valid_url')
        self.is_valid_url_mock = self.is_valid_url_patcher.start()
        self.redirect_resolver_mock = Mock()
        
    def tearDown(self):
        
        self.is_valid_url_patcher.stop()
        
    def _get_tested_instance(self):
        self._set_redirect_urls(self.url_redirects)
        initial_urls = self.url_redirects.keys()
        return UrlsAndLocations(initial_urls, self.redirect_resolver_mock)
    
    def test_constructor_for_invalid_url(self):
        invalid_url = 'invalid.url.com'
        self.is_valid_url_mock.side_effect = lambda u: u != invalid_url

        self.assertRaises(InvalidURLError, UrlsAndLocations, self.valid_urls+[invalid_url])
        
    def _set_redirect_urls(self, redirect_locations_per_url):
        
        side_effect = lambda u: redirect_locations_per_url.get(u, [])
        self.redirect_resolver_mock.get_redirect_urls.side_effect = side_effect
        
    def test_iter_returns_initial_urls_before_resolving_redirects(self):
        urls_and_locations = self._get_tested_instance()
        
        for i, _ in enumerate(urls_and_locations):
            if i == len(self.url_redirects.keys()) - 1:
                break
            
        self.redirect_resolver_mock.get_redirect_urls.assert_not_called()
        
    def test_iter_maintains_order_betten_runs(self):
        urls_and_locations = self._get_tested_instance()
        
        first_run_results = list(urls_and_locations)
        second_run_results = list(urls_and_locations)
        
        self.assertSequenceEqual(first_run_results, second_run_results)
        
    def test_iter_returns_no_duplicates(self):
        urls_and_locations = self._get_tested_instance()
        
        expected_items = set(chain(self.url_redirects.keys(), *self.url_redirects.values()))
        actual_items = list(urls_and_locations)
            
        self.assertItemsEqual(expected_items, actual_items)
        
    def test_iter_does_not_resolve_redirects_during_second_run(self):
        urls_and_locations = self._get_tested_instance()
        
        list(urls_and_locations)
        self.redirect_resolver_mock.get_redirect_urls.reset_mock()
        
        list(urls_and_locations)
        self.redirect_resolver_mock.get_redirect_urls.assert_not_called()
        
        
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
    classification = set(['TEST'])
    
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
        
    @parameterized.expand([
                             ('no_matching_url', {}),
                             ('matching_urls', url_to_source_id)
                             ])
    def test_filter_matching_for(self, _, matching_urls):
        
        self._test_filter_matching_for(matching_urls)
        
    @parameterized.expand([
                           ('any_match_does_not_handle_value_error', 'any_match', ValueError),
                           ('any_match_does_not_handle_unknown_code_error', 'any_match', UnknownCodeError),
                           ('lookup_matching_does_not_handle_value_error', 'lookup_matching', ValueError),
                           ('lookup_matching_does_not_handle_unknown_code_error', 'lookup_matching', UnknownCodeError),
                           ('filter_matching_does_not_handle_value_error', 'filter_matching', ValueError),
                           ('filter_matching_does_not_handle_unknown_code_error', 'filter_matching', UnknownCodeError)
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