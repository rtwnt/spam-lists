# -*- coding: utf-8 -*-
'''
This module contains unit tests for functions and classes provided by
spam_lists.composites module
'''
from __future__ import unicode_literals

from collections import defaultdict
from random import shuffle

from builtins import next, range  # pylint: disable=redefined-builtin
from nose_parameterized import parameterized
from requests.exceptions import (
    ConnectionError, InvalidSchema, InvalidURL, Timeout
)

from spam_lists.exceptions import InvalidURLError, UnknownCodeError
from spam_lists.structures import AddressListItem
from spam_lists.composites import (
    RedirectUrlResolver, UrlTesterChain, CachedIterable, GeneralizedUrlTester
)
from test.compat import unittest, Mock, patch, lru_cache, MagicMock
from test.unit.common_definitions import (
    UrlTesterTestBaseMixin, TestFunctionDoesNotHandleMixin
)


def get_response_mock(url):
    ''' Get mock representing response to a request

    :param url: response url
    :returns: an instance of mock representing a response
    '''
    response = Mock()
    response.url = url
    return response


class HeadSideEffects(dict):
    def __call__(self, url):
        return self.get(url)


class ResolveRedirectsSideEffects(object):
    '''' Provides side effects for redirect resolution

    The side effects include both response object mocks and exceptions.

    :var redirect_responses: a dictionary mapping response mocks
    to objects representing response arguments of
    the requests.Session.resolve_redirects method.
    :var exceptions: a dictionary mapping exception types to
    objects representing response arguments of the resolve_redirects
    method
    '''
    def __init__(self):
        self.responses = {}
        self.exceptions = {}

    def __call__(self, response, request):
        yielded = self.responses.get(response, [])
        exception_type = self.exceptions.get(response)
        for i in yielded:
            yield i
        if exception_type is not None:
            raise exception_type


class RedirectUrlResolverTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for RedirectUrlResolver class

    :var valid_urls: a list of strings representing valid urls used
     in tests
    :var head_mock: a mocked implementation of head function
    used by the tested class to perform HEAD requests. Uses an instance
    of HeadSideEffects as its implementation
    :var resolve_redirects_mock: a mock for
    requests.Session.resolve_redirects function. An instance of
    ResolveRedirectsSideEffects is used as its implementation
    :var redirect_results: points to an instance of
    ResolveRedirectsSideEffects used as a replacement implementation
    for requests.Session.resolve_redirects
    :var resolver: an instance of RedirectUrlResolver to be tested
    :var patcher: an object used to patch is_valid_url function
    :var is_valid_url_mock: a mocked implementation of
     the is_valid_url function
    '''
    redirect_url_chain = [
        'http://test.com',
        'http://first.com',
        'http://122.55.33.21',
        'http://[2001:db8:abc:123::42]'
    ]
    no_redirect_url_chain = ['http://noredirects.com']

    def setUp(self):
        session_mock = Mock()
        self.head_mock = session_mock.head
        self.head_mock.side_effect = HeadSideEffects()
        self.resolve_redirects_mock = session_mock.resolve_redirects
        self.redirect_results = ResolveRedirectsSideEffects()
        self.resolve_redirects_mock.side_effect = self.redirect_results
        self.resolver = RedirectUrlResolver(session_mock)
        self.patcher = patch('spam_lists.composites.is_valid_url')
        self.is_valid_url_mock = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_get_locations_for_invalid(self):
        self.is_valid_url_mock.return_value = False
        with self.assertRaises(InvalidURLError):
            next(self.resolver.get_locations('http://test.com'))

    def _set_up_side_effects(self, url_histories, exceptions=None,
                             last_location=''):
        ''' Prepare mocks for their calls to have expected side effects

        :param url_histories: a sequence containing sequences of
        url addresses of all responses to a request to a redirecting url
        :param exceptions: a dictionary mapping initial urls of
        redirection chains to exceptions raised when attempting to
        get response to a request to final location
        :param last_location: a value for location response header,
        specifying the location of the last request, if it couldn't be
        completed
        '''
        for history in url_histories:
            response_mocks = [get_response_mock(u) for u in history]
            response_mocks[-1].headers = {'location': last_location}
            first_response = response_mocks.pop(0)
            self.head_mock.side_effect[history[0]] = first_response
            self.redirect_results.responses[first_response] = response_mocks
            if exceptions is None:
                exceptions = {}
            exception_type = exceptions.get(history[0])
            self.redirect_results.exceptions[first_response] = exception_type

    def _test_get_locations(self, argument, expected):
        url_generator = self.resolver.get_locations(argument)
        self.assertEqual(expected, list(url_generator))

    @parameterized.expand([
        ('no_url', no_redirect_url_chain),
        ('urls', redirect_url_chain)
    ])
    def test_get_locations_yields(self, _, history):
        expected = history[1:]
        self._set_up_side_effects([history])
        self._test_get_locations(history[0], expected)

    @parameterized.expand([
        [ConnectionError],
        [InvalidSchema],
        [Timeout],
    ])
    def test_get_locations_arg_raising(self, exception_type):
        self.head_mock.side_effect = exception_type
        self._test_get_locations('http://error_source', [])

    @parameterized.expand([
        ('initial_url_causing_timeout', no_redirect_url_chain, Timeout),
        ('last_url_casuing_timeout', redirect_url_chain, Timeout),
        ('initial_invalid_url', no_redirect_url_chain, InvalidURL, False),
        ('last_invalid_url', redirect_url_chain, InvalidURL, False),
        (
            'initial_url_causing_connection_error',
            no_redirect_url_chain, ConnectionError
        ),
        (
            'last_url_causing_connection_error',
            redirect_url_chain, ConnectionError
        ),
        (
            'initial_invalid_url_causing_connection_error',
            no_redirect_url_chain, ConnectionError,
            False
        ),
        (
            'last_invalid_url_causing_connection_error',
            redirect_url_chain, ConnectionError,
            False
        ),
        ('initial_invalid_schema', no_redirect_url_chain, InvalidSchema),
        ('last_invalid_schema', redirect_url_chain, InvalidSchema),
        (
            'initial_invalid_url_with_invalid_schema',
            no_redirect_url_chain, InvalidSchema,
            False
        ),
        (
            'last_invalid_url_with_invalid_schema',
            redirect_url_chain, InvalidSchema,
            False
        )
    ])
    def test_get_locations_for(self, _, history,
                               exception_type, triggered_by_valid_url=True):
        ''' The get_locations method is expected to yield all
         valid urls appearing as url addresses and location headers in
         response histories for given urls

        :param history: url addresses of all responses in redirection chain
        :param exception_type: a type of exception to be raised while
        getting a response to the last location header value
        :param triggered_by_valid_url: if True, the value of the last
        location header - the one that tiggered an exception - is
        a valid url, and therefore it is also expected to be yielded
        '''
        expected = history[1:]
        exceptions = {history[0]: exception_type}
        error_source = 'http://triggered.error.com'
        self._set_up_side_effects([history], exceptions, error_source)
        if triggered_by_valid_url:
            expected += [error_source]
        else:

            def is_valid_url(url):
                return url in history
            self.is_valid_url_mock.side_effect = is_valid_url
        self._test_get_locations(history[0], expected)

    def _test_get_new_locations(self, histories):
        self._set_up_side_effects(histories)
        input_data = [h[0] for h in histories]
        redirects = [u for h in histories for u in h[1:]]
        expected = list(set(redirects) - set(input_data))
        actual = list(self.resolver.get_new_locations(input_data))
        self.assertCountEqual(expected, actual)

    def test_get_new_locations(self):
        ''' The method is expected to yield only new urls,
        that is urls that were not part of the original input '''
        no_redirects = 'http://noredirects.com'
        histories = [
            [no_redirects],
            ['http://abc.com', no_redirects],
            [
                'http://first.com',
                'http://second.com',
                'http://third.com'
            ]
        ]
        self._test_get_new_locations(histories)

    def test_get_new_unique_locations(self):
        ''' The generator returned by get_new_locations is expected
        to yield no urls that it yielded previously '''
        duplicated_part = [
            'http://first.com',
            'http://second.com',
            'http://third.com'
        ]
        histories = [
            duplicated_part,
            ['http://abc.com'] + duplicated_part
        ]
        self._test_get_new_locations(histories)

    @patch('spam_lists.composites.CachedIterable')
    def test_get_urls_and_locations(self, cached_iterable_mock):
        ''' The method get_urls_and_locations is expected to return
        an instance of CachedIterable.
        '''
        expected = Mock()
        cached_iterable_mock.return_value = expected
        actual = self.resolver.get_urls_and_locations(['http://test.com'])
        self.assertEqual(expected, actual)


@lru_cache()
def get_url_tester_mock(identifier):
    source = Mock()
    source.identifier = identifier
    return source


class UrlTesterChainTest(
        UrlTesterTestBaseMixin,
        TestFunctionDoesNotHandleMixin,
        unittest.TestCase
):
    # pylint: disable=too-many-public-methods
    ''' Tests for UrlTesterChain class

    This class uses get_url_tester_mock function to populate list of
    url testers used by the tested instance

    :var classification: a set of classifications used in tests
    :var tested_instance: an instance of tested class
    '''
    classification = set(['TEST'])
    url_to_source_id = {
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
        ''' Add a preconfigured url tester mock to the tested instance

        :param source_id: an identifier for a mocked url tester
        :param matching_urls: a list of urls expected to be matched by
        a service represented by the mocked url tester
        '''
        tester = get_url_tester_mock(source_id)

        def any_match(url):
            return not set(url).isdisjoint(set(matching_urls))
        tester.any_match.side_effect = any_match
        tester.filter_matching.return_value = list(matching_urls)
        url_items = [self._get_item(u, source_id) for u in matching_urls]
        tester.lookup_matching.return_value = url_items
        if tester not in self.tested_instance.url_testers:
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
        ''' Set urls expected to be matched during a test

        The method groups given urls by their source ids: identifiers
         of services expected to report urls associated with them as
         matching. Then, mocks representing url testers are added
         to the tested instance of UrlTesterChain. They are shuffled
         to ensure some of mocked services reporting a match
         will be queried before some that do not.

        :param urls: a dictionary containing
        '''
        by_source_id = defaultdict(list)
        for url, ids in list(urls.items()):
            for i in ids:
                by_source_id[i].append(url)
        for i, urls in list(by_source_id.items()):
            self._add_url_tester(i, urls)
        shuffle(self.tested_instance.url_testers)

    def test_any_match_expecting_true(self):
        self._test_any_match_for(self.url_to_source_id)

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
        ('any_match_raises_value_error', 'any_match', ValueError),
        ('any_match_raises_unknown_code_error', 'any_match', UnknownCodeError),
        ('lookup_matching_raises_value_error', 'lookup_matching', ValueError),
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


class CachedIterableTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for CachedIterable class

    :var iterator_mock: a mock object representing iterator injected
    into the tested instance
    :var cache: a list of values set as initial cache for tested instance
    :var tested_instance: an instance of CachedIterable to be tested
    '''
    def setUp(self):
        self.iterator_mock = MagicMock()
        self.cache = range(3)
        self.tested_instance = CachedIterable(self.iterator_mock, self.cache)

    def test_cached_returned_first(self):
        for i in self.tested_instance:
            if i == self.cache[-1]:
                break
        self.iterator_mock.__iter__.assert_not_called()

    def test_fixed_order(self):
        self.iterator_mock.__iter__.return_value = range(4, 10)
        first_run_result = list(self.tested_instance)[:9]
        second_run_result = list(self.tested_instance)[:9]
        self.assertSequenceEqual(first_run_result, second_run_result)


class GeneralizedUrlTesterTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for GeneralizedUrlTester class

    :var no_resolution_setup: a parameter setup for test methods
    requiring no explicit parameter to use (or not use)
    redirect resolution in tested calls. Contains names of
    method of tested instance to be called
    :var common_setup: a parameter setup for test methods
    testing calls with and without redirect resolution, depending
    on value of a parameter, with False assumed as default.
    Contains names of method of tested instance to be called.
    :var test_urls: a list of urls passed as argument to methods of
    tested_instance
    :var tested_instance: instance of GeneralizedUrlTester to be
    tested.
    :var whitelist_mock: an object representing an instance of
    whitelist used by tested_instance
    :var url_tester_mock: an object representing a url tester instance
    to be used by tested instance
    :var resolver_mock: an object representing an instance of
    redirect resolver to be used by tested instance
    '''
    test_urls = ['http:abc.com', 'http://def.com', 'http://xyz.com']
    no_resolution_setup = [
        ['any_match'],
        ['filter_matching'],
        ['lookup_matching'],
    ]
    common_setup = [
        ['any_match', True],
        ['filter_matching', True],
        ['lookup_matching', True]
    ] + no_resolution_setup

    def setUp(self):
        self.whitelist_mock = Mock()
        self.whitelist_mock.filter_matching.return_value = MagicMock()
        self.resolver_mock = Mock()
        self.resolver_mock.get_urls_and_locations.return_value = MagicMock()
        self.url_tester_mock = Mock()
        self.tested_instance = GeneralizedUrlTester(
            self.url_tester_mock,
            self.whitelist_mock,
            self.resolver_mock
        )

    def _call_for(self, function_name, resolve_redirects):
        function = getattr(self.tested_instance, function_name)
        return function(self.test_urls, resolve_redirects)

    @parameterized.expand(common_setup)
    def test_whitelist_used_with(self, function_name, resolve_redirects=False):
        self._call_for(function_name, resolve_redirects)
        urls_and_locations = self.test_urls
        if resolve_redirects:
            urls_and_locations = self.resolver_mock.get_urls_and_locations()
        whitelist_method = self.whitelist_mock.filter_matching
        whitelist_method.assert_called_once_with(
            urls_and_locations
        )

    @parameterized.expand(no_resolution_setup)
    def test_resolution_with(self, function_name):
        ''' Redirect resolution must be performed during all calls
        that receive resolve_redirects=True as argument '''
        self._call_for(function_name, True)
        resolver_function = self.resolver_mock.get_urls_and_locations
        resolver_function.assert_called_once_with(self.test_urls)

    @parameterized.expand(no_resolution_setup)
    def test_no_resolution_with(self, function_name):
        ''' Redirect resolution must not be performed during all calls
        that receive resolve_redirects=True as argument '''
        self._call_for(function_name, False)
        self.resolver_mock.assert_not_called()

    @parameterized.expand(common_setup)
    def test_url_tester_results_for(self, function_name,
                                    resolve_redirects=False):
        ''' Each method must return result of a method of url_tester
        called during its execution'''
        url_tester_function = getattr(self.url_tester_mock, function_name)
        expected = url_tester_function()
        actual = self._call_for(function_name, resolve_redirects)
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
