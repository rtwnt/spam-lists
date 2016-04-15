# -*- coding: utf-8 -*-
'''
This module contains definitions used by some of the test_ modules
'''
from __future__ import unicode_literals

from types import GeneratorType

from builtins import object


class UrlTesterTestBase(object):
    ''' A class providing basic methods for performing tests for classes
    having any_match, filter_matching and lookup_matching methods

    The methods are to be used to write and generate actual test methods
    '''
    valid_urls = ['http://test.com', 'http://127.33.22.11', 'https://[2001:ddd:ccc:123::55]']

    def _test_any_match_returns_true_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        self.assertTrue(self.tested_instance.any_match(self.valid_urls + list(matching_urls)))

    def _test_any_match_returns_false(self, not_matching_urls):
        self.assertFalse(self.tested_instance.any_match(not_matching_urls))

    def _test_lookup_matching_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        expected = self._get_expected_items_for_urls(matching_urls)
        actual = list(self.tested_instance.lookup_matching(self.valid_urls + list(matching_urls)))

        self.assertCountEqual(expected, actual)

    def _test_filter_matching_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        actual = list(self.tested_instance.filter_matching(self.valid_urls + list(matching_urls)))

        self.assertCountEqual(matching_urls, actual)

    def test_any_match_returns_false(self):
        self._test_any_match_returns_false(self.valid_urls)


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

