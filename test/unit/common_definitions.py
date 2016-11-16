# -*- coding: utf-8 -*-
"""Classes and functions shared by some of the test_ modules."""

from __future__ import unicode_literals

from builtins import object  # pylint: disable=redefined-builtin
from future.moves.urllib.parse import urlparse
from nose_parameterized import parameterized
from types import GeneratorType

from spam_lists.exceptions import InvalidURLError, InvalidHostError
from spam_lists.structures import AddressListItem
from test.compat import MagicMock, patch, lru_cache


class URLTesterTestBaseMixin(object):
    """Common tests for URL-testing classes."""

    valid_urls = ['http://test.com', 'http://127.33.22.11',
                  'https://[2001:ddd:ccc:123::55]']

    def _test_any_match_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        self.assertTrue(
            self.tested_instance.any_match(
                self.valid_urls + list(matching_urls)
            )
        )

    def _test_any_match_returns_false(self, not_matching_urls):
        self.assertFalse(self.tested_instance.any_match(not_matching_urls))

    def _test_lookup_matching_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        expected = self._get_expected_items_for_urls(matching_urls)
        actual = list(
            self.tested_instance.lookup_matching(
                self.valid_urls + list(matching_urls)
            )
        )

        self.assertCountEqual(expected, actual)

    def _test_filter_matching_for(self, matching_urls):
        self._set_matching_urls(matching_urls)
        actual = list(
            self.tested_instance.filter_matching(
                self.valid_urls + list(matching_urls)
            )
        )

        self.assertCountEqual(matching_urls, actual)

    def test_any_match_returns_false(self):
        """Test if False is returned for valid, non-malicious URLs."""
        self._test_any_match_returns_false(self.valid_urls)


class URLTesterTestMixin(URLTesterTestBaseMixin):
    """Common tests for URL-testing classes.

    :cvar classification: expected value of classification attribute
    of instances of AddressListItem to be returned by
    lookup_matching(urls) method
    :cvar valid_url_input: test arguments, each containing
    a suffix for a name of a test method to be generated and a list
    of URLs to be passed to a tested method.

    Each list of URLs contains a value.
    :cvar valid_url_list_input: test arguments, each containing
    a suffix for a name of a test method to be generated and a list
    of URLs to be passed to a tested method
    """

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
    def test_query_for_invalid_url_with(
            self,
            function_name,
            is_valid_url_mock
    ):
        """Test if the method raises InvalidURLError.

        :param function_name: name of a method to be tested
        :param is_valid_url_mock: mock of is_valid_url function
        """
        invalid_url = 'http://invalid.url.com'
        is_valid_url_mock.side_effect = lambda u: u != invalid_url
        function = getattr(self.tested_instance, function_name)
        with self.assertRaises(InvalidURLError):
            function(self.valid_urls + [invalid_url])

    @parameterized.expand(valid_url_input)
    def test_any_match_returns_true_for(self, _, matching_urls):
        """Test if True is returned for matching URLs.

        :param matching_urls: URL values set up to be recognized as
        matching
        """
        self._test_any_match_for(matching_urls)

    @parameterized.expand(valid_url_list_input)
    def test_lookup_matching_for(self, _, matching_urls):
        """Test if matching items are returned for matching URLs.

        :param matching_urls: URL values set up to be recognized as
        matching
        """
        self._test_lookup_matching_for(matching_urls)

    @parameterized.expand(valid_url_list_input)
    def test_filter_matching_for(self, _, matching_urls):
        """Test if matching URLs are returned.

        :param matching_urls: URL values set up to be recognized as
        matching
        """
        self._test_filter_matching_for(matching_urls)

    def _get_expected_items(self, values):
        def get_item(item):
            return AddressListItem(
                item,
                self.tested_instance,
                self.classification
            )
        return [get_item(v) for v in values]


def get_hosts(urls):
    """Get hosts extracted from URLs.

    :param urls: URL addresses from which the function extracts hosts
    :returns: a list of hosts extracted from the URLs
    """
    return [urlparse(u).hostname for u in urls]


class HostListTestMixin(URLTesterTestMixin):
    """Common tests for classes querying for hosts.

    :cvar valid_host_input: test arguments, each containing a suffix
    for a name of a test method to be generated and a valid hostname
    or IP address to be passed to a tested method
    """

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
        """Test if False is returned for a host of an unsupported type.

        An instance of a tested class may represent a list of hosts of
        a specific type, or a client for a list containing specific
        types of hosts. Calling the method of such an object with
        a host of other types as its argument should result in
        the method returning False.
        """
        function = self.tested_instance.__contains__
        actual = self._get_result_for_invalid_host(function)
        self.assertFalse(actual)

    def test_lookup_for_invalid_host(self):
        """Test if None is returned for a host of an unsupported type.

        An instance of a tested class may represent a list of hosts of
        a specific type, or a client for a list containing specific
        types of hosts. Calling lookup method of such an object with
        a host of other types as its argument should result in
        the method returning None.
        """
        function = self.tested_instance.lookup
        actual = self._get_result_for_invalid_host(function)
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
        """Test if InvalidHostError is raised for an invalid host.

        :param function_name: a name of a method to be tested
        :param is_valid_host_mock: a mock for the is_valid_host function
        """
        function = getattr(self.tested_instance, function_name)
        invalid_host = 'invalid.com'
        is_valid_host_mock.side_effect = lambda h: h != invalid_host
        with self.assertRaises(InvalidHostError):
            function(invalid_host)

    @parameterized.expand(valid_host_input)
    def test_contains_for_listed(self, _, value):
        """Test if True is returned for a matching value.

        :param value: a host value set up to be recognized as matching
        """
        self._set_matching_hosts([value])
        self.assertTrue(value in self.tested_instance)

    @parameterized.expand(valid_host_input)
    def test_contains_for_not_listed(self, _, value):
        """Test if False is returned for a missing value.

        :param value: a host value set up as not listed
        """
        self.assertFalse(value in self.tested_instance)

    @parameterized.expand(valid_host_input)
    def test_lookup_for_listed(self, _, value):
        """Test if the method returns expected value for listed host.

        :param value: a host value set up as listed
        """
        expected = self._get_expected_items([value])[0]
        self._set_matching_hosts([value])
        self.assertEqual(self.tested_instance.lookup(value), expected)

    @parameterized.expand(valid_host_input)
    def test_lookup_for_not_listed(self, _, value):
        """Test if None is returned for a missing host.

        :param value: a host value set up as not listed
        """
        self.assertIsNone(self.tested_instance.lookup(value))


@lru_cache()
def host_list_host_factory(host):
    """Get a mock object representing a host.

    :param host: a host value to be represented by the mock
    :returns: an instance of Mock for an object representing given host
    """
    host_object = MagicMock()
    host_object.to_unicode.return_value = host
    return host_object


class TestFunctionDoesNotHandleMixin(object):
    """A mixin containing a test for expected exception bubbling."""

    def _test_function_does_not_handle(
            self,
            exception_type,
            exception_origin,
            function,
            *args,
            **kwargs
    ):
        """Test if an error raised by a dependency is not handled.

        :param exception_type: a type of exception to be raised
        :param exception_origin: a function raising the error,
        represented by an instance of Mock
        :param function: a function to be tested
        :param *args: positional arguments to be passed to
        the tested function
        :param **kwargs: keyword arguments to be passed to
        the tested function
        """
        exception_origin.side_effect = exception_type
        with self.assertRaises(exception_type):
            result = function(*args, **kwargs)
            if isinstance(result, GeneratorType):
                list(result)
