# -*- coding: utf-8 -*-
"""Tests for functions and classes defined in spam_lists.validation."""
from __future__ import unicode_literals

import unittest

from builtins import object  # pylint: disable=redefined-builtin
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidURLError, InvalidHostError
from spam_lists.validation import (
    accepts_valid_urls, is_valid_url, accepts_valid_host
)
from test.compat import Mock, patch


class ValidationDecoratorTestMixin(object):
    """Tests for validators implemented as decorators and wrappers.

    :ivar validity_tester_patcher: an object used for patching
    a function responsible for testing validity of arguments of
    a decorated function
    :ivar validity_tester_mock: a mocked implementation for
    the validity tester
    :ivar obj: a mock representing object having the method decorated
    by the decorator
    :ivar function: a mock representing function to be decorated
    :ivar decorated_function: a result of applying decorator to
    the function

    Additionally, the test cases using this mixin are expected to have
    the following attributes:

    :cvar exception_type: a type of exception to be raised in case
    of a failed validation
    :cvar validity_tester: a fully qualified name of a function used by
    the tested wrapper as argument validator
    """
    def setUp(self):
        self.validity_tester_patcher = patch(self.validity_tester)
        self.validity_tester_mock = self.validity_tester_patcher.start()
        function = Mock()
        function.__name__ = str('function')
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
        self.assertRaises(
            self.exception_type,
            self.decorated_function,
            self.obj,
            value
        )
        self.function.assert_not_called()


class AcceptValidURLsTest(ValidationDecoratorTestMixin, unittest.TestCase):
    """Tests for accepts_valid_urls decorator."""

    # pylint: disable=too-many-public-methods
    exception_type = InvalidURLError
    decorator = staticmethod(accepts_valid_urls)
    validity_tester = 'spam_lists.validation.is_valid_url'

    @parameterized.expand([
        ('hostname', ['https://valid.com']),
        ('ipv4_host', ['http://122.34.59.109']),
        ('ipv6_host', ['http://[2001:db8:abc:123::42]'])
    ])
    def test_for_urls_with_valid(self, _, urls):
        """Test if no error is raised for URLs with valid hosts."""
        self._test_wrapper_for_valid(urls)

    @parameterized.expand([
        ('invalid_hostname', ['http://-abc.com']),
        ('invalid_schema', ['abc://hostname.com']),
        ('no_schema', ['hostname.com']),
        ('invalid_ipv4', ['http://999.999.999.999']),
        ('invalid_ipv4', ['http://127.0.0.0.1']),
        ('invalid_ipv6', ['http://[2001:db8:abcef:123::42]']),
        ('invalid_ipv6', ['http://[2001:db8:abch:123::42]'])])
    def test_for_urls_with(self, _, urls):
        """Test if InvalidURLError is raised for invalid URLs."""
        self._test_wrapper_for_invalid(urls)


class AcceptsValidHostTest(ValidationDecoratorTestMixin, unittest.TestCase):
    """Tests for accepts_valid_host decorator."""

    # pylint: disable=too-many-public-methods
    exception_type = InvalidHostError
    decorator = staticmethod(accepts_valid_host)
    validity_tester = 'spam_lists.validation.is_valid_host'

    @parameterized.expand([
        ('hostname', 'valid.com'),
        ('ipv4', '122.34.59.109'),
        ('ipv6', '2001:db8:abc:123::42')
    ])
    def test_for_valid(self, _, value):
        """Test if no error is raised for valid hosts."""
        self._test_wrapper_for_valid(value)

    @parameterized.expand([
        ('hostname', '-abc.com'),
        ('ipv4', '999.999.999.999'),
        ('ipv4', '127.0.0.0.1'),
        ('ipv6', '2001:db8:abcef:123::42'),
        ('ipv6', '2001:db8:abch:123::42')
    ])
    def test_for_invalid(self, _, value):
        """Test if InvalidHostError is raised for an invalid host."""
        self._test_wrapper_for_invalid(value)


class IsValidURLTest(unittest.TestCase):
    """Tests for is_valid_url function."""

    # pylint: disable=too-many-public-methods

    @parameterized.expand([
        ('http_scheme', 'http://test.url.com'),
        ('https_scheme', 'https://google.com'),
        ('ftp_scheme', 'ftp://ftp.test.com'),
        ('numeric_hostname', 'http://999.com'),
        ('final_slash', 'https://google.com/'),
        ('path_query_and_fragment', (
            'https://test.domain.com/path/element'
            '?var=1&var_2=3#fragment'
        )),
        ('query', 'http://test.domain.com?var_1=1&var_2=2'),
        ('path', 'http://test.domain.com/path'),
        ('path_and_fragment', 'http://test.domain.com/path#fragment'),
        (
            'query_and_fragment',
            'http://test.domain.com?var_1=1&var_2=2#fragment'
        ),
        ('port', 'https://test.domain.com:123'),
        ('authentication', 'https://abc:def@test.domain.com'),
        ('ipv4', 'http://255.0.0.255'),
        ('ipv6', 'http://[2001:db8:abc:125::45]'),
        ('no_schema', 'test.url.com', False),
        ('invalid_ipv4', 'http://266.0.0.266', False),
        ('invalid_ipv6', 'http://127.0.0.1.1', False),
        ('invalid_port', 'http://test.domain.com:aaa', False),
        ('no_top_level_domain', 'https://testdomaincom', False),
        ('invalid_hostname', 'http://-invalid.domain.com', False)
    ])
    def test_for_url_with(self, _, url, expected=True):
        """Test expected result for given URL.

        :param url: a URL for which the function is tested
        :param expected: a value expected to be returned by the function
        for the URL
        """
        actual = is_valid_url(url)
        if expected:
            self.assertTrue(actual)
        else:
            self.assertFalse(actual)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
