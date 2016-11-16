# -*- coding: utf-8 -*-
"""Tests for functions and classes defined in spam_lists.structures."""
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import str, range, object
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidHostError, InvalidHostnameError
from spam_lists.structures import (
    Hostname, create_host, IPv4Address, IPv6Address
)
from test.compat import unittest, Mock, patch, MagicMock


class BaseHostTest(object):
    """Tests for subclasses of Host class.

    :ivar tested_instance: an instance of tested class to be used
    in tests
    :cvar class_to_test: a class to be tested
    """

    def setUp(self):
        self.tested_instance.value = MagicMock()

    def test_lt_for_smaller_value(self):
        """Test if False is returned for a smaller value."""
        self.tested_instance.value.__lt__.return_value = False
        self.assertFalse(self.tested_instance < Mock())

    def test_lt_for_larger_value(self):
        """Test if True is returned for a larger value."""
        self.tested_instance.value.__lt__.return_value = True
        self.assertTrue(self.tested_instance < Mock())

    def test_lt_for_missing_value_attribute(self):
        """Test for TypeError when value misses a 'value' attribute."""
        other = Mock(spec=[])
        self.assertRaises(
            TypeError,
            self.tested_instance.__lt__,
            other
        )

    @parameterized.expand([
        ('type_error', TypeError),
        ('not_implemented_return_value', lambda o: NotImplemented)
    ])
    def test_lt_for_missing_to_unicode_method_to_handle(self, _, side_effect):
        """Test for TypeError when the other misses to_unicode method.

        :param side_effect: a side effect for __lt__ method of value
        attribute of the tested instance.
        """
        other = Mock(spec=['value'])
        value = MagicMock()
        value.__lt__.side_effect = side_effect
        self.tested_instance.value = value
        self.assertRaises(
            TypeError,
            self.tested_instance.__lt__,
            other
        )


class HostnameTest(BaseHostTest, unittest.TestCase):
    """Tests for Hostname class.

    :cvar superdomain_str: a string value representing a parent of
    a domain used to create tested instance
    :cvar domain_str: a string value used as an argument to
    constructor when creating tested instance
    :cvar subdomain_str: a string value representing a child domain
    to the one used to create tested instance
    :cvar superdomain: a Hostname instance representing a parent
    of the tested instance
    :cvar domain: a Hostname instance to be tested
    :cvar subdomain: a Hostname instance representing a child
    of the tested instance
    :cvar unrelated_domain: a Hostname instance representing
    a domain unrelated to the one represented by tested instance
    """

    # pylint: disable=too-many-public-methods

    class_to_test = Hostname
    superdomain_str = 'superdomain.com'
    domain_str = 'domain.'+superdomain_str
    subdomain_str = 'subdomain.'+domain_str
    superdomain = class_to_test(superdomain_str)
    domain = class_to_test(domain_str)
    subdomain = class_to_test(subdomain_str)
    unrelated_domain = class_to_test('other.com')
    tested_instance = class_to_test('compared.com')

    @parameterized.expand([
        ('hostname', '-e'),
        ('hostname', '/e'),
        ('argument', 123)
    ])
    def test_constructor_for_invalid(self, _, value):
        """Test if InvalidHostnameError is raised.

        :param value: a value used to construct an instance of
        the tested class
        """
        self.assertRaises(InvalidHostnameError, Hostname, value)

    @parameterized.expand([
        ('unrelated_domain', unrelated_domain, False),
        ('a_subdomain', subdomain, False),
        ('non_hostname_object', '123.4.5.11', False),
        ('the_same_domain', domain, True),
        ('a_superdomain', superdomain, True)
    ])
    def test_is_subdomain_for(self, _, other, expected):
        """Test if an expected value is returned.

        :param other: the other object passed as argument of
        the tested method
        :param expected: a boolean value expected to be returned
        for given argument
        """
        actual = self.domain.is_subdomain(other)
        if expected:
            self.assertTrue(actual)
        else:
            self.assertFalse(actual)

    @parameterized.expand([
        ('returns_false', False),
        ('returns_true', True)
    ])
    def test_lt_for_not_comparable_values(self, _, result):
        self.tested_instance.value.__lt__.side_effect = TypeError

        str_value = self.tested_instance.to_unicode()
        str_value.__lt__.return_value = result
        other = Mock()

        assertion = self.assertTrue if result else self.assertFalse
        assertion(self.tested_instance < other)


class IPAddressTestMixin(BaseHostTest):
    """Tests for subclasses of IPAddress.

    :cvar class_to_test: a subclass of IPAddress to be tested
    """

    def setUp(self):
        self.value_constructor_patcher = patch.object(
            self.class_to_test,
            'factory',
            Mock()
        )
        self.value_constructor_mock = self.value_constructor_patcher.start()

        self.name_from_ip_patcher = patch('spam_lists.structures.name_from_ip')
        self.name_from_ip_mock = self.name_from_ip_patcher.start()

        self.tested_instance = self.class_to_test(Mock())
        super(IPAddressTestMixin, self).setUp()

    def tearDown(self):
        self.value_constructor_patcher.stop()
        self.name_from_ip_patcher.stop()

    def test_constructor_for_invalid_argument(self):
        """Test if an error is raised for an invalid argument."""
        self.value_constructor_mock.side_effect = ValueError
        self.assertRaises(
            self.class_to_test.invalid_ip_error_type,
            self.class_to_test,
            Mock()
        )

    def test_create_relative_domain_for_ip(self):
        """Test if accessing relative_domain creates a relative domain."""
        # pylint: disable=W0104
        self.tested_instance.relative_domain

        self.name_from_ip_mock.assert_called_once_with(
            str(self.tested_instance.value)
        )
        name = self.name_from_ip_mock.return_value
        name.relativize.assert_called_once_with(
            self.class_to_test.reverse_domain
        )

    def test_relative_domain_value(self):
        """Test if relative_domain has an expected value."""
        name = self.name_from_ip_mock.return_value
        expected = name.relativize.return_value
        actual = self.tested_instance.relative_domain
        self.assertEqual(expected, actual)

    def test_lt_for_not_comparable_values(self):
        """Test a result of comparing non-comparable values.

        The result is expected to be equal to that of comparison of
        string values of both objects.
        """
        self.tested_instance.value.__lt__.side_effect = TypeError

        str_value = self.tested_instance.to_unicode()
        other = Mock()
        other_str_value = 'other_str'
        other.to_unicode.return_value = other_str_value

        self.assertEqual(
            str_value < other_str_value,
            self.tested_instance < other
        )


class IPv4AddressTest(IPAddressTestMixin, unittest.TestCase):
    """Tests for IPv4Address class."""

    # pylint: disable=too-many-public-methods
    class_to_test = IPv4Address


class IPv6AddressTest(IPAddressTestMixin, unittest.TestCase):
    """Tests for IPv6Address class."""

    # pylint: disable=too-many-public-methods
    class_to_test = IPv6Address


class CreateHostTest(unittest.TestCase):
    """Tests for create_host function.

    :cvar factories: a list of mocks representing factories used by
    the function during tests
    """

    # pylint: disable=too-many-public-methods

    def setUp(self):
        self.factories = tuple(Mock() for _ in range(5))

    @parameterized.expand([
        ('v4', '127.0.0.1'),
        ('v6', '2001:db8:abc:125::45'),
    ])
    def test_host_for_ip(self, _, value):
        """Test return value of the function for IP address argument.

        :param value: an IP address to be passed to the create_host
        function
        """
        ip_address = self.factories[0]
        expected = ip_address(value)
        actual = create_host(self.factories, value)
        self.assertEqual(actual, expected)

    def test_host_for_hostname(self):
        """Test return value of the function for hostname argument.

        The function is expected to return an object returned by a host
        factory for given hostname.
        """
        for i, factory in enumerate(self.factories):
            if i != 1:
                factory.side_effect = InvalidHostError
        host_factory = self.factories[1]
        host_value = 'abc.com'
        expected = host_factory(host_value)
        actual = create_host(self.factories, host_value)
        self.assertEqual(expected, actual)

    @parameterized.expand([
        ('ipv4', '299.0.0.1'),
        ('ipv4', '99.22.33.1.23'),
        ('ipv6', '2001:db8:abc:125::4h'),
        ('ipv6', '2001:db8:abcef:125::43'),
        ('hostname', '-e'),
        ('hostname', '/e')
    ])
    def test_host_for_invalid(self, _, value):
        """Test for InvalidHostError when the argument is invalid.

        :param value: a value to be passed as the argument to
        the create_host function
        """
        for factory in self.factories:
            factory.side_effect = InvalidHostError
        self.assertRaises(InvalidHostError, create_host, self.factories, value)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
