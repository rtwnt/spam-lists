# -*- coding: utf-8 -*-
'''
This module contains unit tests for functions and classes provided by
spam_lists.structures module
'''
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import str, range, object
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidHostError, InvalidHostnameError
from spam_lists.structures import Hostname, create_host, IPv4Address, \
    IPv6Address
from test.compat import unittest, Mock, patch, MagicMock


class HostnameTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for Hostname class

    :var superdomain_str: a string value representing a parent of
     a domain used to create tested instance
    :var domain_str: a string value used as an argument to
    constructor when creating tested instance
    :var subdomain_str: a string value representing a child domain
    to the one used to create tested instance
    :var superdomain: a Hostname instance representing a parent
    of the tested instance
    :var domain: a Hostname instance to be tested
    :var subdomain: a Hostname instance representing a child
    of the tested instance
    :var unrelated_domain: a Hostname instance representing
    a domain unrelated to the one represented by tested instance
    '''
    superdomain_str = 'superdomain.com'
    domain_str = 'domain.'+superdomain_str
    subdomain_str = 'subdomain.'+domain_str
    superdomain = Hostname(superdomain_str)
    domain = Hostname(domain_str)
    subdomain = Hostname(subdomain_str)
    unrelated_domain = Hostname('other.com')

    @parameterized.expand([
        ('hostname', '-e'),
        ('hostname', '/e'),
        ('argument', 123)
    ])
    def test_constructor_for_invalid(self, _, value):
        self.assertRaises(InvalidHostnameError, Hostname, value)

    @parameterized.expand([
        ('unrelated_domain', unrelated_domain, False),
        ('a_subdomain', subdomain, False),
        ('non_hostname_object', '123.4.5.11', False),
        ('the_same_domain', domain, True),
        ('a_superdomain', superdomain, True)
    ])
    def test_is_subdomain_for(self, _, other, expected):
        actual = self.domain.is_subdomain(other)
        if expected:
            self.assertTrue(actual)
        else:
            self.assertFalse(actual)


class IPAddressTestMixin(object):
    ''' A class providing tests for subclasses of IPAddress

    :var class_to_test: a subclass of IPAddress to be tested
    '''
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
        self.tested_instance.value = MagicMock()

    def tearDown(self):
        self.value_constructor_patcher.stop()
        self.name_from_ip_patcher.stop()

    def test_constructor_for_invalid_argument(self):
        self.value_constructor_mock.side_effect = ValueError
        self.assertRaises(
            self.class_to_test.invalid_ip_error_type,
            self.class_to_test,
            Mock()
        )

    def test_create_relative_domain_for_ip(self):
        self.tested_instance.relative_domain

        self.name_from_ip_mock.assert_called_once_with(
            str(self.tested_instance.value)
        )
        name = self.name_from_ip_mock.return_value
        name.relativize.assert_called_once_with(
            self.class_to_test.reverse_domain
        )

    def test_relative_domain_value(self):
        name = self.name_from_ip_mock.return_value
        expected = name.relativize.return_value
        actual = self.tested_instance.relative_domain
        self.assertEqual(expected, actual)

    def test_lt_for_smaller_value(self):
        self.tested_instance.value.__lt__.return_value = False
        self.assertFalse(self.tested_instance < Mock())

    def test_lt_for_larger_value(self):
        self.tested_instance.value.__lt__.return_value = True
        self.assertTrue(self.tested_instance < Mock())

    def test_lt_for_ip_of_different_version(self):
        self.tested_instance.value.__lt__.side_effect = TypeError
        self.assertEqual(
            NotImplemented,
            self.tested_instance.__lt__(self.class_to_test(Mock()))
        )


class IPv4AddressTest(IPAddressTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    class_to_test = IPv4Address


class IPv6AddressTest(IPAddressTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    class_to_test = IPv6Address


class CreateHostTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for create_host function

    :var factories: a list of mocks representing factories used by
    the function during tests
    '''
    def setUp(self):
        self.factories = tuple(Mock() for _ in range(5))

    @parameterized.expand([
        ('v4', '127.0.0.1'),
        ('v6', '2001:db8:abc:125::45'),
    ])
    def test_host_for_ip(self, _, value):
        ip_address = self.factories[0]
        expected = ip_address(value)
        actual = create_host(self.factories, value)
        self.assertEqual(actual, expected)

    def test_host_for_hostname(self):
        ''' The function is expected to return an object
        returned by a host factory for given hostname'''
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
        for factory in self.factories:
            factory.side_effect = InvalidHostError
        self.assertRaises(InvalidHostError, create_host, self.factories, value)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
