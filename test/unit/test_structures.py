# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import str, range, object
from dns import reversename
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidHostError, InvalidHostnameError, \
    InvalidIPv4Error, InvalidIPv6Error
from spam_lists.structures import Hostname, IPv4Address, IPv6Address, \
    create_host
from test.compat import unittest, Mock


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


class IpAddressTestMixin(object):
    ''' A class providing tests for subclasses of IPAddress

    The classes using this mixin are expected to have
     the following attributes:
    :var constructor: a constructor of an IPAddress subclass instance
    :var value_error_type: a type of a ValueError raised by
     the constructor when provided with an invalid value
    :var reverse_name_root: a root of a reverse domain representing
    ip address created with the constructor
    :var ip_address: a string value of ip address passed to
     the constructor
    '''
    @parameterized.expand([
                           ('ipv4', '299.0.0.1'),
                           ('ipv4', '99.22.33.1.23'),
                           ('ipv6', '2001:db8:abc:125::4h'),
                           ('ipv6', '2001:db8:abcef:125::43'),
                           ('hostname', 'abc.def.gh'),
                           ('non_unicode_ipv4', '299.0.0.1')
                           ])
    def test_constructor_for_invalid(self, _, value):
        self.assertRaises(self.value_error_type, self.constructor, value)

    def test_relative_domain_for_ip(self):
        ip_object = self.constructor(self.ip_address)
        reversed_name = reversename.from_address(str(ip_object))
        expected = reversed_name.relativize(self.reverse_name_root)
        self.assertEqual(expected, ip_object.relative_domain)


class IPv4AddressTest(IpAddressTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    reverse_name_root = reversename.ipv4_reverse_domain
    constructor = IPv4Address
    value_error_type = InvalidIPv4Error
    ip_address = '122.44.55.99'


class IPv6AddressTest(IpAddressTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    reverse_name_root = reversename.ipv6_reverse_domain
    constructor = IPv6Address
    value_error_type = InvalidIPv6Error
    ip_address = 'fe80::0202:b3ff:fe1e:8329'


class CreateHostTest(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for create_host function

    :var factories: a list of mocks representing factories used by
    the function during tests
    '''
    def setUp(self):
        self.factories = [Mock() for _ in range(5)]

    @parameterized.expand([
                           ('v4',  '127.0.0.1'),
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
