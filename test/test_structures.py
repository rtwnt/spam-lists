# -*- coding: utf-8 -*-


import unittest

from mock import Mock
from nose_parameterized import parameterized
from dns import reversename

from spam_lists.structures import get_create_host, Hostname, IPv4Address,\
IPv6Address, SimpleClassificationCodeResolver, SumClassificationCodeResolver
from spam_lists.exceptions import InvalidHostError, InvalidHostnameError,\
InvalidIPv4Error, InvalidIPv6Error, UnknownCodeError


class BaseClassificationCodeResolverTest(object):
    
    def setUp(self):
        self.code_item_class = {}
        self.resolver = self.factory(self.code_item_class)
        
class SimpleClassificationCodeResolverTest(
                                           BaseClassificationCodeResolverTest,
                                           unittest.TestCase
                                           ):
    
    factory = SimpleClassificationCodeResolver
        
    def test_call_for_valid_key(self):
        
        key = 4
        self.code_item_class.update({key: 'TestClass'})
        
        expected = self.code_item_class[key],
        actual = self.resolver(key)
        
        self.assertEqual(expected, actual)
            
    def test_call_for_invalid_key(self):
        
        self.assertRaises(UnknownCodeError, self.resolver, 4)
            
class SumClassificationCodeResolverTest(
                                        BaseClassificationCodeResolverTest,
                                        unittest.TestCase
                                        ):
    
    factory = SumClassificationCodeResolver
        
    def _set_code_item_class(self, code_class):
        self.code_item_class.update(code_class)
            
    @parameterized.expand([
                           ('simple_valid_key', [2]),
                           ('sum_of_keys', [2, 4, 8])
                           ])
    def test_getitem_for(self, _, keys):
        
        classes = {k: 'Class #{}'.format(k) for k in keys}
        self._set_code_item_class(classes)
        
        expected = tuple(classes.values())
        actual = self.resolver(sum(keys))
        
        self.assertItemsEqual(expected, actual)
        
    @parameterized.expand([
                           ('key', [16]),
                           ('sum_of_keys', [2, 4, 16])
                           ])
    def test_getitem_for_invalid(self, _, keys):
        
        self._set_code_item_class({2: 'Class: 2', 4: 'Class:4'})
        
        self.assertRaises(UnknownCodeError, self.resolver, sum(keys))


class HostnameTest(unittest.TestCase):
    
    hostname_pl = Hostname('hostname.pl')
    
    subdomain_hostname_pl = Hostname('subdomain.hostname.pl')
    
    @parameterized.expand([
                           ('hostname', '-e'),
                           ('hostname', '/e'),
                           ('argument', 123)
                           ])
    def test_constructor_for_invalid(self, _, value):
        
        self.assertRaises(InvalidHostnameError, Hostname, value)
        
    @parameterized.expand([
                           ('the_same_domain', Hostname('subdomain.hostname.pl')),
                           ('a_superdomain', hostname_pl)
                           ])
    def test_is_subdomain_returns_true_for(self, _, other):
        
        self.assertTrue(self.subdomain_hostname_pl.is_subdomain(other))
        
    @parameterized.expand([
                       ('unrelated_domain', Hostname('other.com')),
                       ('a_subdomain', subdomain_hostname_pl),
                       ('non_hostname_object', '123.4.5.11')
                       ])
    def test_is_subdomain_returns_false_for(self, _, other):
        
        self.assertFalse(self.hostname_pl.is_subdomain(other))

class IpAddressTest(object):
    
    @parameterized.expand([
                           ('ipv4', u'299.0.0.1'),
                           ('ipv4', u'99.22.33.1.23'),
                           ('ipv6', u'2001:db8:abc:125::4h'),
                           ('ipv6', u'2001:db8:abcef:125::43'),
                           ('hostname', u'abc.def.gh'),
                           ('non_unicode_ipv4', '299.0.0.1')
                           ])
    def test_constructor_for_invalid(self, _, value):
        
        self.assertRaises(self.value_error_type, self.constructor, value)
        
    def test_relative_domain_for_ip(self):
        ip = self.constructor(self.ip_address)
        reversed_name = reversename.from_address(str(ip))
        expected = reversed_name.relativize(self.reverse_name_root)
        
        self.assertEqual(expected, ip.relative_domain)
    
class IPv4AddressTest(IpAddressTest, unittest.TestCase):
    reverse_name_root = reversename.ipv4_reverse_domain
    constructor = IPv4Address
    value_error_type = InvalidIPv4Error
    ip_address = u'122.44.55.99'

class IPv6AddressTest(IpAddressTest, unittest.TestCase):
    reverse_name_root = reversename.ipv6_reverse_domain
    constructor = IPv6Address
    value_error_type = InvalidIPv6Error
    ip_address = u'fe80::0202:b3ff:fe1e:8329'
        
class CreateHostTest(unittest.TestCase):
    
    def setUp(self):
        self.factories = [Mock() for _ in range(5)]
        self.create_host = get_create_host(*self.factories)
        
    @parameterized.expand([
                           ('v4',  u'127.0.0.1'),
                           ('v6', u'2001:db8:abc:125::45'),
                           ])
    def test_host_for_ip(self, _, value):
        ip_address = self.factories[0]
        ip_address.return_value = ip_address
        
        expected = ip_address(value)
        actual = self.create_host(value)
        
        self.assertEqual(actual, expected)
        
    def test_host_for_hostname(self):
        
        for i, factory in enumerate(self.factories):
            if i != 1:
                factory.side_effect = InvalidHostError
        
        host_factory = self.factories[1]
        
        host_value = 'abc.com'
        
        expected = host_factory(host_value)
        actual = self.create_host(host_value)
        
        self.assertEqual(expected, actual)
        
    @parameterized.expand([
                           ('ipv4', u'299.0.0.1'),
                           ('ipv4', u'99.22.33.1.23'),
                           ('ipv6', u'2001:db8:abc:125::4h'),
                           ('ipv6', u'2001:db8:abcef:125::43'),
                           ('hostname', '-e'),
                           ('hostname', '/e')
                           ])
    def test_host_for_invalid(self, _, value):
        
        for f in self.factories:
            f.side_effect = InvalidHostError
        
        self.assertRaises(InvalidHostError, self.create_host, value)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()