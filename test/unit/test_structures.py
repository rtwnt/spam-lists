# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from builtins import str, range, object
from dns import reversename
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidHostError, InvalidHostnameError, \
InvalidIPv4Error, InvalidIPv6Error, UnknownCodeError
from spam_lists.structures import Hostname, IPv4Address, IPv6Address, \
SimpleClassificationCodeMap, SumClassificationCodeMap, create_host
from test.compat import unittest, Mock


class ClassificationCodeMapTestMixin(object):
    
    def setUp(self):
        self.code_item_class = {}
        self.classification_code_map = self.factory(self.code_item_class)
        
class SimpleClassificationCodeMapTest(
                                           ClassificationCodeMapTestMixin,
                                           unittest.TestCase
                                           ):
    
    factory = SimpleClassificationCodeMap
        
    def test_getitem_for_valid_key(self):
        
        key = 4
        self.code_item_class.update({key: 'TestClass'})
        
        expected = set([self.code_item_class[key]])
        actual = self.classification_code_map[key]
        
        self.assertEqual(expected, actual)
            
    def test_getitem_for_invalid_key(self):
        
        self.assertRaises(UnknownCodeError, self.classification_code_map.__getitem__, 4)
            
class SumClassificationCodeMapTest(
                                        ClassificationCodeMapTestMixin,
                                        unittest.TestCase
                                        ):
    
    factory = SumClassificationCodeMap
        
    def _set_code_item_class(self, code_class):
        self.code_item_class.update(code_class)
            
    @parameterized.expand([
                           ('simple_valid_key', [2]),
                           ('sum_of_keys', [2, 4, 8])
                           ])
    def test_getitem_for(self, _, keys):
        
        classes = {k: 'Class #{}'.format(k) for k in keys}
        self._set_code_item_class(classes)
        
        expected = set(classes.values())
        actual = self.classification_code_map[sum(keys)]
        
        self.assertCountEqual(expected, actual)
        
    @parameterized.expand([
                           ('key', [16]),
                           ('sum_of_keys', [2, 4, 16])
                           ])
    def test_getitem_for_invalid(self, _, keys):
        
        self._set_code_item_class({2: 'Class: 2', 4: 'Class:4'})
        
        self.assertRaises(UnknownCodeError, self.classification_code_map.__getitem__, sum(keys))


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
        ip = self.constructor(self.ip_address)
        reversed_name = reversename.from_address(str(ip))
        expected = reversed_name.relativize(self.reverse_name_root)
        
        self.assertEqual(expected, ip.relative_domain)
    
class IPv4AddressTest(IpAddressTest, unittest.TestCase):
    reverse_name_root = reversename.ipv4_reverse_domain
    constructor = IPv4Address
    value_error_type = InvalidIPv4Error
    ip_address = '122.44.55.99'

class IPv6AddressTest(IpAddressTest, unittest.TestCase):
    reverse_name_root = reversename.ipv6_reverse_domain
    constructor = IPv6Address
    value_error_type = InvalidIPv6Error
    ip_address ='fe80::0202:b3ff:fe1e:8329'

        
class CreateHostTest(unittest.TestCase):
    
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
        
        for f in self.factories:
            f.side_effect = InvalidHostError
        
        self.assertRaises(InvalidHostError, create_host, self.factories, value)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()