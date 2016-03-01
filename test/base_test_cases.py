# -*- coding: utf-8 -*-

from spambl import AddressListItem
from nose_parameterized import parameterized

class BaseValueTesterTest(object):
    
    classification = ('TEST',)
    
    def _get_expected_items(self, values):
        item = lambda i: AddressListItem(i, self.tested_instance,
                                             self.classification)
        return [item(v) for v in values]


class BaseHostListTest(BaseValueTesterTest):
    ''' A common test case for all classes that represent
    a host list stored locally or by a remote service '''
    
    invalid_host_input = [
                          ('ipv4', u'255.0.120.1.1'),
                          ('ipv6', '2001:db8:abcef:123::42'),
                          ('host', '-aaa')
                          ]
    
    valid_host_input = [
                        ('ipv4', u'255.0.120.1'),
                        ('hostname', 'test.pl')
                        ]
    
    valid_ipv6 = '2001:ddd:ccc:111::33'
    
    __get_expected_items = BaseValueTesterTest._get_expected_items
    
    def _test_function_for_invalid(self, function, value):
        
        self.host_factory_mock.side_effect = ValueError
        self.assertRaises(ValueError, function, value)
        
    @parameterized.expand(invalid_host_input)
    def test_contains_for_invalid(self, _, value):
        
        self._test_function_for_invalid(self.tested_instance.__contains__, value)
        
    @parameterized.expand(invalid_host_input)
    def test_lookup_for_invalid(self, _, value):
        self._test_function_for_invalid(self.tested_instance.lookup, value)
        
    def _test_contains_for_listed(self, value):
        
        self._set_matching_hosts(value)
        self.assertTrue(value in self.tested_instance)
        
    def _test_contains_not_for_listed(self, value):
        
        self.assertFalse(value in self.tested_instance)
        
    def _test_lookup_for_listed(self, value):
        
        expected = self.__get_expected_items([value])[0]
        self._set_matching_hosts(value)
        self.assertEqual(self.tested_instance.lookup(value), expected)
        
    def _test_lookup_for_not_listed(self, value):
        
        self.assertIsNone(self.tested_instance.lookup(value))
        
    @parameterized.expand(valid_host_input)
    def test_contains_for_listed(self, _, value):
        self._test_contains_for_listed(value)
            
    @parameterized.expand(valid_host_input)
    def test_contains_for_not_listed(self, _, value):
        self._test_contains_not_for_listed(value)
                
    @parameterized.expand(valid_host_input)
    def test_lookup_for_listed(self, _, value):
        self._test_lookup_for_listed(value)
          
    @parameterized.expand(valid_host_input)  
    def test_lookup_for_not_listed(self, _, value):

        self._test_lookup_for_not_listed(value)
