#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import DNSBL, UnknownCodeError, NXDOMAIN, HpHosts, DNSBLService, BaseDNSBLClient, NoRequiredContentError
from mock import Mock, patch
from ipaddress import ip_address as IP
from itertools import cycle
from __builtin__ import classmethod

hostnames  = 't1.pl', 't2.com', 't3.com.pl'
ips = IP(u'255.255.0.1'), IP(u'2001:DB8:abc:123::42')

host_collection = Mock()
host_collection.ips = ips
host_collection.hostnames = hostnames

empty_host_collection = Mock()
empty_host_collection.ips = ()
empty_host_collection.hostnames = ()


class DNSBLTest(unittest.TestCase):
    
    code_item_class = {1: 'Class #1', 2: 'Class #2'}
    query_suffix = 'query.suffix'
    
    @classmethod
    def setUpDNSBLInstance(cls):
        ''' Create DNSBL instance used for testing '''
        
        cls.dnsbl = DNSBL('test.dnsbl', cls.query_suffix, cls.code_item_class, True, True)
        
    @classmethod
    def setUpQueryPatch(cls):
        ''' Patch query function in spambl module
        
        The query function was originally imported from dns.resolver module
        '''
        
        cls.patcher = patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
    def setUpQuerySideEffect(self, nxdomain = False):
        ''' Set up side effect of patched query
        
        :param nxdomain: if True, the side effect will be raising NXDOMAIN exception, otherwise
        it will be an iterator cycling through supported return values
        '''
        side_effects = []
        
        for n in self.code_item_class:
            m = Mock()
            m.to_text.side_effect = '127.0.0.%d' % n
            side_effects.append([m])
        
        self.mocked_query.side_effect = NXDOMAIN('test NXDOMAIN exception') if nxdomain else cycle(side_effects)
    
    @classmethod
    def setUpClass(cls):
        cls.setUpDNSBLInstance()
        cls.setUpQueryPatch()
        
    def testGetClassification(self):
        ''' Test get_classification method of DNSBL instance '''
        
        msg = 'The expected value {} is not equal to received value {}'
        
        for key, value in self.code_item_class.iteritems():
            actual = self.dnsbl.get_classification(key)
            self.assertEqual(actual, value, msg.format(value, actual))
        
        self.assertRaises(UnknownCodeError, self.dnsbl.get_classification, 4)
        

    def testContainsAny(self):
        self.setUpQuerySideEffect()
        self.assertTrue(self.dnsbl.contains_any(host_collection))
        
        self.setUpQuerySideEffect(True)
        self.assertFalse(self.dnsbl.contains_any(empty_host_collection))
        self.assertFalse(self.dnsbl.contains_any(host_collection))
        
    def testLookup(self):
        self.setUpQuerySideEffect()
        actual_host_strings = [h.host for h in self.dnsbl.lookup(host_collection)]
        expected_host_strings = [n for n in ips + hostnames]
        
        self.assertSequenceEqual(actual_host_strings, expected_host_strings)
        
        self.setUpQuerySideEffect(True)
        self.assertSequenceEqual(self.dnsbl.lookup(empty_host_collection), [])
        self.assertSequenceEqual(self.dnsbl.lookup(host_collection), [])
        
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        
class HpHostsTest(unittest.TestCase):
    ''' Tests HpHosts methods '''
    
    classification = '[TEST]'
    
    @classmethod
    def setUpClass(cls):
        cls.hp_hosts = HpHosts('spambl_test_suite')
        
        cls.patcher = patch('spambl.get')
        cls.mocked_get = cls.patcher.start()
        
    def prepareGetReturnValue(self, listed, classification = False):
        ''' Set up return value of get 
        
        :param listed: if True, the content will contain 'Listed' string, else it will contain 'Not listed'
        :param classification: if True, a classification will be added to the content
        '''
        
        if listed:
            c = self.classification if classification else ''
            content = ','.join(('Listed', c))
        else:
            content = 'Not listed'
            
        self.mocked_get.return_value.content = content
    
    def testContains(self):
        ''' Test __contains__ method '''
        
        for listed in True, False:
            self.prepareGetReturnValue(listed)
            
            for k in ips:
                self.assertEqual(k in self.hp_hosts, listed)
                
    def testLookup(self):
        ''' Test lookup method'''
        
        self.prepareGetReturnValue(True, True)
         
        for host in ips + hostnames:
            self.assertEqual(self.hp_hosts.lookup(host).host, host)
            
        self.prepareGetReturnValue(False)
        
        for host in ips + hostnames:
            self.assertEqual(self.hp_hosts.lookup(host), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()

class DNSBLServiceTest(unittest.TestCase):
    
    code_item_class = {1: 'Class #1', 2: 'Class #2'}
    
    @classmethod
    def setUpClass(cls):
        
        cls.dnsbl_service = DNSBLService('test_service', 'test.suffix', cls.code_item_class, True, True)
        
        cls.patcher = patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
    def setUpQuerySideEffect(self, nxdomain = False):
        ''' Prepare side effects of mocked query function for tests
        
        :param nxdomain: if True, the side effect of calling query is set to be a sequence of
        return values, otherwise it is raising NXDOMAIN exception
        '''
        
        side_effect = NXDOMAIN('test NXDOMAIN exception')
        
        if not nxdomain:
            return_values = []
        
            for n in self.code_item_class:
                m = Mock()
                m.to_text.return_value = '127.0.0.%d' % n
                return_values.append([m])
            
            side_effect = cycle(return_values)
                
        self.mocked_query.side_effect = side_effect
        
    def testGetClassification(self):
        ''' Test get_classification method of DNSBL instance '''
        
        for key, value in self.code_item_class.iteritems():
            actual = self.dnsbl_service.get_classification(key)
            self.assertEqual(actual, value)
        
        self.assertRaises(UnknownCodeError, self.dnsbl_service.get_classification, 4)
        
    def testQuery(self):
        ''' Test query method
        
        The method is tested against a set of host values, which are expected to be recognized
        as spam or not, depending on configuration of side effect of mocked query function.
        
        :param mocked_query: a patched instance of query function
        '''
        inverted_ips =  '1.0.255.255', '2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.2.1.0.c.b.a.0.8.b.d.0.1.0.0.2'
        values = hostnames + inverted_ips
        
        self.setUpQuerySideEffect()
        
        return_code_iterator = cycle(self.code_item_class.keys())
        
        for v in values:
            self.assertEqual(self.dnsbl_service.query(v), next(return_code_iterator))
        
        self.setUpQuerySideEffect(True)
        
        for v in values:
            self.assertEqual(self.dnsbl_service.query(v), None)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
class BaseDNSBLClientTest(unittest.TestCase):
    
    test_lists_attr_name = 'test_lists_attr'
    def setUp(self):
        self.base_dnsbl_client = BaseDNSBLClient()
        self.base_dnsbl_client._LISTS_ATTR_NAME = self.test_lists_attr_name
        
    def getDNSBLMock(self, required_property = True, query_return_value = None):
        ''' Create a Mock instance for dnsbl service object
        
        :param required_property: boolean value set to value of the required property
        to which BaseDNSBLClient._LISTS_ATTR_NAME is set
        :returns: an instance of Mock with all necessary attributes
        '''
        
        dnsbl = Mock()
        setattr(dnsbl, self.test_lists_attr_name, bool(required_property))
        dnsbl.query.return_value = query_return_value
        
        return dnsbl
        
    def testAddDNSBL(self):
        ''' Test add_dnsbl method of BaseDNSBLClient '''
        
        valid_dnsbl = self.getDNSBLMock()
        
        self.base_dnsbl_client.add_dnsbl(valid_dnsbl)
         
        self.assertEqual(self.base_dnsbl_client.dnsbl_services[0], valid_dnsbl)
         
        invalid_dnsbl = self.getDNSBLMock(False)

        self.assertRaises(NoRequiredContentError, self.base_dnsbl_client.add_dnsbl, invalid_dnsbl)
        
        no_dnsbl = Mock(spec=[])
         
        self.assertRaises(TypeError, self.base_dnsbl_client.add_dnsbl, no_dnsbl)
        
    def testContains(self):
        ''' Test __contains__ method '''
        return_value = 3
        test_host = 'test'
        
        valid_dnsbl = self.getDNSBLMock(query_return_value = return_value)
        
        self.base_dnsbl_client.dnsbl_services.append(valid_dnsbl)
        
        self.assertTrue(test_host in self.base_dnsbl_client)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()