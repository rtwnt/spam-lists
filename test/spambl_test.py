#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import DNSBL, UnknownCodeError, NXDOMAIN, HpHosts
import mock
from ipaddress import ip_address as IP
from itertools import cycle
from __builtin__ import classmethod


spam_hostnames  = 't1.pl', 't2.com', 't3.com.pl'
spam_ips = IP(u'255.255.0.1'), IP(u'2001:DB8:abc:123::42')
inverted_ips =  '1.0.255.255', '2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.2.1.0.c.b.a.0.8.b.d.0.1.0.0.2'

hosts_with_spam = mock.Mock()
hosts_with_spam.ips = spam_ips + (IP(u'127.180.0.18'),)
hosts_with_spam.hostnames = spam_hostnames + ('valid.com',)

empty_hosts = mock.Mock()
empty_hosts.ips = ()
empty_hosts.hostnames = ()

non_spam_hosts = mock.Mock()
non_spam_hosts.ips = IP(u'150.99.0.2'), IP(u'150.99.0.3')
non_spam_hosts.hostnames = 't4.pl', 't5.com.pl'


class DNSBLTest(unittest.TestCase):
    
    @classmethod
    def setUpDNSBLInstance(cls, code_item_class, query_suffix):
        ''' Create DNSBL instance used for testing
        :param code_item_class: a map of return code values to spam host classifications
        :param query_suffix: a value attached to host to create a query name
        '''
        
        cls.dnsbl = DNSBL('test.dnsbl', query_suffix, code_item_class, True, True)
        
    @classmethod
    def setUpQueryPatch(cls, return_codes, existent_addr_suffix):
        ''' Patch query function in spambl module
        
        The query function was originally imported from dns.resolver module
        
        :param return_codes: dnsbl return codes to be used for testing
        :param existent_addr_suffix: a suffix used to create qname arguments that
        do not cause raising NXDOMAIN error
        '''
        
        cls.patcher = mock.patch('spambl.query')
        cls.mocked_query = cls.patcher.start()
        
        dns_queries = [h + '.' + existent_addr_suffix for h in spam_hostnames + inverted_ips]
        
        existent_responses = cycle('127.0.0.%d' % n for n in return_codes)
        cls.mocked_query.query_responses = {q: next(existent_responses) for q in dns_queries}
        
        def mocked_query(address):
            if address in cls.mocked_query.query_responses:
                m = mock.Mock()
                m.to_text = mock.Mock(return_value = cls.mocked_query.query_responses[address])
                return m,
            raise NXDOMAIN('test NXDOMAIN exception')
        
        cls.mocked_query.side_effect = mocked_query
        
    
    @classmethod
    def setUpClass(cls):
        code_item_class = {1: 'Class #1', 2: 'Class #2'}
        query_suffix = 'query.suffix'
        
        cls.setUpDNSBLInstance(code_item_class, query_suffix)
        cls.setUpQueryPatch(code_item_class.keys(), query_suffix)
        
    def testGetClassification(self):
        ''' Test get_classification method of DNSBL instance '''
        
        msg = 'The expected value {} is not equal to received value {}'
        
        for key, value in self.dnsbl._code_item_class.iteritems():
            actual = self.dnsbl.get_classification(key)
            self.assertEqual(actual, value, msg.format(value, actual))
        
        self.assertRaises(UnknownCodeError, self.dnsbl.get_classification, 4)
        

    def testContainsAny(self):
        
        self.assertTrue(self.dnsbl.contains_any(hosts_with_spam), 'Failed to detect spam existing in given host collection')
        self.assertFalse(self.dnsbl.contains_any(empty_hosts), 'Spam has been detected in empty host collection')
        self.assertFalse(self.dnsbl.contains_any(non_spam_hosts), 'Spam has been detected in host collection with no spam')
        
    def testLookup(self):
        
        actual_host_strings = [h.host for h in self.dnsbl.lookup(hosts_with_spam)]
        expected_host_strings = [n for n in spam_ips + spam_hostnames]
        
        self.assertSequenceEqual(actual_host_strings, expected_host_strings)
        self.assertSequenceEqual(self.dnsbl.lookup(empty_hosts), [])
        self.assertSequenceEqual(self.dnsbl.lookup(non_spam_hosts), [])
        
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
        
class HpHostsTest(unittest.TestCase):
    ''' Tests HpHosts methods '''
    
    classification = '[TEST]'
    
    @classmethod
    def setUpClass(cls):
        cls.hp_hosts = HpHosts('spambl_test_suite')
        
        cls.patcher = mock.patch('spambl.get')
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
            
            for k in spam_ips:
                self.assertEqual(k in self.hp_hosts, listed)
            
    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()