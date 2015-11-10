#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest
from spambl import DNSBL


class DNSBLTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        code_item_class = {1: 'Class #1', 2: 'Class #2'}
        query_suffix = 'query.suffix'
        
        cls.dnsbl = DNSBL('test.dnsbl', query_suffix, code_item_class, True, True)
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()