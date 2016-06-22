# -*- coding: utf-8 -*-
'''
This module contains unit tests for functions and classes provided by
spam_lists.host_list module
'''
from __future__ import unicode_literals

from spam_lists.host_list import HostList
from test.compat import unittest, Mock, patch
from test.unit.common_definitions import (
    HostListTestMixin, host_list_host_factory
)


class HostListTest(HostListTestMixin, unittest.TestCase):
    # pylint: disable=too-many-public-methods
    ''' Tests for HostList class

    HostList does not provide implementation of some methods it uses.
    These methods are ought to be implemented by its subclasses. Here,
    we mock these methods so that HostList can be tested.

    :var listed_hosts: a list of all host values assumed to be listed for
    a given test
    :var host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_list_host_factory as its implementation
    :var tested_instance: an instance of tested class
    :var _contains_patcher: a patcher for HostList._contains method
    :var _contains_mock: a mock for HostList._contains method.
    :var host_data_getter_patcher: a patcher for
    HostList._get_match_and_classification method
    :var host_data_getter_mock: a mock for
    HostList._get_match_and_classification method. Uses
     host_list_host_factory as its implementation.
    '''
    def setUp(self):
        self.listed_hosts = []
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = host_list_host_factory
        self.tested_instance = HostList(self.host_factory_mock)
        self._contains_patcher = patch(
            'spam_lists.host_list.HostList._contains'
        )
        self._contains_mock = self._contains_patcher.start()
        self._contains_mock.side_effect = lambda h: h in self.listed_hosts
        host_data_getter_name = (
            'spam_lists.host_list.HostList._get_match_and_classification'
        )
        self.host_data_getter_patcher = patch(host_data_getter_name)
        self.host_data_getter_mock = self.host_data_getter_patcher.start()

        def _get_match_and_classification(host):
            if host in self.listed_hosts:
                return host, self.classification
            return None, None
        self.host_data_getter_mock.side_effect = _get_match_and_classification

    def tearDown(self):
        self._contains_patcher.stop()
        self.host_data_getter_patcher.stop()

    def _set_matching_hosts(self, matching_hosts):
        self.listed_hosts = [self.host_factory_mock(mh)
                             for mh in matching_hosts]


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
