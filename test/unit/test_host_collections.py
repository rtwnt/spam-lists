# -*- coding: utf-8 -*-

"""Tests for classes representing custom host collections."""
from __future__ import unicode_literals

from dns import name
from ipaddress import ip_address
from nose_parameterized import parameterized

from spam_lists.exceptions import InvalidHostError
from spam_lists.host_collections import HostCollection, SortedHostCollection
from test.compat import unittest, Mock
from test.unit.common_definitions import (
    TestFunctionDoesNotHandleMixin, host_list_host_factory, HostListTestMixin
)


def get_sorting_key(value):
    """Get a key for sorting host values during tests.

    :param value: a host value for which we generate key
    :returns: a value used as the sorting key
    """
    try:
        return ip_address(value)
    except ValueError:
        return name.from_text(value)


def has_to_unicode(value):
    """Check if an object has a to_unicode attribute.

    :param value: a value for which we test membership of the attribute
    :returns: True if the value has the attribute
    """
    return hasattr(value, 'to_unicode')


def host_collection_host_factory(host):
    """Get a mock of a host object stored in a collection.

    :param host: a host value to be represented by the mock
    :returns: an instance of Mock representing a host object stored
    in a host collection
    """
    host_object = host_list_host_factory(host)
    _str = host_object.to_unicode()

    def test(other):
        """Test if the other and the host object match each other.

        :param other: an object to be compared
        :returns: result of the test
        """
        return (has_to_unicode(other) and
                other.to_unicode() in _str)
    host_object.is_match.side_effect = test
    host_object.is_subdomain.side_effect = test

    def less_than(other):
        """Check if the host object key is less than the other.

        This function is an implementation of __lt__ expected from host
        objects by bisect_right function.

        :param other: a value to be compared
        :returns: result of the comparison
        """
        host_object_key = get_sorting_key(_str)
        other_value = other.to_unicode() if has_to_unicode(other) else other
        other_key = get_sorting_key(other_value)
        try:
            result = host_object_key < other_key
        except TypeError:
            result = _str < other_value
        return result

    host_object.__lt__.side_effect = less_than
    return host_object


class HostCollectionBaseTest(
        HostListTestMixin,
        TestFunctionDoesNotHandleMixin,
):
    """Tests for subclasses or BaseHostCollection.

    :ivar host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_collection_host_factory
    as its implementation.
    :ivar tested_instance: an instance of tested class
    """

    # pylint: disable=too-many-public-methods

    valid_urls = ['http://test.com', 'http://127.33.22.11']

    def setUp(self):
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = host_collection_host_factory
        self.tested_instance = self.constructor(
            'test_host_collection',
            self.classification,
            host_factory=self.host_factory_mock
        )

    def test_add_invalid_host(self):
        """Test for InvalidHostError when adding an invalid host.

        An invalid host is defined as a value that doesn't match a type
        of host value accepted by a collection.
        """
        function = self.tested_instance.add
        self._test_function_does_not_handle(
            InvalidHostError,
            self.host_factory_mock,
            function,
            'invalidhost.com'
        )

    @parameterized.expand(HostListTestMixin.valid_host_input)
    def test_add_for_valid(self, _, value):
        """Test the method for a valid host value.

        :param value: a host value to be added
        """
        self.tested_instance.add(value)
        self.assertTrue(value in self.tested_instance.hosts)

    def test_add_for_subdomain(self):
        """Test the method for a subdomain of a listed domain.

        A subdomain to a domain already listed in the collection is
        expected not to be added to the collection.
        """
        initial_hosts = ['domain.com']
        self._set_matching_hosts(initial_hosts)
        self.tested_instance.add('subdomain.domain.com')
        self.assertCountEqual(initial_hosts, self.tested_instance.hosts)

    def test_add_for_the_same_value(self):
        """Test the method for a listed value.

        An already listed value is expected not to be added to
        the collection
        """
        value = 'domain.com'
        initial_hosts = ['host.com', value]
        self._set_matching_hosts(initial_hosts)
        self.tested_instance.add(value)
        self.assertCountEqual(initial_hosts, self.tested_instance.hosts)

    def test_add_a_superdomain(self):
        """Test the method for a superdomain of a listed domain.

        A superdomain of a domain listed in the collection is expected
        to replace its subdomain when added.
        """
        superdomain = 'domain.com'
        subdomain = 'sub.domain.com'
        initial_hosts = ['host1.com', subdomain]
        self._set_matching_hosts(initial_hosts)
        self.tested_instance.add(superdomain)
        initial_hosts.remove(subdomain)
        initial_hosts.append(superdomain)
        self.assertCountEqual(initial_hosts, self.tested_instance.hosts)

    def _set_matching_hosts(self, hosts):
        self.tested_instance.hosts = list(hosts)


class HostCollectionTest(HostCollectionBaseTest, unittest.TestCase):
    """Tests for HostCollection class."""

    constructor = HostCollection


class SortedHostCollectionTest(HostCollectionBaseTest, unittest.TestCase):
    """Tests for SortedHostCollection class."""

    constructor = SortedHostCollection

    def _set_matching_hosts(self, hosts):
        self.tested_instance.hosts = list(hosts)
        self.tested_instance.hosts.sort(key=self.host_factory_mock)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
