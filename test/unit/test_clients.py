# -*- coding: utf-8 -*-

"""Tests for classes representing blacklist service clients."""
from __future__ import unicode_literals

from dns.resolver import NXDOMAIN
from future.moves.urllib.parse import urlparse, parse_qs
from nose_parameterized import parameterized
from requests.exceptions import HTTPError

from spam_lists.exceptions import UnathorizedAPIKeyError, UnknownCodeError
from spam_lists.clients import (
    DNSBL, GoogleSafeBrowsing, HpHosts, BitmaskingDNSBL
)
from test.compat import unittest, Mock, patch
from test.unit.common_definitions import (
    HostListTestMixin, host_list_host_factory, URLTesterTestMixin
)


class DNSQuerySideEffects(object):
    """A class providing a side effect for a mock of query function."""

    def __init__(self, expected_query_names, last_octet=2):
        """Initialize a new instance.

        :param expected_query_names: domain names for which the mock is
        expected to return a mock of a DNS answer object
        :param last_octet: a number to be used as last octet of an
        IP address provided by the answer object
        """
        self.expected_query_names = expected_query_names
        self.last_octet = last_octet

    def __call__(self, query_name):
        """Query for a DNS name.

        :param query_name: a domain for which the mock is being queried
        :returns: a list containing a DNS answer mock
        :raises NXDOMAIN: if query_name is not included in
        the preconfigured list
        """
        if query_name in self.expected_query_names:
            dns_answer_mock = Mock()
            return_value = '121.0.0.{}'.format(self.last_octet)
            dns_answer_mock.to_text.return_value = return_value
            return [dns_answer_mock]
        raise NXDOMAIN


class DNSBLTestMixin(HostListTestMixin):
    """Tests for DNSBL client classes.

    :cvar query_domain_str: a string used as a suffix for DNS queries
    to a service
    :cvar host_with_unknown_code: a host value to be used during tests
    :ivar host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_list_host_factory as its implementation
    :ivar dnsbl_factory: constructor of instance of tested class
    :ivar tested_instance: an instance of tested class
    :ivar dns_query_patcher: an object used for patching query function
     used by DNSBL instance
    :ivar dns_query_mock: a mocked implementation of the query function
    """

    query_domain_str = 'test.query.domain'
    host_with_unknown_code = 'hostwithunknowncode.com'

    def setUp(self):
        self.host_factory_mock = Mock()
        self.host_factory_mock.side_effect = host_list_host_factory
        classification_map = {}
        for i, k in enumerate(self.classification, 1):
            classification_map[2**i] = k
        self.tested_instance = self.dnsbl_factory(
            'test_service',
            self.query_domain_str,
            classification_map,
            self.host_factory_mock
        )
        self.dns_query_patcher = patch('spam_lists.clients.query')
        self.dns_query_mock = self.dns_query_patcher.start()
        self.dns_query_mock.side_effect = DNSQuerySideEffects([])

    def tearDown(self):
        self.dns_query_patcher.stop()

    def _set_matching_hosts(self, hosts):
        host_objects = [self.host_factory_mock(h) for h in hosts]
        query_names = [h.relative_domain.derelativize()
                       for h in host_objects]
        self.dns_query_mock.side_effect.expected_query_names = query_names

    @parameterized.expand([
        ('lookup', host_with_unknown_code),
        (
            'lookup_matching',
            ['http://'+host_with_unknown_code]
        )
    ])
    def test_code_error_raised_by(self, function_name, tested_value):
        """Test if UnknownCodeError is raised for tested value.

        The error is expected to be raised when a DNSBL service returns
        a code whose value was not recognized by the client. Occurence
        of such an error means that there is probably a new return code
        provided by the service and that the client provided by this
        library must be updated to take this value into account.

        :param function_name: a name of a method to be tested
        :param tested_value: a host value to be used for the test
        """
        self._set_matching_hosts([self.host_with_unknown_code])
        self.dns_query_mock.side_effect.last_octet = 14

        def function(hosts):
            func = getattr(self.tested_instance, function_name)
            return list(func(hosts))

        self.assertRaises(UnknownCodeError, function, tested_value)


class DNSBLTest(DNSBLTestMixin, unittest.TestCase):
    """Tests for DNSBL class."""

    # pylint: disable=too-many-public-methods
    dnsbl_factory = DNSBL


class BitmaskingDNSBLTest(DNSBLTestMixin, unittest.TestCase):
    """Tests for BitmaskingDNSBL class."""

    # pylint: disable=too-many-public-methods
    dnsbl_factory = BitmaskingDNSBL


def create_hp_hosts_get(classification, listed_hosts):
    """Get a function to replace the get function used by HpHosts.

    :param classification: a classification for given hosts
    :param listed_hosts: listed hosts for generating responses
    :returns: a function providing side effects of Mock instance
    for the get function
    """
    class_str = ','.join(classification)

    def hp_hosts_get(url):
        """Get mock representing a response for a GET request.

        :param url: a request address
        :returns: a Mock instance representing response object expected
        by HpHosts
        """
        query_string = urlparse(url).query
        query_data = parse_qs(query_string)
        content = 'Not Listed'
        host = query_data['s'][0]
        if host in listed_hosts:
            content = 'Listed,{}'.format(class_str)
        response = Mock()
        response.text = content
        return response
    return hp_hosts_get


class HpHostsTest(HostListTestMixin, unittest.TestCase):
    """Tests for HpHosts client class.

    :cvar tested_instance: an instance of tested class

    :ivar listed_hosts: a list of host values assumed to be listed
    for tests
    :ivar get_patcher: an object used for patching get function used by
    a HpHosts instance
    :ivar get_mock: a mocked implementation of the get function. Uses
    a function returned by create_hp_hosts_get for given classification
    and list of hosts
    :ivar host_factory_mock: a mocked implementation of host factory
    used by tested instance. Uses host_list_host_factory as its
    implementation.
    """

    # pylint: disable=too-many-public-methods
    @classmethod
    def setUpClass(cls):
        cls.tested_instance = HpHosts('spam_lists_test_suite')

    def setUp(self):
        self.listed_hosts = []
        self.get_patcher = patch('spam_lists.clients.get')
        self.get_mock = self.get_patcher.start()
        self.get_mock.side_effect = create_hp_hosts_get(
            self.classification,
            []
        )
        self.host_factory_mock = Mock()
        self.tested_instance = HpHosts('spam_lists_test_suite')
        self.tested_instance._host_factory = self.host_factory_mock
        self.host_factory_mock.side_effect = host_list_host_factory

    def tearDown(self):
        self.get_patcher.stop()

    def _set_matching_hosts(self, hosts):
        side_effect = create_hp_hosts_get(
            self.classification,
            hosts
        )
        self.get_mock.side_effect = side_effect


def create_gsb_post(expected_401, spam_urls, classification):
    """Get mock for post function used by GoogleSafeBrowsing.

    :param expected_401: if True, the code of response mock returned
    by the returned function will be 401
    :param spam_urls: a list of URLs to be recognized as spam
    :param classification: a classification used for spam URLs
    :returns: mocked implementation of post function
    """
    def post(_, body):
        """Get mock of a response to a POST query to GSB Lookup API.

        :param body: a request body
        :returns: a Mock instance representing the response. Properties
        of the object depend on external values provided by the creator
        of the method: expected_401, spam_urls and classification
        """
        response = Mock()
        if expected_401:
            response.status_code = 401
            response.raise_for_status.side_effect = HTTPError
        else:
            urls = body.splitlines()[1:]
            classes = ['ok' if u not in spam_urls else
                       ','.join(classification) for u in urls]
            response.text = '\n'.join(classes)
            code = 200 if spam_urls else 204
            response.status_code = code
        return response
    return post


class GoogleSafeBrowsingTest(URLTesterTestMixin, unittest.TestCase):
    """Tests for GoogleSafeBrowsing class.

    This class adds an additional test method to the ones provided
    by URLTesterTestMixin: test_unathorized_query_with. This method
    is used to test methods of GoogleSafeBrowsing class for expected
    behaviour while calling Google Safe Browsing lookup API with
    an unathorized API key.

    :cvar tested_instance: an instance of tested class

    :ivar post_patcher: an object used for patching post function used
    by GoogleSafeBrowsing instance
    :ivar mocked_post: a mocked implementation of the post function
    for the tested instance. Uses a function returned by
    create_gsb_post function as its implementation.
    """

    # pylint: disable=too-many-public-methods
    def _get_expected_items_for_urls(self, urls):
        return self._get_expected_items(urls)

    @classmethod
    def setUpClass(cls):
        cls.tested_instance = GoogleSafeBrowsing(
            'test_client',
            '0.1',
            'test_key'
        )

    def _set_up_post_mock(self, spam_urls, error_401_expected=False):
        side_efect = create_gsb_post(
            error_401_expected,
            spam_urls,
            self.classification
        )
        self.mocked_post.side_effect = side_efect

    def setUp(self):
        self.post_patcher = patch('spam_lists.clients.post')
        self.mocked_post = self.post_patcher.start()

    def tearDown(self):
        self.post_patcher.stop()

    def _set_matching_urls(self, urls):
        self._set_up_post_mock(urls)

    @parameterized.expand([
        ('any_match'),
        ('lookup_matching'),
        ('filter_matching')
    ])
    def test_unathorized_query_with(self, function_name):
        """Test if a method raises an UnathorizedAPIKeyError.

        :param function_name: a name of a method to be tested
        """
        tested_function = getattr(self.tested_instance, function_name)

        def called_function(urls):
            """Call the function and return its return value.

            This function ensures generators are fully executed, too.

            :param urls: URL values to be used during the test
            """
            return list(tested_function(urls))
        self._set_up_post_mock([], error_401_expected=True)
        self.assertRaises(
            UnathorizedAPIKeyError,
            called_function,
            self.valid_urls
        )


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
