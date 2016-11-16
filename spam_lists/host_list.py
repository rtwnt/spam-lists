# -*- coding: utf-8 -*-

"""A module defining HostList class."""
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import object
from future.moves.urllib.parse import urlparse

from .exceptions import InvalidHostError
from .structures import AddressListItem
from .validation import accepts_valid_urls, accepts_valid_host


class HostList(object):
    """A base class for objects representing host lists.

    Objects representing host lists are defined as custom host
    whitelists and blacklists or clients of online host blacklists.
    """

    def __init__(self, host_factory):
        """Initialize a new instance.

        :param host_factory: a function responsible for creating valid
        host objects. It may raise InvalidHostError (or its subclasses)
        if a value passed to it is not a valid host of type accepted by
        the factory.
        """
        self._host_factory = host_factory

    def _contains(self, host_value):
        """Check if host list contains a match for the given value.

        :param host_value: a host value
        :returns: True if the service lists a matching value
        """
        raise NotImplementedError

    def _get_match_and_classification(self, host_value):
        """Get value and data stored for the given value.

        :param host_value: a host value
        :returns: a tuple containing listed item and its classification
        as a tuple containing all classification groups to which
        the item belongs
        """
        raise NotImplementedError

    @accepts_valid_host
    def __contains__(self, host_value):
        """Check if the given host value is listed by the host list.

        :param host_value: a string representing a valid host
        :returns: True if the host is listed
        :raises InvalidHostError: if the argument is not a valid
        host string
        """
        try:
            host_object = self._host_factory(host_value)
        except InvalidHostError:
            return False
        return self._contains(host_object)

    @accepts_valid_host
    def lookup(self, host_value):
        """Get a host value matching the given value.

        :param host_value: a value of the host of a type that can be
        listed by the service
        :returns: an instance of AddressListItem representing
        a matched value
        :raises InvalidHostError: if the argument is not a valid
        host string
        """
        try:
            host_object = self._host_factory(host_value)
        except InvalidHostError:
            return None
        result = self._get_match_and_classification(
            host_object
        )
        host_item, classification = result
        if host_item is not None:
            return AddressListItem(
                host_item.to_unicode(),
                self,
                classification
            )
        return None

    @accepts_valid_urls
    def any_match(self, urls):
        """Check if any of the given URLs has a matching host.

        :param urls: an iterable containing URLs
        :returns: True if any host has a listed match
        :raises InvalidURLError: if there are any invalid URLs in
        the sequence
        """
        return any(urlparse(u).hostname in self for u in urls)

    @accepts_valid_urls
    def lookup_matching(self, urls):
        """Get matching hosts for the given URLs.

        :param urls: an iterable containing URLs
        :returns: instances of AddressListItem representing listed
        hosts matching the ones used by the given URLs
        :raises InvalidURLError: if there are any invalid URLs in
        the sequence
        """
        hosts = (urlparse(u).hostname for u in urls)
        for val in hosts:
            item = self.lookup(val)
            if item is not None:
                yield item

    @accepts_valid_urls
    def filter_matching(self, urls):
        """Get URLs with hosts matching any listed ones.

        :param urls: an iterable containing URLs to filter
        :returns: a generator yielding matching URLs
        :raises InvalidURLError: if there are any invalid URLs in
        the sequence
        """
        for url in urls:
            if urlparse(url).hostname in self:
                yield url
