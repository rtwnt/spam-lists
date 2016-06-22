# -*- coding: utf-8 -*-

'''
This module contains a definition of HostList - a common base class
for classes representing host lists, like clients of online host
blacklists or custom host whitelists and blacklists.
'''
from __future__ import unicode_literals

# pylint: disable=redefined-builtin
from builtins import object
from future.moves.urllib.parse import urlparse

from .exceptions import InvalidHostError
from .structures import AddressListItem
from .validation import accepts_valid_urls, accepts_valid_host


class HostList(object):
    ''' A class of clients for local or remote host list services '''
    def __init__(self, host_factory):
        ''' Constructor

        :param host_factory: a function responsible for
        creating valid host objects. It may raise InvalidHostError
        (or its subclasses) if a value passed to it is not
        a valid host of type accepted by the factory.
        '''
        self._host_factory = host_factory

    def _contains(self, host_value):
        ''' Check if the service lists an item
        matching given host value

        :param host_value: a host value
        :returns: True if the service lists a matching
        value
        '''
        raise NotImplementedError

    def _get_match_and_classification(self, host_value):
        ''' Get a listed value that matches
        given host value and its classification

        :param host_value: a host value
        :returns: a tuple containing listed item and its classification as
        a tuple containing all classification groups to which the item belongs
        '''
        raise NotImplementedError

    @accepts_valid_host
    def __contains__(self, host_value):
        ''' Check if given host value is listed by the service

        :param host_value: a string representing a valid host
        :returns: True if the host is listed
        :raises InvalidHostError: if the argument is not a valid host string
        '''
        try:
            host_object = self._host_factory(host_value)
        except InvalidHostError:
            return False
        return self._contains(host_object)

    @accepts_valid_host
    def lookup(self, host_value):
        ''' Get an object representing a host value
        matched by this host

        :param host_value: a value of the host of a type
        that can be listed by the service
        :returns: an instance of AddressListItem representing
        a matched value
        :raises InvalidHostError: if the argument is not a valid host string
        '''
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
        ''' Check if any of given urls has a listed host

        :param urls: an iterable containing urls
        :returns: True if any host is listed
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        return any(urlparse(u).hostname in self for u in urls)

    @accepts_valid_urls
    def lookup_matching(self, urls):
        '''Get objects representing hosts in given urls
        that match listed hosts

        :param urls: an iterable containing urls
        :returns: items representing hosts matching the listed ones
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        hosts = (urlparse(u).hostname for u in urls)
        for val in hosts:
            item = self.lookup(val)
            if item is not None:
                yield item

    @accepts_valid_urls
    def filter_matching(self, urls):
        ''' Get urls with hosts matching listed ones

        :param urls: an iterable containing url addresses to filter
        :returns: a list containing matching urls
        :raises InvalidURLError: if there are any invalid urls in the sequence
        '''
        def is_match(url):
            return urlparse(url).hostname in self
        return (u for u in urls if is_match(u))
