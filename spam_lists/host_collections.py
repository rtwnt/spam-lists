# -*- coding: utf-8 -*-

'''
This module contains classes of objects representing
custom host collections and their dependencies
'''
from __future__ import unicode_literals
from bisect import bisect_right

from .host_list import HostList
from .structures import hostname_or_ip


class BaseHostCollection(HostList):
    ''' Base class for containers storing ip addresses
    and domain names
    '''
    def __init__(
            self,
            identifier,
            classification,
            hosts=None,
            host_factory=hostname_or_ip):
        ''' Create new instance

        :param identifier: an identifier of this instance of host collection
        :param classification: a list or tuple containing strings representing
        types of items, assigned to each element of the collection
        :param hosts: an object storing ip adresses and hostnames.
        It must have the following methods:
        * __getitem__
        * __len__
        * pop
        * append
        :param host_factory: a callable used to create hosts objects stored
        in the collection or representing values searched in it.
        '''
        self.identifier = identifier
        self.classification = set(classification)
        self.hosts = hosts if hosts is not None else []
        super(BaseHostCollection, self).__init__(host_factory)

    def __len__(self):
        return len(self.hosts)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.__class__(
                self.identifier,
                self.classification,
                self.hosts[index],
                self._host_factory
            )
        return self._host_factory(self.hosts[index])

    def _contains(self, host_object):
        match = self._get_match(host_object)
        return match is not None

    def _get_match_and_classification(self, host_object):
        match = self._get_match(host_object)
        _class = None if match is None else self.classification
        return match, _class

    def add(self, host_value):
        ''' Add the given value to collection

        :param host: an ip address or a hostname
        :raises InvalidHostError: raised when the given value
        is not a valid ip address nor a hostname
        '''
        host_obj = self._host_factory(host_value)
        if self._get_match(host_obj) is not None:
            return
        self._add_new(host_obj)

    def _add_new(self, host_object):
        ''' Add a new host to the collection

        A new host is defined as a value not currently listed
        (in case of both hostnames and ip) or not currently
        covered by another value (in case of hostnames, which
        could be covered by their parent domain).

        Before a new hostname can be added, all its subdomains
        already present in the collection must be removed.

        :param host_obj: an object representing value to be added.
        It is assumed that, during execution of this method,
        the value to be added is not currently listed.
        '''
        raise NotImplementedError


class HostCollection(BaseHostCollection):
    ''' Represents a custom host list.

    May be used as a local whitelist or blacklist.
    '''
    def _get_match(self, host_object):
        for val in self:
            if host_object.is_match(val):
                return val

    def _add_new(self, host_obj):
        for i, listed_obj in enumerate(self):
            if listed_obj.is_subdomain(host_obj):
                self.hosts.pop(i)
        self.hosts.append(host_obj.to_unicode())


class SortedHostCollection(BaseHostCollection):
    ''' Represent a custom host list that keeps its items in
    sorted order.
    '''
    def _get_insertion_point(self, host_obj):
        return bisect_right(self, host_obj)

    def _get_match(self, host_object):
        ''' Get an item matching given host object

        The item may be either a parent domain or identical value.
        Parent domains and existing identical values always precede
        insertion point for given value - therefore, we treat
        an item just before insertion point as potential match.

        :param host_object: an object representing ip address
        or hostname whose match we are trying to find
        '''
        i = self._get_insertion_point(host_object)
        potential_match = None
        try:
            potential_match = self[i-1]
        except IndexError:
            pass

        if host_object.is_match(potential_match):
            return potential_match
        return None

    def _add_new(self, host_object):
        ''' Add a new host to the collection

        Before a new hostname can be added, all its subdomains
        already present in the collection must be removed.
        Since the collection is sorted, we can limit our
        search for them to slice of the collection starting
        from insertion point and ending with the last subdomain
        detected
        :param host_obj: an object representing value to be added.
        It is assumed that, during execution of this method,
        the value to be added is not currently listed.
        '''
        i = self._get_insertion_point(host_object)

        for listed in self[i:]:
            if not listed.is_subdomain(host_object):
                break
            self.hosts.pop(i)

        self.hosts.insert(i, host_object.to_unicode())
