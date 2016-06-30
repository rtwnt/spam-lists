# -*- coding: utf-8 -*-

'''
This module defines classes of objects containing various data, and
functions for creating proper objects for given arguments. They are used
by service models in spam_lists.host_list module
'''

from __future__ import unicode_literals

from collections import namedtuple
import ipaddress

from builtins import str, object  # pylint: disable=redefined-builtin
from dns import name
from dns.reversename import (
    ipv4_reverse_domain, ipv6_reverse_domain, from_address as name_from_ip
)
from future.utils import raise_with_traceback
import tldextract
import validators

from .exceptions import (
    InvalidHostError, InvalidHostnameError, InvalidIPv4Error, InvalidIPv6Error
)
from .compat import lru_cache


class Host(object):
    ''' Base class for host objects '''
    def __lt__(self, other):
        ''' Check if the other is smaller

        This method is necessary for sorting and search
        algorithms using bisect_right.

        :param other: a value to be compared
        :returns: result of comparison between value attributes of
        both this object and the other, or of comparison between
        their unicode string representations.

        In case of the other not having necessary attributes,
        NotImplemented constant is returned.
        '''
        try:
            try:
                return self.value < other.value
            except TypeError:
                return self.to_unicode() < other.to_unicode()
        except AttributeError:
            return NotImplemented


class Hostname(Host):
    ''' A class of objects representing hostname values.

    The instances are used as values tested by clients of
    hostname-listing services or as items stored by objects
    representing such host lists.
    '''
    def __init__(self, value):
        ''' Create a new instance of Hostname

        :param value: a string representing a hostname
        :raises InvalidHostnameError: if value parameter is not a valid domain
        '''
        value = str(value)
        if not validators.domain(value):
            msg = "'{}' is not a valid hostname".format(value)
            raise_with_traceback(InvalidHostnameError(msg))
        hostname = name.Name(value.split('.'))
        self.value = hostname
        self.relative_domain = hostname

    def is_subdomain(self, other):
        ''' Test if the object is a subdomain of the
        other

        :param other: the object to which we compare this instance
        :returns: True if this instance is a subdomain of the other
        '''
        compared = other.value if hasattr(other, 'value') else other
        try:
            return self.value.is_subdomain(compared)
        except AttributeError:
            return False

    is_match = is_subdomain

    def to_unicode(self):
        ''' Get unicode string representing the object

        :returns: the ip value as unicode string
        '''
        return self.value.to_unicode()


class IPAddress(Host):
    ''' A class of objects representing IP address values.

    The instances are used as values tested by clients of
    IP-address-listing services or as items stored by objects
    representing such IP address lists.
    '''
    reverse_domain = None

    def __init__(self, value):
        ''' Constructor

        :param value: a valid ip address for this class
        :raises self.invalid_ip_error_type: if the value is not
        a valid ip address for this class
        '''
        try:
            self.value = self.factory(value)
        except ValueError:
            msg_tpl = '{} is not a valid ip address for {}'
            msg = msg_tpl.format(value, self.__class__)
            raise_with_traceback(self.invalid_ip_error_type(msg))

    @property
    def relative_domain(self):
        ''' Get a relative domain name representing the ip address

        :returns: the reverse pointer relative to the common root
        depending on the version of ip address represented by this object
        '''

        return name_from_ip(str(self.value)).relativize(self.reverse_domain)

    def is_subdomain(self, _):
        # pylint: disable=no-self-use
        ''' Check if this object is a subdomain of the other

        :param other: another host
        :returns: False, because ip address is not a domain
        '''
        return False

    def to_unicode(self):
        ''' Get unicode string representing the object

        :returns: the ip value as unicode string
        '''
        return str(self.value)

    def is_match(self, other):
        return self == other


class IPv4Address(IPAddress):
    factory = ipaddress.IPv4Address
    reverse_domain = ipv4_reverse_domain
    invalid_ip_error_type = InvalidIPv4Error


class IPv6Address(IPAddress):
    factory = ipaddress.IPv6Address
    reverse_domain = ipv6_reverse_domain
    invalid_ip_error_type = InvalidIPv6Error


def cached(function):
    return lru_cache()(function)

hostname = cached(Hostname)
ip_v4 = cached(IPv4Address)
ip_v6 = cached(IPv6Address)


@cached
def create_host(factories, value):
    ''' Create an instance of host object for given value, using
    the factories.

    :param factories: a list of functions that return host objects
    (Hostname, IPv4Address, IPv6Address) for valid arguments
    :param value: a value to be passed as argument to factories
    :returns: an object representing value, created by one of the factories.
    It's a return value of the first factory that could create it
    for the given argument
    :raises InvalidHostError: if the value is not a valid input
    for any factory used by this function
    '''
    data = [value]
    for func in factories:
        try:
            return func(value)
        except InvalidHostError as ex:
            data.append(str(ex))
    msg_tpl = "Failed to create a host object for '{}', \
    raising the following errors in the process:"+"\n".join(data)
    raise InvalidHostError(msg_tpl.format(value))


def ip_address(value):
    ''' Create an ip address object

    :param value: a valid ip address
    :returns: a .structures.IPAddress subclass instance
    :raises InvalidHostError: if the value is not a valid IPv4 or
    IPv6 value
    '''
    factories = ip_v4, ip_v6
    return create_host(factories, value)


def hostname_or_ip(value):
    ''' Create a hostname or ip address object
    for given value

    :param value: a valid host string
    :returns: a host object for given value
    :raises InvalidHostError: if the value is not a valid hostname or
    ip address
    '''
    factories = ip_v4, ip_v6, hostname
    return create_host(factories, value)


TLD_EXTRACTOR = tldextract.TLDExtract()


def registered_domain(value):
    ''' Create a Hostname instance representing registered domain
    extracted from the value

    :param value: a valid host string
    :returns: a Hostname instance representing registered domain
    :raises InvalidHostnameError: if the value is not a valid hostname
    '''
    registered_domain_string = TLD_EXTRACTOR(value).registered_domain
    return hostname(registered_domain_string)


def registered_domain_or_ip(value):
    ''' Get host object representing a registered domain or an ip address

    :param value: a valid hostname or ip string
    :returns: a host object representing a registered domain extracted from
    given hostname, or an ip address
    :raises InvalidHostError: if value is not a valid host
    '''
    factories = ip_v4, ip_v6, registered_domain
    return create_host(factories, value)


def non_ipv6_host(value):
    ''' Create host object representing a registered domain or an IPv4 address

    :param value: a valid hostname or IPv4 string
    :returns: a host object representing a registered domain extracted from
    given hostname, or an IPv4 address
    :raises InvalidHostError: if value is not a valid hostname or IPv4 address
    '''
    factories = ip_v4, registered_domain
    return create_host(factories, value)

AddressListItem = namedtuple('AddressListItem', 'value source classification')
