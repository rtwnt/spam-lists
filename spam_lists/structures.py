# -*- coding: utf-8 -*-

'''
This module defines classes of objects containing various data, and
functions for creating proper objects for given arguments. They are used
by service models in spam_lists.service_models module
'''

from __future__ import unicode_literals

from collections import namedtuple
import ipaddress

from builtins import str, object  # pylint: disable=redefined-builtin
from dns import name
from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain, \
    from_address as name_from_ip
from future.utils import raise_with_traceback
import tldextract
import validators

from .exceptions import InvalidHostError, InvalidHostnameError, \
    InvalidIPv4Error, InvalidIPv6Error
from .compat import lru_cache


class CachedFactoryMixin(object):
    ''' A class adding a constructor class method with
    cached results to classes that extend it
    '''
    @classmethod
    @lru_cache()
    def create(cls, *args, **kwargs):
        ''' Create an instance of the class using __init__

        This method serves as a way to have a cached constructor
        while avoiding problems with inheritance resulting
        from applying lru_cache() decorator to class definitions.

        :param *args: positional arguments expected by
        the __init__ method
        :param **kwargs: keyword arguments expected by
        the __init__ method
        :returns: an instance of the class
        '''
        return cls(*args, **kwargs)


class Hostname(CachedFactoryMixin, name.Name):
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
        super(Hostname, self).__init__(value.split('.'))

    @property
    def relative_domain(self):
        ''' Return a relative domain representing the host

        :returns: this instance
        '''
        return self

    def is_subdomain(self, other):
        ''' Test if the object is a subdomain of the
        other

        :param other: the object to which we compare this instance
        :returns: True if this instance is a subdomain of the other
        '''
        try:
            return name.Name.is_subdomain(self, other)
        except AttributeError:
            return False

    is_match = is_subdomain


class IPAddress(object):
    ''' A class of objects representing IP address values.

    The instances are used as values tested by clients of
    IP-address-listing services or as items stored by objects
    representing such IP address lists.
    '''
    reverse_domain = None

    @property
    def relative_domain(self):
        ''' Get a relative domain name representing the ip address

        :returns: the reverse pointer relative to the common root
        depending on the version of ip address represented by this object
        '''
        return name_from_ip(str(self)).relativize(self.reverse_domain)

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
        return str(self)

    def is_match(self, other):
        return self == other


class IPv4Address(ipaddress.IPv4Address, IPAddress):
    reverse_domain = ipv4_reverse_domain

    def __init__(self, value):
        ''' Constructor

        :param value: a valid IPv4 address
        :raises InvalidIPv4Error: if the value was not a valid IPv4 address,
        or if it was a bytes string instead of unicode
        '''
        try:
            super(IPv4Address, self).__init__(value)
        except ValueError:
            msg = '{} is not a valid IPv4 address'.format(value)
            raise_with_traceback(InvalidIPv4Error(msg))


class IPv6Address(ipaddress.IPv6Address, IPAddress):
    reverse_domain = ipv6_reverse_domain

    def __init__(self, value):
        ''' Constructor

        :param value: a valid IPv6 address
        :raises InvalidIPv6Error: if the value was not a valid IPv6 address,
        or if it was a bytes string instead of unicode
        '''
        try:
            super(IPv6Address, self).__init__(value)
        except ValueError:
            msg = '{} is not a valid IPv6 address'.format(value)
            raise_with_traceback(InvalidIPv6Error(msg))


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
    factories = IPv4Address, IPv6Address
    return create_host(factories, value)


def hostname_or_ip(value):
    ''' Create a hostname or ip address object
    for given value

    :param value: a valid host string
    :returns: a host object for given value
    :raises InvalidHostError: if the value is not a valid hostname or
    ip address
    '''
    factories = IPv4Address, IPv6Address, Hostname
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
    return Hostname(registered_domain_string)


def registered_domain_or_ip(value):
    ''' Get host object representing a registered domain or an ip address

    :param value: a valid hostname or ip string
    :returns: a host object representing a registered domain extracted from
    given hostname, or an ip address
    :raises InvalidHostError: if value is not a valid host
    '''
    factories = IPv4Address, IPv6Address, registered_domain
    return create_host(factories, value)


def non_ipv6_host(value):
    ''' Create host object representing a registered domain or an IPv4 address

    :param value: a valid hostname or IPv4 string
    :returns: a host object representing a registered domain extracted from
    given hostname, or an IPv4 address
    :raises InvalidHostError: if value is not a valid hostname or IPv4 address
    '''
    factories = IPv4Address, registered_domain
    return create_host(factories, value)

AddressListItem = namedtuple('AddressListItem', 'value source classification')
