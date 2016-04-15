# -*- coding: utf-8 -*-

'''
This module defines classes of objects containing various data, and
functions for creating proper objects for given arguments. They are used
by service models in spam_lists.service_models module
'''

from __future__ import unicode_literals

from collections import namedtuple
import ipaddress

#pylint: disable=redefined-builtin
from builtins import str, object
from dns import name
from dns.reversename import ipv4_reverse_domain, ipv6_reverse_domain, \
from_address as name_from_ip
from future.utils import raise_with_traceback
import tldextract
import validators

from .exceptions import InvalidHostError, InvalidHostnameError, \
InvalidIPv4Error, InvalidIPv6Error, UnknownCodeError


class BaseClassificationCodeMap(object):
    ''' A class responsible for providing classification
    for given return code '''
    def __init__(self, classification):
        ''' Create new instance

        :param classification: a dictionary mapping integer codes
        to taxonomical units
        '''
        self._classification = classification

    def _get_single_class(self, index):
        ''' Get one taxonimical unit from the classification

        :param index: a value to which a classification may be assigned
        :return: a taxonomical unit assigned to the code
        :raises UnknownCodeException: when there is no taxonomical unit
        for given code in the instance
        '''
        _class = self._classification.get(index)
        if _class is None:
            msg = 'The classification code {} was not recognized'.format(index)
            raise UnknownCodeError(msg)
        return _class

    def __getitem__(self, code):
        raise NotImplementedError

class SimpleClassificationCodeMap(BaseClassificationCodeMap):
    ''' A classification map recognizing only
    code values that are stored as indexes of taxonomical units '''
    def __getitem__(self, code):
        ''' Get classification for given code

        :param code: a value to which a taxonomical unit may be assigned
        :return: a set containing taxonomical unit assigned to the code,
        if it exists
        :raises UnknownCodeError: when there is no classification
        for given code
        '''
        return set([self._get_single_class(code)])


def get_powers_of_2(_sum):
    ''' Get powers of with a given sum

    This function transforms given integer to a binary string.
    A reversed value limited to digits of binary number is extracted
    from it, and each of its characters is enumerated.

    Each digit is tested for not being 0. If the test passes, the index
    associated with the digit is used as an exponent to get the next
    value in the sequence to be returned.

    :param _sum: a sum of all elements of the sequence to be returned
    :returns: a list of powers of two whose sum is given
    '''
    return [2**y for y, x in enumerate(bin(_sum)[:1:-1]) if int(x)]

class SumClassificationCodeMap(BaseClassificationCodeMap):
    ''' A classification map that recognizes indexes in form
    of both the same codes as stored in the instance and integers
    that can be represented as a sum of different indexes stored in
    the instance'''
    def _get_codes(self, code):
        ''' Get codes from given index

        The valid codes are different powers of 2. This method transforms
        given integer to a binary string. A reversed value limited to digits
        of binary number is extracted from it, and each of its characters
        is enumerated. If it's not 0, it represents one of the powers
        of 2 whose sums result in index

        :param code: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns a list of powers of 2 whose sum is equal to index
        '''
        return (2**y for y, x in enumerate(bin(code)[:1:-1]) if int(x))

    def __getitem__(self, code):
        ''' Get classification for given code

        :param index: an integer that is supposed to represent a sum
        of indexes mapping to classes
        :returns: a set containing taxonomical units
        :raises: UnknownCodeError, if the code or one of the elements
        of the sum is not present in the instance
        '''
        classifications = []
        for code in self._get_codes(code):
            _class = self._get_single_class(code)
            classifications.append(_class)
        return set(classifications)

class Hostname(name.Name):
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
        value  = str(value)
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
            return  func(value)
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


tld_extractor = tldextract.TLDExtract()


def registered_domain(value):
    ''' Create a Hostname instance representing registered domain
    extracted from the value

    :param value: a valid host string
    :returns: a Hostname instance representing registered domain
    :raises InvalidHostnameError: if the value is not a valid hostname
    '''
    registered_domain_string = tld_extractor(value).registered_domain
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
