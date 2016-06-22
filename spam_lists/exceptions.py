# -*- coding: utf-8 -*-
'''
This module contains all classes of exceptions raised
by the library
'''
from __future__ import unicode_literals


class SpamListsError(Exception):
    '''There was an error during testing a url or host'''


class SpamListsValueError(SpamListsError, ValueError):
    '''An inapropriate value was used in spam-lists library '''


class UnknownCodeError(SpamListsError, KeyError):
    '''The classification code from the service was not recognized'''


class UnathorizedAPIKeyError(SpamListsValueError):
    '''The API key used to query the service was not authorized'''


class InvalidHostError(SpamListsValueError):
    '''The value is not a valid host'''


class InvalidIPError(InvalidHostError):
    ''' The value is not a valid IP address'''


class InvalidIPv4Error(InvalidIPError):
    '''The value is not a valid IPv4 address'''


class InvalidIPv6Error(InvalidIPError):
    '''The value is not a valid IPv6 address'''


class InvalidHostnameError(InvalidHostError):
    '''The value is not a valid hostname'''


class InvalidURLError(SpamListsValueError):
    '''The value is not a valid url'''
