# -*- coding: utf-8 -*-

class SpamListsError(Exception):
    '''There was an error during testing a url or host'''
    
class UnknownCodeError(SpamListsError, KeyError):
    '''The classification code from the service was not recognized'''
    
class UnathorizedAPIKeyError(SpamListsError, ValueError):
    '''The API key used to query the service was not authorized'''

class InvalidHostnameError(SpamListsError, ValueError):
    '''The value is not a valid hostname'''
    
class InvalidURLError(SpamListsError, ValueError):
    '''The value is not a valid url'''
