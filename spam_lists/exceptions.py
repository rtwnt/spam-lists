# -*- coding: utf-8 -*-

class SpamListsError(Exception):
    '''There was an error during testing a url or host'''
    
class UnknownCodeError(SpamListsError):
    '''The classification code from the service was not recognized'''
    
class UnathorizedAPIKeyError(SpamListsError):
    '''The API key used to query the service was not authorized'''
