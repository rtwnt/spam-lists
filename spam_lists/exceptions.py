# -*- coding: utf-8 -*-

class SpamBLError(Exception):
    '''There was an error during testing a url or host'''
    
class UnknownCodeError(SpamBLError):
    '''The classification code from the service was not recognized'''
    
class UnathorizedAPIKeyError(SpamBLError):
    '''The API key used to query the service was not authorized'''
