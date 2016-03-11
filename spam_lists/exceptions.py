# -*- coding: utf-8 -*-

class SpamBLError(Exception):
    ''' Base exception class for spambl module '''
    
class UnknownCodeError(SpamBLError):
    ''' Raise when trying to use an unexpected value of dnsbl return code '''
    
class UnathorizedAPIKeyError(SpamBLError):
    ''' Raise when trying to use an unathorized api key '''
