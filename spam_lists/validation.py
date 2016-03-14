# -*- coding: utf-8 -*-

'''
This module contains functions responsible for
validating arguments for other functions and
methods provided by the library
'''

import functools
import re
from urlparse import urlparse

import validators

from .exceptions import InvalidURLError

def is_valid_host(value):
    ''' Check if given value is valid host string
    
    :param value: a value to test
    :returns: True if the value is valid host string
    '''
    host_validators = validators.ipv4, validators.ipv6, validators.domain
    return any(f(value) for f in host_validators)

url_regex = re.compile(r'^[a-z0-9\.\-\+]*://' #scheme
                       r'(?:\S+(?::\S*)?@)?' #authentication
                       r'(?:[^/:]+|\[[0-9a-f:\.]+\])' # host
                       r'(?::\d{2,5})?' # port
                       r'(?:[/?#][^\s]*)?' # path, query or fragment
                       r'$', re.IGNORECASE)

def is_valid_url(value):
    ''' Check if given value is valid url string
    
    :param value: a value to test
    :returns: True if the value is valid url string
    '''
    
    match = url_regex.match(value)
    host_str = urlparse(value).hostname
    
    return (match and is_valid_host(host_str))
    

def accepts_valid_urls(f):
    @functools.wraps(f)
    def wrapper(obj, urls, *args, **kwargs):
        '''Run the function and return its return value
         if all given urls are valid - otherwise raise InvalidURLError
        :param obj: an object in whose class f is defined
        :param urls: an iterable containing urls
        :returns: a return value of the function f
        :raises InvalidURLError: if the iterable contains invalid urls
        '''
        invalid_urls = filter(lambda u: not is_valid_url(u), urls)
        if invalid_urls:
            msg = 'The values: {} are not valid urls'.format(','.join(invalid_urls))
            raise InvalidURLError, msg
        
        return f(obj, urls, *args, **kwargs)
    
    return wrapper
