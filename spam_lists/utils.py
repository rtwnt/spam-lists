# -*- coding: utf-8 -*-

'''
This module contains various utilities to be used to create
composite spam url checkers.
'''

from __future__ import unicode_literals

from itertools import chain

from builtins import object
from requests import Session
from requests.exceptions import ConnectionError, InvalidSchema, InvalidURL, \
Timeout

from .exceptions import InvalidURLError
from .validation import accepts_valid_urls, is_valid_url


class CachedIterable(object):
    '''
    An iterable returning items from an iterator
    and caching them for future runs
    
    Items are returned in fixed order.
    '''
    def __init__(self, iterator, initial_cache=None):
        ''' Constructor
        
        :param iterator: an iterator, wrom which items
         will be returned and cached
        :param initial_cache: values added to cache before
         the first run
        '''
        if initial_cache is None:
            initial_cache = []
        self._cache = list(initial_cache)
        self._iterator = iterator

    def __iter__(self):
        for i in self._cache:
            yield i
        for i in self._iterator:
            self._cache.append(i)
            yield i


class RedirectUrlResolver(object):
    ''' A class used for getting all redirect urls for
    given url
    
    The urls include:
    * url addresses of all responses acquired for a HEAD request in its
     response history
    * value of location header for the last response, if it is
    a valid url but we still couldn't get a response for it
    '''
    def __init__(self, requests_session = Session()):
        '''
        Constructor
        
        :param requests_session: a session object implementing
        methods:
        * head(url) (for HEAD request)
        * resolve_redirects(response, request)
        '''
        
        self.session = requests_session
        
    def _get_first_response(self, url):
        ''' Get the first response to HEAD request for given url
        
        :param url: a url value
        :returns: If no exception was raised, it returns 
        an object representing the first response in the response history 
        for given url.
        
        Otherwise, None is returned.
        
        :raises InvalidURLError: if the parameter is not a valid url value
        '''
        
        if not is_valid_url(url):
            raise InvalidURLError('{} is not a valid url'.format(url))
        
        try:
            return self.session.head(url)
        
        except (ConnectionError, InvalidSchema, Timeout):
            return None
        
    def get_locations(self, url):
        ''' Get valid location header values from
        responses for given url
        
        :param url: a url value
        :returns: valid redirection addresses. If a request
        for an address fails, and the address is still a valid url string, 
        it's included as the last yielded value. If it's not, the previous value
        is the last one.
        :raises ValuError: if the argument is not a valid url
        '''
        
        response = self._get_first_response(url)
        
        if response:
            try:
                generator = self.session.resolve_redirects(
                                                           response,
                                                           response.request
                                                           )
                for response in generator:
                    yield response.url
                    
            except InvalidURL:
                pass
                
            except (Timeout, ConnectionError, InvalidSchema) as error:
                last_url = response.headers['location']
                
                if isinstance(error, Timeout) or is_valid_url(last_url):
                    yield last_url

class UrlTesterChain(object):
    '''
    A url tester using a sequence of other url testers
    '''
    
    def __init__(self, *url_testers):
        '''
        Constructor
        
        :param url_testers: a list of objects having any_match(urls)
         and lookup_matching(urls) 
         methods
        '''
        
        self.url_testers = list(url_testers)
        
    def any_match(self, urls):
        ''' Check if any of given urls is a match
        
        :param urls: a sequence of urls to be tested
        :returns: True if any of the urls is a match
        '''
        
        return any(t.any_match(urls) for t in self.url_testers)
    
    def lookup_matching(self, urls):
        '''
        Get objects representing match criteria (hosts, whole urls, etc) for
        given urls
        
        :param urls: an iterable containing urls
        :returns: items representing match criteria
        '''
        
        for tester in self.url_testers:
            for item in tester.lookup_matching(urls):
                yield item
                
    def filter_matching(self, urls):
        ''' Get those of given ruls that match listing criteria 
        (hosts, whole urls, etc.)
        
        :param urls: an iterable containing urls
        :returns: matching urls
        '''
        seen = set()
        urls = set(urls)
        for tester in self.url_testers:
            urls = urls - seen
            for url in tester.filter_matching(urls):
                if url not in seen:
                    seen.add(url)
                    yield url
                    
class UrlsAndLocations(object):
    ''' 
    An iterable returning given urls and
    their redirect urls
    '''
    
    @accepts_valid_urls
    def __init__(self, urls, redirect_resolver=RedirectUrlResolver()):
        ''' Constructor
        
        :param urls: a sequence of urls
        :param redirect resolver: an object that has get_locations method
        :raises InvalidURLError: if the urls argument contains an invalid url
        '''
        
        self._redirect_resolver = redirect_resolver
        self._all_resolved = False
        
        self._initial_urls = set(urls)
        self._cached_urls = list(self._initial_urls)
        
    def __iter__(self):
        ''' Get iterator that returns all urls acquired so far (initial urls
        provided when creating the instance + redirect urls).
        
        If the url resolution was not completed, the methods
        performs further resolution when necessary
        '''
        
        if self._all_resolved:
            return iter(self._cached_urls)
        
        return chain(self._cached_urls, self._get_redirect_urls())
    
    def _get_redirect_urls(self):
        '''
        Get redirect urls for all initial urls
        
        Each value yielded by the function is cached, so it
        can be reused in next loop.
        
        :returns: redirect url value returned
        by _redirect_resolver for given initial url, if it
        was not cached before
        '''
        for url in self._initial_urls:
            for redirect_url in self._redirect_resolver.get_locations(url):
                if redirect_url not in self._cached_urls:
                    self._cached_urls.append(redirect_url)
                    yield redirect_url
        self._all_resolved = True

