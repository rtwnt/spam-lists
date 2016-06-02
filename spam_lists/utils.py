# -*- coding: utf-8 -*-

'''
This module contains various utilities to be used to create
composite spam url checkers.
'''

from __future__ import unicode_literals

from builtins import object  # pylint: disable=redefined-builtin
from requests import Session
from requests.exceptions import (
    ConnectionError, InvalidSchema, InvalidURL, Timeout
)

from .exceptions import InvalidURLError
from .validation import is_valid_url


class CachedIterable(object):
    '''An iterable returning items from an iterator
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
    def __init__(self, requests_session=Session()):
        '''
        Constructor

        :param requests_session: a session object implementing
        methods:
        * head(url) (for HEAD request)
        * resolve_redirects(response, request)
        '''
        self.session = requests_session

    def get_locations(self, url):
        ''' Get valid location header values from
        responses for given url

        :param url: a url address. If a HEAD request sent to it
        fails because the address has invalid schema, times out
        or there is a connection error, the generator yields nothing
        :returns: valid redirection addresses. If a request for
        a redirection address fails, and the address is still a valid
        url string, it's included as the last yielded value. If it's
        not, the previous value is the last one.
        :raises ValuError: if the argument is not a valid url
        '''
        if not is_valid_url(url):
            raise InvalidURLError('{} is not a valid url'.format(url))
        try:
            response = self.session.head(url)
        except (ConnectionError, InvalidSchema, Timeout):
            raise StopIteration
        try:
            generator = self.session.resolve_redirects(
                response,
                response.request
            )
            for response in generator:
                yield response.url
        except InvalidURL:
            pass
        except (ConnectionError, InvalidSchema, Timeout) as error:
            last_url = response.headers['location']
            if isinstance(error, Timeout) or is_valid_url(last_url):
                yield last_url

    def get_new_locations(self, urls):
        ''' Get valid location header values for all given urls

        The returned values are new, that is: they do not repeat any
        value contained in the original input. Only unique values
        are yielded.

        :param urls: a list of url addresses
        :returns: valid location header values from responses
        to the urls
        '''
        seen = set(urls)
        for i in urls:
            for k in self.get_locations(i):
                if k not in seen:
                    seen.add(k)
                    yield k

    def get_urls_and_locations(self, urls):
        ''' Get urls and their redirection addresses

        :param urls: a list of url addresses
        :returns: an instance of CachedIterable containing given urls
        and valid location header values of their responses
        '''
        location_generator = self.get_new_locations(urls)
        initial_cache = list(set(urls))
        return CachedIterable(location_generator, initial_cache)


class UrlTesterChain(object):
    '''A url tester using a sequence of other url testers'''
    def __init__(self, *url_testers):
        '''Constructor

        :param url_testers: a list of objects having any_match(urls)
        and lookup_matching(urls) methods
        '''
        self.url_testers = list(url_testers)

    def any_match(self, urls):
        ''' Check if any of given urls is a match

        :param urls: a sequence of urls to be tested
        :returns: True if any of the urls is a match
        '''
        return any(t.any_match(urls) for t in self.url_testers)

    def lookup_matching(self, urls):
        '''Get objects representing match criteria
        (hosts, whole urls, etc) for given urls

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


class GeneralizedUrlTester(object):
    ''' A url tester using redirect resolution, whitelist
    and another url tester
    '''
    def __init__(self, url_tester, whitelist=None,
                 redirect_resolver=RedirectUrlResolver()):
        ''' Constructor

        :param url_tester: an object with any_match, filter_matching
        and lookup_matching methods that can be used for testing urls
        :param whitelist: an object with a filter_matching method, used
        for filtering urls to be tested against the url_tester
        :param redirect_resolver: an object used for getting valid
        location header values to test them with the other url values.
        '''
        self.url_tester = url_tester
        self.whitelist = whitelist
        self.redirect_resolver = redirect_resolver

    def _get_results_for(self, function, urls, resolve_redirects):
        ''' Get results of given function for given arguments

        :param function: a function to be called
        :param urls: an iterable containing initial url values
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given urls and
        tested with them
        '''
        urls_to_test = urls
        if resolve_redirects:
            urls_to_test = self.redirect_resolver.get_urls_and_locations(urls)
        if self.whitelist is not None:
            generator = self.whitelist.filter_matching(urls_to_test)
            urls_to_test = list(set(urls_to_test) - set(generator))
        return function(urls_to_test)

    def any_match(self, urls, resolve_redirects=True):
        ''' Check if any of given urls is a match

        :param urls: an iterable containing initial url values
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given urls and
        tested with them
        :returns: True if any of the urls is a match
        '''
        return self._get_results_for(
            self.url_tester.any_match,
            urls,
            resolve_redirects
        )

    def filter_matching(self, urls, resolve_redirects=True):
        ''' Get those of given ruls that match listing criteria
        (hosts, whole urls, etc.)

        :param urls: an iterable containing initial url values
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given urls and
        tested with them
        :returns: matching urls
        '''
        return self._get_results_for(
            self.url_tester.filter_matching,
            urls,
            resolve_redirects
        )

    def lookup_matching(self, urls, resolve_redirects=True):
        '''Get objects representing match criteria
        (hosts, whole urls, etc) for given urls

        :param urls: an iterable containing initial url values
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given urls and
        tested with them
        :returns: items representing match criteria
        '''
        return self._get_results_for(
            self.url_tester.lookup_matching,
            urls,
            resolve_redirects
        )
