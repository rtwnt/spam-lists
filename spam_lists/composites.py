# -*- coding: utf-8 -*-

"""Classes used to create composite malicious URL checkers."""

from __future__ import unicode_literals

from builtins import object  # pylint: disable=redefined-builtin
from requests import Session
from requests.exceptions import (
    ConnectionError, InvalidSchema, InvalidURL, Timeout
)

from .exceptions import InvalidURLError
from .validation import is_valid_url


class CachedIterable(object):
    """A class of lazy iterables created from iterators.

    Instances of this class return items from an iterator and cache
    them for future runs.

    Items are returned in fixed order.
    """

    def __init__(self, iterator, initial_cache=None):
        """Initialize a new instance.

        :param iterator: an iterator, wrom which items
         will be returned and cached
        :param initial_cache: values added to cache before
         the first run
        """
        if initial_cache is None:
            initial_cache = []
        self._cache = list(initial_cache)
        self._iterator = iterator

    def __iter__(self):
        """Yield elements of the iterable."""
        for i in self._cache:
            yield i
        for i in self._iterator:
            self._cache.append(i)
            yield i


class RedirectURLResolver(object):
    """Extracts URL addresses from responses and location headers.

    Instances of this class can be used to acquire the following:
    * URL addresses of all responses acquired for a HEAD request in its
     response history
    * value of location header for the last response, if it is a valid
    URL but we still couldn't get a response for it
    """

    def __init__(self, requests_session=Session()):
        """Initialize a new instance.

        :param requests_session: a session object implementing
        methods:
        * head(url) (for HEAD request)
        * resolve_redirects(response, request)
        """
        self.session = requests_session

    def get_locations(self, url):
        """Get valid location header values from responses.

        :param url: a URL address. If a HEAD request sent to it
        fails because the address has invalid schema, times out
        or there is a connection error, the generator yields nothing.
        :returns: valid redirection addresses. If a request for
        a redirection address fails, and the address is still a valid
        URL string, it's included as the last yielded value. If it's
        not, the previous value is the last one.
        :raises ValuError: if the argument is not a valid URL
        """
        if not is_valid_url(url):
            raise InvalidURLError('{} is not a valid URL'.format(url))
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
        """Get valid location header values for all given URLs.

        The returned values are new, that is: they do not repeat any
        value contained in the original input. Only unique values
        are yielded.

        :param urls: a list of URL addresses
        :returns: valid location header values from responses
        to the URLs
        """
        seen = set(urls)
        for i in urls:
            for k in self.get_locations(i):
                if k not in seen:
                    seen.add(k)
                    yield k

    def get_urls_and_locations(self, urls):
        """Get URLs and their redirection addresses.

        :param urls: a list of URL addresses
        :returns: an instance of CachedIterable containing given URLs
        and valid location header values of their responses
        """
        location_generator = self.get_new_locations(urls)
        initial_cache = list(set(urls))
        return CachedIterable(location_generator, initial_cache)


class URLTesterChain(object):
    """A URL tester using a sequence of other URL testers."""

    def __init__(self, *url_testers):
        """Initialize a new url tester chain.

        :param url_testers: a tuple containing objects, each having
        the following methods:
            * any_match(urls)
            * lookup_matching(urls)
            * filter_matching(urls)
        """
        self.url_testers = list(url_testers)

    def any_match(self, urls):
        """Check if any of given URLs is a match.

        :param urls: an iterable containing URLs to be tested
        :returns: True if any of the URLs is a match for any of
        the URL testers in the chain.
        """
        return any(t.any_match(urls) for t in self.url_testers)

    def lookup_matching(self, urls):
        """Get values of match criteria for listed URLs.

        :param urls: an iterable containing URLs to be tested
        :returns: objects representing match criteria (hosts and whole
        URL addresses) for those of the given URLs that are recognized
        as matching by the URL testers in the chain.
        """
        for tester in self.url_testers:
            for item in tester.lookup_matching(urls):
                yield item

    def filter_matching(self, urls):
        """Get those of given URLs that match listing criteria.

        :param urls: an iterable containing URLs to be tested
        :returns: URLs whose values or their parts (like hosts) match
        listing criteria of the URL testers in the chain.
        """
        seen = set()
        urls = set(urls)
        for tester in self.url_testers:
            urls = urls - seen
            for url in tester.filter_matching(urls):
                if url not in seen:
                    seen.add(url)
                    yield url


class GeneralizedURLTester(object):
    """A URL tester that can use a redirect resolver and a whitelist."""

    def __init__(self, url_tester, whitelist=None,
                 redirect_resolver=RedirectURLResolver()):
        """Initialize a new instance.

        :param url_tester: an object with any_match, filter_matching
        and lookup_matching methods that can be used for testing URLs
        :param whitelist: an object with a filter_matching method, used
        for filtering URLs to be tested against the url_tester
        :param redirect_resolver: an object used for getting valid
        location header values to test them with the other URL values.
        """
        self.url_tester = url_tester
        self.whitelist = whitelist
        self.redirect_resolver = redirect_resolver

    def _get_results_for(self, function, urls, resolve_redirects):
        """Get results of given function for given arguments.

        :param function: a function to be called
        :param urls: an iterable containing initial URL values
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given URLs and
        tested with them.
        """
        urls_to_test = urls
        if resolve_redirects:
            urls_to_test = self.redirect_resolver.get_urls_and_locations(urls)
        if self.whitelist is not None:
            generator = self.whitelist.filter_matching(urls_to_test)
            urls_to_test = list(set(urls_to_test) - set(generator))
        return function(urls_to_test)

    def any_match(self, urls, resolve_redirects=True):
        """Check if any of given URLs is a match.

        :param urls: an iterable containing URLs to be tested
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given URLs and
        tested with them.
        :returns: True if any of the URLs is a match for the URL tester
        """
        return self._get_results_for(
            self.url_tester.any_match,
            urls,
            resolve_redirects
        )

    def filter_matching(self, urls, resolve_redirects=True):
        """Get URLs that match listing criteria.

        :param urls: an iterable containing URLs to be tested
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given URLs and
        tested with them.
        :returns: URLs whose values or their parts (like hosts) match
        listing criteria of the URL tester
        """
        return self._get_results_for(
            self.url_tester.filter_matching,
            urls,
            resolve_redirects
        )

    def lookup_matching(self, urls, resolve_redirects=True):
        """Get values of match criteria for listed URLs.

        :param urls: an iterable containing URLs to be tested
        :param resolve_redirects: a boolean value. If True, all valid
        redirect location values will be resolved for given URLs and
        tested with them.
        :returns: objects representing match criteria (hosts and whole
        URL addresses) for those of the given URLs and their response
        addresses that are recognized as matching by the URL tester
        """
        return self._get_results_for(
            self.url_tester.lookup_matching,
            urls,
            resolve_redirects
        )
