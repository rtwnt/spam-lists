# -*- coding: utf-8 -*-
'''
====================
spam-lists library
====================

spam-lists provides common interfaces for querying whitelists and
blacklists containing web addresses: hostnames, IP addresses or urls.

It supports the following third party services:

    * `Spamhaus ZEN https://www.spamhaus.org/zen/`_
    * `Spamhaus DBL https://www.spamhaus.org/dbl/`_
    * `SURBL http://www.surbl.org/`_
    * `hpHosts http://www.hosts-file.net/`_
    * `Google Safe Browsing Lookup API https://developers.google.com/
    safe-browsing/lookup_guide`_

In addition, it provides a HostCollection class whose instances can be
used as custom host whitelists or blacklists.

Python versions: 2.7.x, 3.4.x and greater are supported.

************
API:
************

The services and custom web address lists can be queried using
the following interfaces:

    * host list interface, containing methods that receive values
    representing hostnames or IP addresses for which we query
    service represented by an object.

    The methods returns values depending on the given value being
    listed (or not) by the service.

    The interface contains the following methods:

        * __contains__: tests membership of given host in
        the host list. Returns a boolean value.
        * lookup: returns an object representing given item. If it is
        listed, an instance of spam_lists.structures.AddressListItem is
        returned, otherwise the method returns None.

    * url tester interface, containing methods that receive an iterable
    containing urls for which we query service(s) represented by
    an object.

    The methods return values depending on recognizing (or not) any of
    the url values as matching criteria used by the service
    (hostnames, IP addresses, etc.)

    The interface contains the following methods:

        * any_match: checks if any of the urls is recognized as
        a match. Returns a boolean value
        * filter_matching: returns a generator yielding matching urls
        * lookup_matching: returns a generator yielding instances of
        spam_lists.structures.AddressListItem representing matching
        criteria for matching urls.

The following objects are part of the API:

:var SPAMHAUS_DBL: Spamhaus DBL service client, implementing host list
and url tester interfaces.

:var SPAMHAUS_ZEN: Spamhaus ZEN service client, implementing host list
and url tester interfaces.

:var SURBL_MULTI: SURBL service client, implementing host list and url
tester interfaces.

:var HpHosts: a class of objects used as clients for hpHosts service,
implementing host list and url tester interfaces.

:var GoogleSafeBrowsing: a class of objects used as clients for
Google Safe Browsing Lookup API service, implementing url tester
interface.

:var HostCollection: a class of objects representing custom host lists,
implementing host list and url tester interfaces.

:var SortedHostCollection: a class of objects representing custom
sorted host lists, implementing host list and url tester interfaces.

:var UrlTesterChain: a class of objects representing composite
url testers, created by providing objects with url tester methods
as arguments to constructor. It implements url tester interface.

:var GeneralizedUrlTester: a class adding url whitelist and redirect
resolution to a url tester to be used. Instances are created by calling
the constructor with the following arguments:

    * the url tester object
    * (optionally) a whitelist object implementing filter_matching
    method of the url tester interface.
    * (optionally) an instance of redirect url resolver to use

GeneralizedUrlTester implements an interface similar to the url tester
interface, with methods any_match, filter_matching and lookup_matching
all receiving an additional argument: a boolean value specifying if
we should include results of redirect url resolution for given urls in
the data set for which we query service(s) represented by
the url tester.

:copyright: (c) 2016 by Piotr Rusin.
:license: Apache 2.0, see LICENSE for more details.
'''
from __future__ import unicode_literals

from .clients import (
    SPAMHAUS_DBL, SPAMHAUS_ZEN, SURBL_MULTI, HpHosts, GoogleSafeBrowsing
)
from .host_collections import HostCollection, SortedHostCollection
from .composites import UrlTesterChain, GeneralizedUrlTester

__title__ = 'spam-lists'
__version__ = '1.0.0b7'
__author__ = 'Piotr Rusin'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 Piotr Rusin'
