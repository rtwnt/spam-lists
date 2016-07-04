spam-lists
==========

A library for querying custom and third party web address blacklists and
whitelists.

Features
--------

-  client classes for `Google Safe Browsing Lookup API`_ and hpHosts_ services, provided by
   spam\_lists.clients module.
-  support for custom DNSBL service clients, using DNSBL and BitmaskingDNSBL
   classes from the spam\_lists.clients module
-  preconfigured instances of BitmaskingDNSBL and DNSBL for the
   following services: SURBL_, `Spamhaus ZEN`_, `Spamhaus DBL`_
-  combining multiple url testers into a composite tester, using
   UrlTesterChain and GeneralizedUrlTester from spam\_lists.composites
   module
-  redirect resolution: all reachable response urls and unavailable
   addresses stored in HTTP Location headers for given urls can be included
   in values searched for in a whitelist by using RedirectResolver or
   GeneralizedUrlTester classes from spam\_lists.composites module
-  support for Python 2 and 3

.. _Google Safe Browsing Lookup API: https://developers.google.com/
   safe-browsing/v3/lookup-guide
.. _hpHosts: https://www.hosts-file.net/
.. _SURBL: http://www.surbl.org/lists#multi
.. _Spamhaus ZEN: https://www.spamhaus.org/zen/
.. _Spamhaus DBL: https://www.spamhaus.org/dbl/

Usage
-----

Simple test for membership of a host value in a host blacklist:

.. code:: python

    >>> from spam_lists import SPAMHAUS_DBL
    >>> 'dbltest.com' in SPAMHAUS_DBL
    True

Lookup method returns an instance of
spam\_lists.structures.AddressListItem - a named tuple containing:

-  a listed host that is a parent of a searched domain, or a listed ip address
   equal to one searched in the blacklist
-  source of the returned information as an instance of the client used
   to search for the value
-  a set of classificiation terms associated with the value

.. code:: python

    >>> SPAMHAUS_DBL.lookup('dbltest.com')
    AddressListItem(value=u'dbltest.com', ...)

Testing if there is any spam url in a sequence:

.. code:: python

    >>> urls_to_test = (
    'http://google.com',
    'http://wikipedia.org',
    'http://dbltest.com'
    )
    >>> SPAMHAUS_DBL.any_match(urls_to_test)
    True

Filtering recognized spam urls out of a sequence of values returns a
generator object...

.. code:: python

    >>> result = SPAMHAUS_DBL.filter_matching(urls_to_test)
    >>> result
    <generator object <genexpr> at 0xb4f60a7c>
    >>> list(result)
    ['http://dbltest.com']

... as does calling lookup\_matching, but here the values yielded by the
generator are instances of the AddressListItem named tuple:

.. code:: python

    >>> result = SPAMHAUS_DBL.lookup_matching(urls_to_test)
    >>> result
    <generator object lookup_matching at 0xb4f60e3c>
    >>> list(result)
    [AddressListItem(value=u'dbltest.com', ...)]

For further information, read `spam_lists package docstring`__.

.. __: https://github.com/piotr-rusin/spam-lists/
   blob/master/spam_lists/__init__.py

Installation
------------

Install using pip:

.. code:: bash

    $ pip install spam-lists

To be able to run tests, install test extras:

.. code:: bash

    $ pip install spam-lists[test]

You can also install dev-tools extras, currently containing pylint_ and
restview_:

.. _pylint: https://www.pylint.org/
.. _restview: https://mg.pov.lt/restview/

.. code:: bash

    $ pip install spam-lists[dev-tools]

License
-------

| Apache 2.0
| See LICENSE__

.. __: https://github.com/piotr-rusin/spam-lists/blob/master/LICENSE
