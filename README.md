# spam-lists

A library for using custom and third party web address blacklists and whitelists.

## Features

- client classes for the following services: Google Safe Browsing lookup API, hpHosts. Provided in spam_lists.clients module.
- support for custom DNSBL service clients, using DNSBL and BitmaskingDNSBL classes from the spam_lists.clients module
- preconfigured instances of DNSBL and BitmaskingDNSBL for the following services: SURBL, Spamhaus ZEN, Spamhaus DBL
- combining multiple url testers into a composite tester, using UrlTesterChain and GeneralizedUrlTester from spam_lists.composites module
- redirect resolution: all reachable response urls and unavailable addresses stored in location HTTP header can be included in testing by using RedirectResolver or GeneralizedUrlTester classes from spam_lists.composites module
- support for Python 2 and 3

## Usage
Simple test for membership of a host value in a host blacklist:
```python
>>> from spam_lists import SPAMHAUS_DBL
>>> 'dbltest.com' in SPAMHAUS_DBL
True
```

Lookup method returns an instance of spam_lists.structures.AddressListItem -
a named tuple containing a listed host that is a parent domain of a searched
domain, source as an instance of the client used to query for the value,
and a set of classificiation terms.
```python
>>> SPAMHAUS_DBL.lookup('dbltest.com')
AddressListItem(value=u'dbltest.com', source=<spam_lists.clients.DNSBL object at 0xb4fd4cac>, classification=set([u'spam domain']))
```

Testing if there is any spam in a list of urls:
```python
>>> SPAMHAUS_DBL.any_match(['http://google.com', 'http://wikipedia.org', 'http://dbltest.com'])
True
```

Filtering recognizes spam urls out of a list of values returns a generator object...
```python
>>> result = SPAMHAUS_DBL.filter_matching(['http://google.com', 'http://wikipedia.org', 'http://dbltest.com'])
>>> result
<generator object <genexpr> at 0xb4f60a7c>
>>> list(result)
['http://dbltest.com']
```
... as does calling lookup_matching, but here the values yielded by the generator are instances of spam_lists.structures.AddressListItem:
```python
>>> result = SPAMHAUS_DBL.lookup_matching(['http://google.com', 'http://wikipedia.org', 'http://dbltest.com'])
>>> result
<generator object lookup_matching at 0xb4f60e3c>
>>> list(result)
[AddressListItem(value=u'dbltest.com', source=<spam_lists.clients.DNSBL object at 0xb4fd4cac>, classification=set([u'spam domain']))]
```

For further information, read [spam_lists package docstring](https://github.com/piotr-rusin/spam-lists/blob/master/spam_lists/__init__.py).

## License
Apache 2.0 See [LICENSE](https://github.com/piotr-rusin/spam-lists/blob/master/LICENSE)