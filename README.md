# spam-lists

A library for querying custom and third party web address blacklists and whitelists.

## Features

- client classes for the following services: Google Safe Browsing Lookup API and hpHosts, provided by spam_lists.clients module.
- support for custom DNSBL service clients, using DNSBL and BitmaskingDNSBL classes from the spam_lists.clients module
- preconfigured instances of BitmaskingDNSBL and DNSBL for the following services: SURBL, Spamhaus ZEN, Spamhaus DBL
- combining multiple url testers into a composite tester, using UrlTesterChain and GeneralizedUrlTester from spam_lists.composites module
- redirect resolution: all reachable response urls and unavailable addresses stored in HTTP Location header can be included in testing their inclusion in a whitelist by using RedirectResolver or GeneralizedUrlTester classes from spam_lists.composites module
- support for Python 2 and 3

## Usage
Simple test for membership of a host value in a host blacklist:
```python
>>> from spam_lists import SPAMHAUS_DBL
>>> 'dbltest.com' in SPAMHAUS_DBL
True
```

Lookup method returns an instance of spam_lists.structures.AddressListItem -
a named tuple containing:
- a listed host that is a parent domain of a searched
domain, or a listed ip address equal to one searched in the blacklist
- source of the returned information as an instance of the client used to search for the value
- a set of classificiation terms associated with the value
```python
>>> SPAMHAUS_DBL.lookup('dbltest.com')
AddressListItem(value=u'dbltest.com', ...))
```

Testing if there is any spam in a sequence of urls:
```python
>>> urls_to_test = 'http://google.com', 'http://wikipedia.org', 'http://dbltest.com'
>>> SPAMHAUS_DBL.any_match(urls_to_test)
True
```

Filtering recognized spam urls out of a sequence of values returns a generator object...
```python
>>> result = SPAMHAUS_DBL.filter_matching(urls_to_test)
>>> result
<generator object <genexpr> at 0xb4f60a7c>
>>> list(result)
['http://dbltest.com']
```
... as does calling lookup_matching, but here the values yielded by the generator are instances of the AddressListItem named tuple:
```python
>>> result = SPAMHAUS_DBL.lookup_matching(urls_to_test)
>>> result
<generator object lookup_matching at 0xb4f60e3c>
>>> list(result)
[AddressListItem(value=u'dbltest.com', ...)]
```

For further information, read [spam_lists package docstring](https://github.com/piotr-rusin/spam-lists/blob/master/spam_lists/__init__.py).

## License
Apache 2.0 See [LICENSE](https://github.com/piotr-rusin/spam-lists/blob/master/LICENSE)