# spam-lists
A library for testing web addresses for inclusion in local and remote whitelists or blacklists, using DNSBL and other services.

Currently supported services:
* Spamhaus ZEN
* Spamhaus DBL
* SURBL
* hpHosts
* Google Safe Browsing (lookup API)

Other features:
* easy addition of custom clients for DNSBL services using spam_lists.service_models.DNSBL class
* support for custom whitelists and blacklists represented by instances of spam_lists.service_models.HostCollection class
* support for combining multiple url testers into a composite tester, using UrlTesterChain and GeneralizedUrlTester from spam_lists.utils module

TODO:
- improve documentation
