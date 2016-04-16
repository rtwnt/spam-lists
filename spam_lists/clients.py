# -*- coding: utf-8 -*-

'''
This module contains instances of objects representing clients of services
that can be ready for use without providing custom, user-specific data, like
API codes, application identifiers or custom data sets.
'''
from __future__ import unicode_literals

from .service_models import DNSBL, TwoToTheNSumDNSBL
from .structures import SimpleClassificationCodeMap, ip_address, \
    registered_domain, registered_domain_or_ip, SumClassificationCodeMap


SPAMHAUS_XBL_CLASSIFICATION = (
                               'CBL (3rd party exploits such as proxies,'
                               ' trojans, etc.)'
                               )
SPAMHAUS_PBL_CLASSIFICATION = (
                               'End-user Non-MTA IP addresses set by ISP'
                               ' outbound mail policy'
                               )

SPAMHAUS_ZEN_CLASSIFICATION = {
                               2: (
                                   'Direct UBE sources, spam operations'
                                   ' & spam services'
                                   ),
                               3: (
                                   'Direct snowshoe spam sources detected'
                                   ' via automation'
                                   ),
                               4: SPAMHAUS_XBL_CLASSIFICATION,
                               5: SPAMHAUS_XBL_CLASSIFICATION,
                               6: SPAMHAUS_XBL_CLASSIFICATION,
                               7: SPAMHAUS_XBL_CLASSIFICATION,
                               10: SPAMHAUS_PBL_CLASSIFICATION,
                               11: SPAMHAUS_PBL_CLASSIFICATION
                               }

SPAMHAUS_ZEN = DNSBL(
                     'spamhaus_zen',
                     'zen.spamhaus.org',
                     SimpleClassificationCodeMap(SPAMHAUS_ZEN_CLASSIFICATION),
                     ip_address
                     )


SPAMHAUS_DBL_CLASSIFICATION = {
                               2: 'spam domain',
                               4: 'phishing domain',
                               5: 'malware domain',
                               6: 'botnet C&C domain',
                               102: 'abused legit spam',
                               103: 'abused spammed redirector domain',
                               104: 'abused legit phishing',
                               105: 'abused legit malware',
                               106: 'abused legit botnet C&C',
                               }

SPAMHAUS_DBL = DNSBL(
                     'spamhaus_dbl',
                     'dbl.spamhaus.org',
                     SimpleClassificationCodeMap(SPAMHAUS_DBL_CLASSIFICATION),
                     registered_domain
                     )

SURBL_MULTI_CLASSIFICATION = {
                              2: 'deprecated (previously SpamCop web sites)',
                              4: 'listed on WS (will migrate to ABUSE'
                              ' on 1 May 2016)',
                              8: 'phishing',
                              16: 'malware',
                              32: 'deprecated (previously AbuseButler'
                              ' web sites)',
                              64: 'spam and other abuse sites: (previously'
                              ' jwSpamSpy + Prolocation sites, SpamCop'
                              ' web sites, AbuseButler web sites)',
                              128: 'Cracked sites'
                              }

SURBL_MULTI = TwoToTheNSumDNSBL(
                    'surbl_multi',
                    'multi.surbl.org',
                    SumClassificationCodeMap(SURBL_MULTI_CLASSIFICATION),
                    registered_domain_or_ip
                    )
