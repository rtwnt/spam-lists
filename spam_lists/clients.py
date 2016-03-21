# -*- coding: utf-8 -*-

'''
This module contains instances of objects representing clients of services
that can be ready for use without providing custom, user-specific data, like
API codes, application identifiers or custom data sets.
'''
from __future__ import unicode_literals

from .service_models import DNSBL
from .structures import SimpleClassificationCodeMap, ip_address, \
registered_domain, registered_domain_or_ip, SumClassificationCodeMap


spamhaus_xbl_classification = (
                               'CBL (3rd party exploits such as proxies,'
                               ' trojans, etc.)'
                               )
spamhaus_pbl_classification = (
                               'End-user Non-MTA IP addresses set by ISP'
                               ' outbound mail policy'
                               )

spamhaus_zen_classification = {
                               2: (
                                   'Direct UBE sources, spam operations'
                                    ' & spam services'
                                    ),
                               3: (
                                   'Direct snowshoe spam sources detected'
                                   ' via automation'
                                   ),
                               4: spamhaus_xbl_classification,
                               5: spamhaus_xbl_classification,
                               6: spamhaus_xbl_classification,
                               7: spamhaus_xbl_classification,
                               10: spamhaus_pbl_classification,
                               11: spamhaus_pbl_classification
                               }

spamhaus_zen = DNSBL(
                     'spamhaus_zen',
                     'zen.spamhaus.org',
                     SimpleClassificationCodeMap(spamhaus_zen_classification),
                     ip_address
                     )


spamhaus_dbl_classification = {
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

spamhaus_dbl = DNSBL(
                     'spamhaus_dbl',
                     'dbl.spamhaus.org',
                     SimpleClassificationCodeMap(spamhaus_dbl_classification),
                     registered_domain
                     )

surbl_multi_classification = {
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

surbl_multi = DNSBL(
                    'surbl_multi',
                    'multi.surbl.org',
                    SumClassificationCodeMap(surbl_multi_classification),
                    registered_domain_or_ip
                    )
