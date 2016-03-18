# -*- coding: utf-8 -*-

'''
This module contains instances of objects representing clients of services
that can be ready for use without providing custom, user-specific data, like
API codes, application identifiers or custom data sets.
'''

from .service_models import DNSBL
from .structures import SimpleClassificationCodeMap, ip_address

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

