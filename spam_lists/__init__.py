# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from .clients import SPAMHAUS_DBL, SPAMHAUS_ZEN, SURBL_MULTI
from .service_models import HpHosts, GoogleSafeBrowsing, HostCollection
from .utils import UrlTesterChain, GeneralizedUrlTester

__title__ = 'spam-lists'
__version__ = '0.9'
__author__ = 'Piotr Rusin'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 Piotr Rusin'
