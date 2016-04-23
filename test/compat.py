# -*- coding: utf-8 -*-
'''
A common module for compatibility related imports and
definitions used during testing
'''

from __future__ import unicode_literals

import unittest

from six import assertCountEqual, PY2, PY3


try:
    from unittest.mock import Mock, MagicMock, patch # @NoMove
except ImportError:
    from mock import Mock, MagicMock, patch  # @NoMove @UnusedImport

if PY3:
    from functools import lru_cache # @NoMove @UnusedImport @UnresolvedImport

class Py2TestCase(unittest.TestCase):
    def assertCountEqual(self, expected_sequence, actual_sequence):
        return assertCountEqual(self, expected_sequence, actual_sequence)
        
if PY2:
    unittest.TestCase = Py2TestCase
    from cachetools.func import lru_cache # @NoMove @UnusedImport @Reimport @UnresolvedImport
    
