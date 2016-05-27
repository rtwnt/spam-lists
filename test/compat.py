# -*- coding: utf-8 -*-
'''
A common module for compatibility related imports and
definitions used during testing
'''
# pylint: disable=unused-import

from __future__ import unicode_literals

import unittest

try:
    from unittest.mock import Mock, MagicMock, patch  # @NoMove
except ImportError:
    # pylint: disable=import-error
    from mock import Mock, MagicMock, patch  # @NoMove @UnusedImport

from six import assertCountEqual, PY2

from spam_lists.compat import lru_cache  # @NoMove @UnusedImport


class Py2TestCase(unittest.TestCase):
    def assertCountEqual(self, expected_sequence, actual_sequence, msg=None):
        return assertCountEqual(self, expected_sequence, actual_sequence, msg)


if PY2:
    unittest.TestCase = Py2TestCase
