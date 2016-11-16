# -*- coding: utf-8 -*-
"""Python 2 and 3 compatibility layer for tests."""

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
    """Adapter for tests executed with Python 2 interpreter."""

    def assertCountEqual(self, expected_sequence, actual_sequence, msg=None):
        """Test if both sequences have the same number of items.

        :param first: the first sequence
        :param second: the second sequence
        :param msg: a message to be displayed if the test fails
        :returns: a result of the test
        """
        return assertCountEqual(self, expected_sequence, actual_sequence, msg)


if PY2:
    unittest.TestCase = Py2TestCase
