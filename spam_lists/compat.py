# -*- coding: utf-8 -*-
"""A module providing a compatibility layer for python 2 and 3.

Most of the compatibility-related features are already provided
by future and other modules - this module provides the ones specific to
this project, like definitions depending on the version of
the interpreter, complex imports that may result in errors, etc.
"""
# pylint: disable=unused-import
# pylint: disable=import-error

try:
    from functools import lru_cache  # @NoMove
except ImportError:
    from cachetools.func import lru_cache  # @NoMove @UnusedImport
