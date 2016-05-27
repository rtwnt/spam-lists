# -*- coding: utf-8 -*-
'''
A module providing a compatibility layer for python 2 and 3.

Most of the compatibility-related features are already provided
by future and other modules. This module contains compatibility
features to be shared by spam-lists and test packages of
this project, like definitions depending on the version
of the interpreter, complex imports that may result in
errors, etc.

For now, it contains only code responsible for importing
functools.lru_cache or cachetools.func.lru_cache
'''
# pylint: disable=unused-import
# pylint: disable=import-error

try:
    from functools import lru_cache  # @NoMove
except ImportError:
    from cachetools.func import lru_cache  # @NoMove @UnusedImport
