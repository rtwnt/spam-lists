# -*- coding: utf-8 -*-

from spambl import AddressListItem

class BaseValueTesterTest(object):
    
    classification = ('TEST',)
    
    def _get_expected_items(self, values):
        item = lambda i: AddressListItem(i, self.tested_instance,
                                             self.classification)
        return [item(v) for v in values]
        
