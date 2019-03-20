# -*- coding: utf-8 -*-

import time
import random
import binascii
import struct
import sys
import os

import slots
'''
p = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print p
if p not in sys.path:
    sys.path.insert(0, p)
'''

class Bots(slots.slots):
    _stub = None
    def __init__(self, _stub):
        _stub.log('Bots __init__')
        super(Bots, self).__init__(_stub)
        self._stub = _stub

        self.append_slot('on_bot_message')
        self.session_file = "bots.txt"

        try:
            self.session_data = self.load_dict(self.session_file)
        except Exception,e:
            self.session_data = {}
            _stub.log(e)
            return
        for k, v in self.session_data.items():
            _stub.log(self.Plug(v))

    def Plug(self, moduleName):
        result = super(Bots, self).Plug('bot.' + moduleName)
        if result.startswith('plug succ:'):
            self.session_set(moduleName,moduleName)
        return result
    def Unplug(self, moduleName):
        result = super(Bots, self).Unplug('bot.' + moduleName)
        if result.startswith('remove succ:'):
            self.session_remove(moduleName,moduleName)
        return result

