#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import json

class slots(object):

    def __init__(self, _stub):
        self._stub = _stub
        self.session_file = "slots.txt"
        self.session_data = {}
        pass

    slots_table = {
    }
    
    stub_func_table = {
    }

    plugins = set()
    
    @classmethod
    def AddStubFunc(cls, func):
        print 'AddStubFunc ' + func.__name__
        try:
            cls.stub_func_table[func.__name__] = func
        except Exception,e:
            print e
        print 'AddStubFunc end'
        return func

    @classmethod
    def Import(cls,moduleName):
        if moduleName in sys.modules:
            reload(sys.modules[moduleName])
        else:
            __import__(moduleName)
        return sys.modules[moduleName]


    def unplug(self, moduleName, removeJob=True):
        for slots in self.slots_table.values():
            i = 0
            while i < len(slots):
                #if slots[i].__module__ == moduleName:
                if slots[i][0].__module__ == moduleName:
                    module = slots[i][1]
                    if hasattr(module, 'on_unplug'):
                        module.on_unplug(self._stub)
                    slots[i] = slots[-1]
                    slots.pop()
                else:
                    i += 1

        self.plugins.discard(moduleName)
    
    def Unplug(self, moduleName):
        if moduleName not in self.plugins:
            result = 'remove error: {}'.format(moduleName)
        else:
            self.unplug(moduleName)
            result = 'remove succ: {}'.format(moduleName)
        return result

    def Plug(self, moduleName):
        self.unplug(moduleName)
        try:
            module = self.Import(moduleName)
        except (Exception, SystemExit) as e:
            result = 'Import module error: {} ,{}: {}'.format(moduleName, type(e), e)
        else:
            self.unplug(moduleName, removeJob=False)

            names = []
            for slotName in self.slots_table.keys():
                if hasattr(module, slotName):
                    self.slots_table[slotName].append([getattr(module, slotName),module])
                    #cls.slots_table[slotName].append(getattr(module, slotName))
                    names.append(slotName)

            if (not names):
                result = 'warning: invalid module {} '.format(moduleName)
            else:
                self.plugins.add(moduleName)
                if hasattr(module, 'on_plug'):
                    module.on_plug(self._stub)
                result = 'plug succ: {}'.format(moduleName)
        return result
    
    @classmethod
    def Plugins(cls):
        return list(cls.plugins)

    @classmethod
    def wrap(cls, slots):
        return lambda *a,**kw: [f[0](*a, **kw) for f in slots[:]]

    def byteify(self, input):
        if isinstance(input, dict):
            return {self.byteify(key):self.byteify(value) for key,value in input.iteritems()}
        elif isinstance(input, list):
            return [self.byteify(element) for element in input]
        elif isinstance(input, unicode):
            return input.encode('utf-8')
        else:
            return input

    def append_slot(self, slot_name):
        if not self.slots_table.has_key(slot_name):
            self.slots_table[slot_name] = []
        setattr(self, slot_name, self.wrap(self.slots_table[slot_name]))

    def session_remove(self, k, v):
        if self.session_data.has_key(k):
            del self.session_data[k]
            self.save_dict(self.session_file, self.session_data)

    def session_set(self, k, v):
        if self.session_data.has_key(k):
            _v = self.session_data[k]
            if v == _v:
                return
        self.session_data[k] = v
        self.save_dict(self.session_file, self.session_data)

    def session_get(self, k):
        if self.session_data.has_key(k):
            return self.session_data[k]
        return None

    def load_dict(self, data_file):
        _data = {}
        if os.path.isfile(data_file):
            with open(data_file, "r") as f:
                _data = self.byteify(json.load(f, encoding='utf-8'))
        return _data
    def save_dict(self, fn, jdata):
        json_string = json.dumps(jdata, ensure_ascii=False)
        with open(fn, "w") as f:
            f.write(json_string)

StubFunc = slots.AddStubFunc