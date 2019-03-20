# -*- coding:utf-8 -*-
import sys

reload(sys)
sys.setdefaultencoding('utf-8')
from pyDes import *
from binascii import b2a_hex, a2b_hex, hexlify, unhexlify
import traceback
import math
import time
from Tools import Coder
from Tools import HexPacket
from Tools import MD5
import json
import requests
import random
from ctypes import *

from urllib import quote, unquote

try:
    ppt_dll = None
except Exception,e:
    ppt_dll = None
    pass

class qq_wallet:
    def __init__(self):
        self.stub = self
        self.msg_count = 1
        self.bcd_table = '0123456789ABCDEF'
        self.keys = ""
        self.keys = self.keys.replace('\r','').replace('\n','').replace(' ','')
        self.keys = Coder.hexstr2str(Coder.trim(self.keys))

    def log(self, info_str):
        print info_str

    def set_stub(self, _stub):
        if _stub is None:
            self.stub = self
        else:
            self.stub = _stub

    def money_format(self, value):
        # value = "%.2f" % float(value)
        if value.replace('.','').isdigit():
            value = '%.2f' % round(float(value)/100, 2)
            components = str(value).split('.')
            if len(components) > 1:
                left, right = components
                right = '.' + right
            else:
                left, right = components[0], ''

            result = ''
            while left:
                result = left[-3:] + ',' + result
                left = left[:-3]
            return result.strip(',') + right
        else:
            return 'x.xx'

    def bcd_encode(self, src):
        _dst = ''
        for i in range(len(src)):
            _code = src[i]
            _dst = _dst + self.bcd_table[ord(_code)>>4] + self.bcd_table[ord(_code)&0x0f]
        return _dst

    def bcd_decode(self, src):
        if len(src)%2 <> 0:
            return None
        src.upper()
        _dst = ''
        for i in range(len(src)/2):
            bcd_h = self.bcd_table.find(src[i+i])
            bcd_l = self.bcd_table.find(src[i+i+1])
            #print bcd_h , bcd_l,chr(bcd_h<<4|bcd_l)
            if bcd_h == -1 or bcd_l == -1:
                return None
            _dst = _dst + chr(bcd_h<<4|bcd_l)
        return _dst

    def redp_encode(self, key, redp):
        random_s = key
        kpos = random_s*8
        KEY = self.keys[kpos:kpos+8]
        k = des(KEY, ECB, padmode=None)

        data_len = len(redp)
        if data_len%8 <> 0:
            _redp = redp + ''.ljust(8-(data_len%8), '\0')
        else:
            _redp = redp
        data_len = len(_redp)/8
        data_enc = ''
        for i in range(data_len):
            data_enc = data_enc + k.encrypt(_redp[i*8:i*8+8])
        data_enc = self.bcd_encode(data_enc)
        return data_enc

    def redp_decode(self, key, redp):
        random_s = key
        kpos = random_s*8
        KEY = self.keys[kpos:kpos+8]
        k = des(KEY, ECB, padmode=None)

        data_enc = self.bcd_decode(redp)
        data_dec = ''
        for i in range(len(data_enc)/8):
            data_dec = data_dec + k.decrypt(data_enc[i*8:i*8+8])
        return data_dec
    
    def generate_msg_no(self, uin):
        msg_no = uin + time.strftime('%Y%m%d%H%M%S',time.localtime(time.time()))
        str_count = str(self.msg_count)
        self.msg_count += 1
        if len(str_count) > 3:
            str_count = str_count[len(str_count)-3:]
        msg_no += ''.ljust(28-len(msg_no)-len(str_count), '0')
        msg_no += str_count
        return msg_no

    def redpacket_gen_url(self, session, redpacket):
        random_s = random.randint(0,15)
        req_url = ""

        return random_s, req_url

    def redpacket_decode_result(self, k, pick_result):
        return self.redp_decode(k, pick_result)

    def try_to_decrypt(self, k, secret):
        if k == -1:
            for k in range(15):
                plain = self.redp_decode(k, secret)
                print k, plain.decode('utf8')
        else:
            plain = self.redp_decode(k, secret)
            print k, plain.decode('utf8')

    def wallet_transfer(self, qq_session, payer_uin, payee_uin, trans_fee, trans_memo):
        return ""

