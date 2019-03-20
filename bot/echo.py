# coding: utf-8
import json
import sys
sys.path.append('../')
import os, io
import random
import re
import time
import requests
import urllib
import base64

import struct 
import traceback

from datetime import datetime,timedelta
import threading

import subprocess


def get_at_txt(c, at_list):
    for ati in at_list:
        if c == ati['uin']:
            return ati['txt']
    return None

def on_bot_message(_stub, qqmsg):
    global tmp_session
    if qqmsg.qq == _stub.qqcode:
        _stub.log('from self')
        return
    if qqmsg.type == 'group.chat' and qqmsg.qq in []:
        pass
    else:
        pass
    if qqmsg.content.startswith('pic '):
        echo = '[pic '+qqmsg.content.replace('pic ','')+']'
        _stub.send_group_msg(qqmsg.groupcode, _stub.qqcode, -1, echo)
    else:
        _stub.send_group_msg(qqmsg.groupcode, _stub.qqcode, -1, "haha")

def on_plug(_stub):
    print ('{} on_plug {}'.format(__name__,_stub))

def on_unplug(_stub):
    print ('{} on_unplug'.format(__name__))
