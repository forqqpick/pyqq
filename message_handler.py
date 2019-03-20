# coding: utf-8
import json
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

sys.path.append('./pb')
import os, io
import random
from random import randint
import re
import time
import hashlib

import zlib

import base64

import imghdr
import os.path 
import threading

import socket
import struct

import datetime

import platform

import traceback

from datetime import timedelta

from PIL import Image
import json
import requests
import urllib

from Tools import Coder
from Tools import HexPacket

from msg_onlinepush_pb2 import msg_onlinepush
from msg_svc_pb2 import msg_svc
from syncookie_pb2 import SynCookie

from cmd0x388_pb2 import cmd0x388
from cmd0x352_pb2 import cmd0x352
from CSDataHighwayHead_pb2 import CSDataHighwayHead
from im_msg_body_pb2 import im_msg_body

from qqwalletaio_resv_pb2 import qqwalletaio_resv
from hummer_resv_generalflags_pb2 import generalflags
from ptt_reserve_pb2 import ptt_reserve


from slots import StubFunc as qqterm_stub_func

from jcemessages import *

from bots import Bots

from facemap import faceMapStr


import qq_wallet


global grouplist
grouplist = {}

global groupmemberlist
groupmemberlist = {}

media_upload_tasks = []

global bots
bots = None


global bot_msg_lock
bot_msg_lock = threading.Lock()

class dyobj(object):
    def __init__(self, plist):
        #lambda self,plist: self.__setattr__(_name,None) for _name in plist
        for _name in plist.split(' '):
            self.__setattr__(_name,None)

def file_extension(path): 
    _r = ''
    try:
        _r = os.path.splitext(path)[1]
    except Exception, e:
        pass
    return _r

def md5hex(word):  
    """ MD5加密算法，返回32位小写16进制符号 """  
    if isinstance(word, unicode):  
        word = word.encode("utf-8")  
    elif not isinstance(word, str):  
        word = str(word)  
    m = hashlib.md5()  
    m.update(word)  
    return m.hexdigest()  
  
  
def md5sum(fname):  
    def read_chunks(fh):  
        fh.seek(0)  
        chunk = fh.read(8096)  
        while chunk:  
            yield chunk  
            chunk = fh.read(8096)  
        else:
            fh.seek(0)  
    m = hashlib.md5()  
    if isinstance(fname, basestring) and os.path.exists(fname):  
        with open(fname, "rb") as fh:  
            for chunk in read_chunks(fh):  
                m.update(chunk)  
    elif fname.__class__.__name__ in ["StringIO", "StringO"] or isinstance(fname, file):  
        for chunk in read_chunks(fname):  
            m.update(chunk)  
    else:  
        return ""  
    return m.hexdigest()  

def detect_endian(_debug=False):
    _ret = ''
    _str = struct.pack('@h',15)
    _str = _str.encode('hex')
    if _str == '0f00':
        _ret = '<'
    else:
        _ret = '>'
    if _debug:
        print _str
        print _ret
    return _ret

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 0))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

global local_ip
local_ip = get_ip()

global qq_stub
qq_stub = None

global wallet
wallet = qq_wallet.qq_wallet()

global parameters
parameters = {}

global qq_session
qq_session = dyobj("web_user_agent qq_guid appid package_name mobile_model mobile_imei os_type os_version os_sdk qq_version qq_skey qq_pskey qq_online")

global c2c_ptt_seq
c2c_ptt_seq = 0

class OptStub(object):
    def __init__(self):
        global grouplist
        global qq_session
        self.qqcode = None
        self.qq_groups = grouplist
        self.qq_session = qq_session

    def byteify(self, input):
        if isinstance(input, dict):
            return {self.byteify(key):self.byteify(value) for key,value in input.iteritems()}
        elif isinstance(input, list):
            return [self.byteify(element) for element in input]
        elif isinstance(input, unicode):
            return input.encode('utf-8')
        else:
            return input

    def load_data(self, data_file):
        _data = {}
        if os.path.isfile(data_file):
            with open(data_file, "r") as f:
                _data = self.byteify(json.load(f, encoding='utf-8'))
        return _data

    def save_data(self, fn, jdata):
        json_string = json.dumps(jdata, ensure_ascii=False)
        #INFO(json_string) 
        with open(fn, "w") as f:
            f.write(json_string)
        #("%s data file saved.", fn)

    def send_group_msg(self, group_code, from_code, to_code, content):
        if qq_stub and qq_stub.online:
            try:
                send_mixmsg(qq_stub, group_code, -1, from_code, to_code, content)
            except Exception,e:
                qq_stub.log(traceback.format_exc())
        pass
    def qq_redpacket_pick(self, group_code, from_code, to_code, content, extra_channel=None):
        if qq_stub and qq_stub.online:
            redpacket_pick(qq_stub, group_code, -1, from_code, to_code, content, extra_channel)
        pass
    def qq_online_status(self, group_code, from_code, to_code, content):
        if qq_stub and qq_stub.online:
            send_online_status(qq_stub, group_code, -1, from_code, to_code, content)
        pass
    def set_parameter(self, k, v):
        if v is None:
            if k in parameters:
                del parameters[k]
        else:
            parameters[k] = v
        pass
    def get_parameter(self, k):
        return parameters.get(k)
        pass
    def log(self, content):
        if qq_stub:
            qq_stub.log(content)
        pass

opt_stub = OptStub()

def on_server_message(_stub, _cmd, _body):
    global qq_session
    global qq_stub
    global bots
    if _cmd == '-=init=-':
        _stub.log('on_server_message ' + _cmd)
        qq_stub = _stub
        wallet.set_stub(_stub)
        bots = None
        bots = Bots(opt_stub)
        opt_stub.qqcode = _stub.qqcode
        qq_session.on_line = 0
        qq_session.package_name = Coder.hexstr2str(_stub.package_name)
        qq_session.mobile_model = _stub.mobile_model 
        qq_session.mobile_imei = Coder.hexstr2str(_stub.imei)
        qq_session.os_type = Coder.hexstr2str(_stub.os_type) #'android'
        qq_session.os_version = Coder.hexstr2str(_stub.os_version) #'5.1.1'
        qq_session.os_sdk = Coder.hexstr2str(_stub.os_sdk) #'sdk22'
        qq_session.qq_version = _stub.qqversion #
        qq_session.qq_guid = _stub.qq_guid #
        qq_session.qqw_libversion = _stub.qqw_libversion #
        qq_session.appid = Coder.hexstr2num(_stub.appId) #
        qq_session.web_user_agent = _stub.web_user_agent #
        return
    if _cmd == '-=online=-':
        _stub.log('-=online=-')
        qq_session.qq_online = 1 
        qq_session.qq_skey = Coder.hexstr2str(qq_stub.skey)
        qq_session.qq_pskey = Coder.hexstr2str(qq_stub.pskey)   #
        send_get_group_list(qq_stub)
        return
    if _cmd == '-=offline=-':
        _stub.log('-=offline=-')
        qq_session.qq_online = 0 
        return

    bytes = Coder.hexstr2str(_body)
    if _cmd == _stub.qq_cmd_onlinepush_pbpushgroupmsg:
        try:
            HexPacket(_body).dump(0)
            #parse_pbpushgroupmsg(_stub, _cmd, bytes[4:len(bytes)-11])
            parse_pbpushgroupmsg(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_messagesvc_pushnotify:
        try:
            HexPacket(_body).dump(0)
            parse_pbpushnotify(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_messagesvc_pbgetmsg:
        try:
            HexPacket(_body).dump(0)
            parse_pbgetmsg(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_friendlist_gettrooplistreqv2:
        try:
            HexPacket(_body).dump(0)
            parse_gettrooplist(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_friendlist_gettroopmemberlist:
        try:
            HexPacket(_body).dump(0)
            parse_getgroupmemberlist(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_longconn_offpicup:
        try:
            HexPacket(_body).dump(0)
            parse_pblongconnoffpicup(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_imgstore_grouppicup:
        try:
            HexPacket(_body).dump(0)
            parse_pbimgstoregrouppicup(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_pttstore_grouppttup:
        try:
            HexPacket(_body).dump(0)
            parse_pbpttstoregrouppttup(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_pttcentersvr_pb_pttcenter_CMD_REQ_APPLY_UPLOAD_500:
        try:
            HexPacket(_body).dump(0)
            parse_pbpttcentersvrcmdreqapplyupload500(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    elif _cmd == _stub.qq_cmd_qqwalletvoicepack_macthvoice:
        try:
            HexPacket(_body).dump(0)
            parse_qqwalletvoicepack_macthvoice(_stub, _cmd, bytes[4:])
        except Exception,e:
            _stub.log(traceback.format_exc())
            #HexPacket(_body).dump(0)
        pass
    else:
        _stub.log('unhandled svr cmd: ' + _cmd)
        HexPacket(_body).dump(0)
        pass

global msg_seq
msg_seq = 1
def get_msg_seq():
    global msg_seq
    msg_seq += 1
    if msg_seq > 65535:
        msg_seq = 1
    return msg_seq

def get_group_code_by_uin(_stub, uin):
    for k,v in grouplist.items():
        if v['uin'] == uin:
            return k
    return uin

def fire_on_bot_message(_stub, qqmsg):
    global bot_msg_lock
    bot_msg_lock.acquire()
    try:
        bots.on_bot_message(_stub, qqmsg)
    except Exception, e:
        _stub.log(traceback.format_exc())
    finally:
        bot_msg_lock.release()

def parse_c2cpbmsg(_stub, pbmsg):
    global opt_stub
    if pbmsg.msg_head.msg_type == 33:       #new comer join group
        qqmsg = dyobj("type qq isowner isadmin card groupcode groupname at content")
        qqmsg.type = 'group.member.add'
        qqmsg.groupcode = get_group_code_by_uin(_stub,pbmsg.msg_head.from_uin)
        qqmsg.groupname = ''
        qqmsg.qq = pbmsg.msg_head.auth_uin
        #qqmsg.isowner = int(sender.get('isowner'))
        #qqmsg.isadmin = int(sender.get('isadmin'))
        qqmsg.card = pbmsg.msg_head.auth_nick
        qqmsg.content = ''

        fire_on_bot_message(opt_stub, qqmsg)
        return

    info_str = "{}@{} sender:{}&{} -> ".format( \
                pbmsg.msg_head.msg_type, \
                pbmsg.msg_head.c2c_cmd, \
                pbmsg.msg_head.from_uin, \
                '-=stranger=-')

    _info_str = ""

    if pbmsg.msg_head.msg_type == 529:      #c2c voice
        tmpPtt = im_msg_body.TmpPtt()
        tmpPtt.ParseFromString(pbmsg.msg_body.msg_content)
        logger.info(tmpPtt)
        return

    for elem in pbmsg.msg_body.rich_text.elems:
        if len(elem.text.str) > 0:
            _info_str += "" + elem.text.str
            if len(elem.text.attr_6_buf) > 0:
                #0001000000140089ff95db0000
                #uin = Coder.hexstr2num(Coder.str2hexstr(elem.text.attr_6_buf[6:-2]))
                uin = Coder.hexstr2num(Coder.str2hexstr(elem.text.attr_6_buf[7:-2]))
                atl.append({"uin":uin,"txt":elem.text.str})
            continue
        if len(elem.custom_face.str_file_path) > 0:
            _info_str += "" + elem.custom_face.str_file_path
            continue
        if len(elem.not_online_image.file_path) > 0:
            _info_str += "" + elem.not_online_image.file_path
            continue
        if len(elem.extra_info.bytes_nick) > 0:
            info_str = info_str.replace('-=stranger=-', elem.extra_info.bytes_nick)
            continue
        if elem.face.index > 0:
            #_info_str += "[fid " + hex(elem.face.index).replace('0x','')+"]"
            _info_str += "[fid " + str(elem.face.index)+"]"
            continue


    _stub.log("parse_c2cpbmsg:[-1]")
    _stub.log(info_str+_info_str)
    group_code = pbmsg.msg_head.c2c_tmp_msg_head.group_code
    group_uin = pbmsg.msg_head.c2c_tmp_msg_head.group_uin
    if group_code == 0:
        group_code = None
    _stub.log("parse_c2cpbmsg:[0]")
    try:
        op = []
        if pbmsg.msg_head.from_uin not in op:
            return

        content = _info_str
        if content.startswith("!bot"):
            match = re.search(r'!bot ([^ ]+)(.*)?', content)
            if match:
                _cmd = match.group(1)
                _param = match.group(2)
                qqmsg = dyobj("type qq isowner isadmin card groupcode groupname at content")
                qqmsg.qq = -1
                if _cmd == "plug":
                    try:
                        result = bots.Plug(_param.strip())
                        qqmsg.type = 'system.plug'
                    except Exception , e:
                        _stub.log(traceback.format_exc())
                        result = str(e)
                        qqmsg = None
                    _stub.log("parse_c2cpbmsg:[1] group_code:{} group_uin:{} _stub.qqcode:{} from_uin:{}".format(group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin))
                    send_mixmsg(_stub, group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin, result)
                    if qqmsg is not None:
                        #fire_on_bot_message(opt_stub, qqmsg)
                        pass
                elif _cmd == "unplug":
                    try:
                        qqmsg.type = 'system.unplug'
                        #fire_on_bot_message(opt_stub, qqmsg)
                        result = bots.Unplug(_param.strip())
                    except Exception,e:
                        _stub.log(traceback.format_exc())
                        qqmsg = None
                    _stub.log("parse_c2cpbmsg:[2] group_code:{} group_uin:{} _stub.qqcode:{} from_uin:{}".format(group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin))
                    send_mixmsg(_stub, group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin, result)
            else:
                _stub.log("parse_c2cpbmsg:[3]")
                send_online_status(_stub, group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin, '')
        elif content.startswith("!p_"):
            match = re.search(r'!p_(?:set|del) ([^ ]+)(.*)?', content)
            if match:
                _k = match.group(1).strip()
                _v = match.group(2).strip()
                ret = ''
                if content.startswith("!p_set"):
                    ret = "set key&value: {}&{}".format(_k,_v)
                    _stub.log(ret)
                    parameters[_k] = _v
                else:
                    _k = match.group(1).strip()
                    ret = "remove key:{}".format(_k)
                    _stub.log("remove key:{}".format(_k))
                    del parameters[_k]
                _stub.log("parameters:{}".format(parameters))
                send_mixmsg(_stub, group_code, group_uin, _stub.qqcode, pbmsg.msg_head.from_uin, ret)
            pass
        else:
            _stub.log("parse_c2cpbmsg:[{}]".format(content))
            pass
    except Exception as e:
        _stub.log(traceback.format_exc())
        pass


def parse_gettrooplist(_stub, _cmd, bytes):
    global grouplist
    _stub.log("parse_gettrooplist start ...")
    if len(bytes) >= 2:
        ziptag = bytes[:2]
        if ord(ziptag[0]) == 0x78 and ord(ziptag[1]) == 0xda:
            bytes = zlib.decompressobj().decompress(bytes)

    _jce_req = jce_RequestPacket.loads(bytes)
    _jce_map = jce_Map.loads(_jce_req.buffer)

    for k, v in _jce_map['map'].items():
        if k == 'GetTroopListRespV2':
            try:
                _v = jce_GetTroopListRespV2Wrap.loads(v)
            except Exception,e:
                try:
                    _v = jce_GetTroopListRespV2Wrap_V1.loads(v)
                except Exception,e:
                    _v = None
                    pass
        tl = {}
        if _v is not None:
            tl = _v.TroopListRespV2.vecTroopList
        _gl = {}
        for tp in tl:
            _gl[tp.troop.code] = {'code':tp.troop.code, 'uin':tp.troop.uin, 'name':tp.troop.name}
            #_stub.log("uin:{}   code:{}   name:{}".format(str(tp.troop.uin).rjust(11),str(tp.troop.code).rjust(11),tp.troop.name.decode('utf8')))
        _stub.log("{}".format(_gl))
        grouplist = _gl
        opt_stub.qq_groups = _gl
    _stub.log("parse_gettrooplist end ...")

@qqterm_stub_func
def send_get_group_list(_stub):
    jce_getgrouplist = jce_GetGroupList()
    jce_getgrouplist.qq = long(_stub.qqnum)
    jce_getgrouplist.hb1 = 0
    jce_getgrouplist.hb4 = 1
    jce_getgrouplist.hb5 = 5
    
    msg = _stub.pack_request_data( 3, _stub.seq, 'mqq.IMService.FriendListServiceServantObj', 'GetTroopListReqV2', 'GetTroopListReqV2', jce_getgrouplist.dumps())

    packet = _stub.assemble_request_package(_stub.qq_cmd_friendlist_gettrooplistreqv2, msg)
    _stub.log('send get_grouplist ({})'.format(_stub.qq_cmd_friendlist_gettrooplistreqv2))
    _stub.send_package(Coder.hexstr2str(packet))


def parse_getgroupmemberlist(_stub, _cmd, bytes):
    global groupmemberlist
    if len(bytes) >= 2:
        ziptag = bytes[:2]
        if ord(ziptag[0]) == 0x78 and ord(ziptag[1]) == 0xda:
            bytes = zlib.decompressobj().decompress(bytes)
    _jce_req = jce_RequestPacket.loads(bytes)
    _jce_map = jce_Map.loads(_jce_req.buffer)
    for k, v in _jce_map['map'].items():
        if k == 'GTMLRESP':
            _v = jce_GetTroopMemberListRespWrap.loads(v)

            tml = _v.GTMLRESP.vecTroopMember
            for tm in tml:
                groupmemberlist[tm.member.memberuin] = {'memberuin': tm.member.memberuin, 'faceid': tm.member.faceid, 'age': tm.member.age, 'gender': tm.member.gender, 'nick': tm.member.nick, 'status': tm.member.status, 'showname': tm.member.showname, 'name': tm.member.name, 'cgender': tm.member.cgender, 'phone': tm.member.phone, 'email': tm.member.email, 'memo': tm.member.memo, 'autoremark': tm.member.autoremark, 'memberlevel': tm.member.memberlevel, 'jointime': tm.member.jointime, 'lastspeaktime': tm.member.lastspeaktime, 'creditlevel': tm.member.creditlevel, 'flag': tm.member.flag, 'flagext': tm.member.flagext, 'point': tm.member.point, 'concerned': tm.member.concerned, 'shielded': tm.member.shielded, 'specialtitle': tm.member.specialtitle, 'specialtitleexpiretime': tm.member.specialtitleexpiretime, 'bytes_job': tm.member.bytes_job, '_26': tm.member._26, '_27': tm.member._27, '_28': tm.member._28, '_29': tm.member._29, '_30': tm.member._30, '_31': tm.member._31 }
                _stub.log("uin:{}   name:{}   nick:{}    showname:{}".format(str(tm.member.memberuin).rjust(11),tm.member.name,tm.member.nick, tm.member.showname))
            _stub.log('total members:{}'.format(len(groupmemberlist)))
            if _v.GTMLRESP.nextuin == 0:
                save_dict('{}.members.txt'.format(_v.GTMLRESP.groupcode), groupmemberlist)
                pass
            else:
                send_get_groupmember_list(_stub, _v.GTMLRESP.groupcode, _v.GTMLRESP.nextuin)
                pass

@qqterm_stub_func
def send_get_groupmember_list(_stub, groupcode, nextuin = 0):
    global grouplist
    if groupcode in grouplist:
        jce_getgroupmemberlist = jce_GetGroupMemberList()
        jce_getgroupmemberlist.uin = long(_stub.qqnum)
        jce_getgroupmemberlist.groupcode = groupcode
        jce_getgroupmemberlist.groupuin = grouplist[groupcode]['uin']
        jce_getgroupmemberlist.nextuin = nextuin
        jce_getgroupmemberlist.version = 2
        
        msg = _stub.pack_request_data( 3, _stub.seq, 'mqq.IMService.FriendListServiceServantObj', 'GetTroopMemberListReq', 'GTML', jce_getgroupmemberlist.dumps())

        packet = _stub.assemble_request_package(_stub.qq_cmd_friendlist_gettroopmemberlist, msg)
        _stub.log('send get_groupmember_list ({})'.format(_stub.qq_cmd_friendlist_gettroopmemberlist))
        _stub.send_package(Coder.hexstr2str(packet))


global synCookie
synCookie = None

def parse_pbpushnotify(_stub, _cmd, bytes):
    global synCookie
    _pbGetMsgReq = msg_svc.PbGetMsgReq()
    _pbGetMsgReq.sync_flag = 0
    if not synCookie:
        synCookie = SynCookie()
        synCookie.tag_01 = long(time.time())
        synCookie.tag_02 = synCookie.tag_01
        synCookie.tag_03 = 870427716
        synCookie.tag_04 = 1116489573
        synCookie.tag_05 = 3296982026
        synCookie.tag_09 = 512030200
        synCookie.tag_11 = 1657375545
        synCookie.tag_13 = synCookie.tag_01
        synCookie.tag_14 = 0

        cc = _stub.session_get('Cookie.counter')
        if cc:
            synCookie.tag_12 = int(cc)
        else:
            synCookie.tag_12 = 62
        _stub.session_set('Cookie.counter' , str(synCookie.tag_12 + 1))
        _pbGetMsgReq.sync_cookie = synCookie.SerializeToString()
    else:
        sync_cookie = _stub.session_get('PbGetMsg.sync_cookie')
        if sync_cookie:
            _pbGetMsgReq.sync_cookie = Coder.hexstr2str(sync_cookie)
        else:
            _pbGetMsgReq.sync_cookie = Coder.hexstr2str("08d8bcf0ca0510d8bcf0ca0518cf9fe7a10920fecd8ef704288af888cd01489f85b4a002589ad0cf8d06603c68d8bcf0ca057000")


    _pbGetMsgReq.ramble_flag = 0
    _pbGetMsgReq.latest_ramble_number = 20
    _pbGetMsgReq.other_ramble_number = 3
    _pbGetMsgReq.online_sync_flag = 1
    _pbGetMsgReq.context_flag = 1
    _pbGetMsgReq.msg_req_type = 0

    _msg = Coder.str2hexstr(_pbGetMsgReq.SerializeToString());
    packet = _stub.assemble_request_package(_stub.qq_cmd_messagesvc_pbgetmsg, _msg)
    _stub.log('send qq_cmd_messagesvc_pbgetmsg ({})'.format(_stub.qq_cmd_messagesvc_pbgetmsg))
    _stub.send_package(Coder.hexstr2str(packet))


def parse_pbpushgroupmsg(_stub, _cmd, bytes):
    global opt_stub
    pbPushMsg = msg_onlinepush.PbPushMsg()
    pbPushMsg.ParseFromString(bytes)

    info_str = "{}@{} sender:{}&{} -> ".format( \
                pbPushMsg.msg.msg_head.msg_type, \
                pbPushMsg.msg.msg_head.group_info.group_code, \
                pbPushMsg.msg.msg_head.from_uin, \
                pbPushMsg.msg.msg_head.group_info.group_card)
    atl = []

    _info_str = ""
    for elem in pbPushMsg.msg.msg_body.rich_text.elems:
        if len(elem.text.str) > 0:
            _info_str += "" + elem.text.str
            if len(elem.text.attr_6_buf) > 0:
                #uin = Coder.hexstr2num(Coder.str2hexstr(elem.text.attr_6_buf[6:-2]))
                uin = Coder.hexstr2num(Coder.str2hexstr(elem.text.attr_6_buf[7:-2]))
                atl.append({"uin":uin,"txt":elem.text.str})
            continue
        if len(elem.custom_face.str_file_path) > 0:
            if isinstance(elem.custom_face.str_file_path, (unicode)):
                _fpath = elem.custom_face.str_file_path.encode('utf8')
            else:
                _fpath = elem.custom_face.str_file_path
            _info_str += "" + _fpath
            continue
        if len(elem.extra_info.bytes_group_card) > 0:
            #logger.info(elem.extra_info.bytes_sender_title)
            continue
        if elem.face.index > 0:
            #_info_str += "[fid " + hex(elem.face.index).replace('0x','')+"]"
            _info_str += "[fid " + str(elem.face.index)+"]"
            continue
        if len(elem.rich_msg.bytes_template_1) > 0:
            if elem.rich_msg.uint32_service_id == 90:
                r = re.search('brief="([^"]+)"',elem.rich_msg.bytes_template_1)
                if r:
                    _info_str += ""+r.group(1)
                r = re.search('<summary>([^<]+)',elem.rich_msg.bytes_template_1)
                if r:
                    _info_str += " location:"+r.group(1)
            continue
        if elem.qqwallet_msg.aio_body.sint32_channelid <> 0:
            _info_str = dyobj("type redtype redpacketid authkey title subtitle msgtype sessiontype redpacketindex redchannel group_type sender_uin")
            _info_str.type = 'redpacket'
            _info_str.redtype = elem.qqwallet_msg.aio_body.sint32_redtype
            _info_str.redpacketid = elem.qqwallet_msg.aio_body.bytes_billno
            _info_str.authkey = elem.qqwallet_msg.aio_body.bytes_authkey
            _info_str.title = elem.qqwallet_msg.aio_body.receiver.bytes_title
            _info_str.subtitle = elem.qqwallet_msg.aio_body.receiver.bytes_subtitle
            _info_str.msgtype = elem.qqwallet_msg.aio_body.sint32_msgtype
            _info_str.sessiontype = elem.qqwallet_msg.aio_body.sint32_sessiontype
            _info_str.redpacketindex = elem.qqwallet_msg.aio_body.string_index
            _info_str.redchannel = elem.qqwallet_msg.aio_body.uint32_redchannel
            _info_str.group_type = 1
            _info_str.sender_uin = pbPushMsg.msg.msg_head.from_uin
            continue
    qqmsg = dyobj("type qq isowner isadmin card groupcode groupname at content")
    qqmsg.type = 'group.chat'
    qqmsg.groupcode = pbPushMsg.msg.msg_head.group_info.group_code
    qqmsg.groupname = pbPushMsg.msg.msg_head.group_info.group_name
    qqmsg.qq = pbPushMsg.msg.msg_head.from_uin
    #qqmsg.isowner = int(sender.get('isowner'))
    #qqmsg.isadmin = int(sender.get('isadmin'))
    qqmsg.card = pbPushMsg.msg.msg_head.group_info.group_card
    qqmsg.at = atl
    qqmsg.content = _info_str

    fire_on_bot_message(opt_stub, qqmsg)


def parse_pbgetmsg(_stub, _cmd, bytes):
    if len(bytes) >= 2:
        ziptag = bytes[:2]
        if ord(ziptag[0]) == 0x78 and ord(ziptag[1]) == 0xda:
            bytes = zlib.decompressobj().decompress(bytes)
    pbGetMsgResp = msg_svc.PbGetMsgResp()
    pbGetMsgResp.ParseFromString(bytes)
    if pbGetMsgResp.result == 0 and len(pbGetMsgResp.errmsg) == 0:
        if len(pbGetMsgResp.sync_cookie) > 0:
            _stub.session_set('PbGetMsg.sync_cookie', Coder.str2hexstr(pbGetMsgResp.sync_cookie))
            for uin_pair_msg in pbGetMsgResp.uin_pair_msgs:
                for pbmsg in uin_pair_msg.msg:
                    parse_c2cpbmsg(_stub, pbmsg)

@qqterm_stub_func
def send_c2cmsg(_stub, group_code, from_code, to_code, _content):
    pbSendMsgReq = msg_svc.PbSendMsgReq()
    if group_code:
        ginfo = grouplist.get(group_code, None)
        if not ginfo:
            _stub.log('can not get corresponding group_uin for ' + group_code)
            return
        pbSendMsgReq.routing_head.grp_tmp.group_uin = ginfo['uin']
        pbSendMsgReq.routing_head.grp_tmp.to_uin = to_code
    else:
        pbSendMsgReq.routing_head.c2c.to_uin = to_code

    pbSendMsgReq.content_head.pkg_num = 1
    pbSendMsgReq.content_head.pkg_index = 0
    pbSendMsgReq.content_head.div_seq = 0

    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
    elem.text.str = _content
    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
    elem.elem_flags2.uint32_custom_font = 0
    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
    elem.general_flags.uint64_pendant_id = 0

    pbSendMsgReq.msg_seq = get_msg_seq()
    pbSendMsgReq.msg_rand = random.randint(10000, 999999999)
    pbSendMsgReq.msg_via = 0

    synCookie = SynCookie()
    synCookie.tag_01 = long(time.time())
    synCookie.tag_02 = synCookie.tag_01
    synCookie.tag_03 = 870427716
    synCookie.tag_04 = 1116489573
    synCookie.tag_05 = 3296982026
    synCookie.tag_09 = 512030200
    synCookie.tag_11 = 1657375545
    synCookie.tag_12 = 46
    synCookie.tag_13 = synCookie.tag_01
    synCookie.tag_14 = 0
    pbSendMsgReq.sync_cookie = synCookie.SerializeToString()

    _msg = Coder.str2hexstr(pbSendMsgReq.SerializeToString());

    HexPacket(_msg).dump(0)

    packet = _stub.assemble_request_package(_stub.qq_cmd_messagesvc_pbsendmsg, _msg)
    _stub.log('send qq_cmd_messagesvc_pbsendmsg ({})'.format(_stub.qq_cmd_messagesvc_pbsendmsg))
    _stub.send_package(Coder.hexstr2str(packet))

######################################################################################################
@qqterm_stub_func
def send_online_status(_stub, group_code, group_uin, from_code, to_code, content):
    delta = datetime.datetime.now() - _stub.online_time
    result = 'counter: {}'.format(_stub.start_counter)
    result += '\nduration: '
    weeks = delta.days/7
    days = delta.days-weeks*7
    hours = delta.seconds/3600
    minus = (delta.seconds - hours*3600)/60
    seconds = delta.seconds - hours*3600 - minus*60
    if weeks > 0:
        result += str(weeks) + "weeks "
    if days > 0:
        result += str(days) + "days "
    if hours > 0:
        result += str(hours) + "hours "
    if minus > 0:
        result += str(minus) + "minus "
    if seconds > 0:
        result += str(seconds) + "seconds"
    result += '\nstart: ' + _stub.start_time.strftime("%Y-%m-%d %H:%M:%S")
    result += "\n{{'{}','{}','python{}'}}".format(re.compile('-with.*').sub('',platform.platform()),platform.architecture()[0],platform.python_version())
    if len(content)>0:
        result = content + '\n' + result
    send_mixmsg(_stub, group_code, group_uin, from_code, to_code, result)

@qqterm_stub_func
def send_mixmsg(_stub, group_code, group_uin, from_code, to_code, content, extra_channel = None):
    global media_upload_tasks
    _content = content
    _task = dyobj("group_code group_uin from_code to_code content uplist taskseq ")
    _task.group_code = group_code
    _task.group_uin = group_uin
    _task.from_code = from_code
    _task.to_code = to_code
    _task.content = _content
    _task.uplist = []
    _task.taskseq = []
    medias = re.findall('(\[(pic|voice) ([^\]]+)\])', _content)
    if medias:
        for media in medias:
            md5 = ''
            if cmp(media[1],'pic') == 0:
                fpath = 'pic/'+media[2]
                imgtype = imghdr.what(fpath)
                if imgtype in ('jpeg', 'gif', 'png'):
                    md5 = md5sum(fpath)
                    width,height = Image.open(fpath).size
                    _td = {'type':imgtype,'name':md5.upper()+file_extension(media[2]), 'rawname':media[2], 'path':fpath, 'md5':md5, 'type':imgtype, 'width':width, 'height':height, 'size':os.path.getsize(fpath) , 'status':'', 'up_succ':0 , 'extra_channel':extra_channel}
                else:
                    _task.content = _task.content.replace(media[0], '')
            elif cmp(media[1],'voice') == 0:
                voice_len = 5
                fpath = 'voice/'+media[2]
                mat = re.search(r"^(\d+) (.+)",media[2].strip())
                if mat <> None and len(mat.groups())==2:
                    voice_len = int(mat.group(1))
                    fpath = 'voice/'+mat.group(2)
                else:
                    ts = 5
                    if ts == -1:
                        pass
                    if ts > 0:
                        voice_len = int(ts + 0.5)
                md5 = md5sum(fpath)
                _td = {'type':'voice','name':md5.upper()+file_extension(media[2]), 'rawname':media[2], 'path':fpath, 'md5':md5, 'type':'voice', 'len':voice_len, 'size':os.path.getsize(fpath) , 'status':'', 'up_succ':0, 'extra_channel':extra_channel}
                pass
            for upd in _task.uplist:
                if upd['md5'] == md5:
                    md5 = ''
                    if upd['rawname'] != media[2]:
                        _task.content = _task.content.replace(media[0], '[{} {}]'.format(media[1], upd['rawname']))
                    break
            if len(md5) > 0:
                _task.uplist.append(_td)
        if len(_task.uplist) > 0:
            media_upload_tasks.append(_task)
            start_upload_task(_stub, media_upload_tasks.index(_task))
    else:
        send_mixmsg_from_task(_stub, _task)
    #print media_upload_tasks
    pass

def send_mixmsg_from_task(_stub, task):
    redpacket_type = -1

    pbSendMsgReq = msg_svc.PbSendMsgReq()
    group_code = task.group_code
    if group_code and group_code != -1:
        if task.to_code == -1:
            pbSendMsgReq.routing_head.grp.group_code = group_code
        else:
            if task.group_uin and task.group_uin != -1:
                pbSendMsgReq.routing_head.grp_tmp.group_uin = task.group_uin
            else:
                ginfo = grouplist.get(group_code, None)
                if not ginfo:
                    _stub.log('can not get corresponding group_uin for ' + group_code)
                    return
                pbSendMsgReq.routing_head.grp_tmp.group_uin = ginfo['uin']
            pbSendMsgReq.routing_head.grp_tmp.to_uin = task.to_code
    else:
        pbSendMsgReq.routing_head.c2c.to_uin = task.to_code

    pbSendMsgReq.content_head.pkg_num = 1
    pbSendMsgReq.content_head.pkg_index = 0
    pbSendMsgReq.content_head.div_seq = 0


    pbSendMsgReq.msg_seq = get_msg_seq()
    pbSendMsgReq.msg_rand = random.randint(10000, 999999999)
    pbSendMsgReq.msg_via = 0

    _content = task.content

    _r = '(\[(at[0-9]*|pic|fid|music|voice) ([^\]]+)\])'
    try:
        match = re.search(_r, _content)
        while match:
            _text = _content[0:match.start()]
            if len(_text) > 0:
                elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                elem.text.str = _text
                #_stub.log('['+_text+']')

            #_stub.log('match: [{}]'.format(_content[match.start():match.end()]))

            _m = _content[match.start():match.end()]
            if _m.startswith('[pic '):
                _pic = _m.replace('[pic ','').replace(']','')
                for upd in task.uplist:
                    if upd['rawname'] == _pic:
                        if upd['up_succ'] == 1:
                            elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                            if task.to_code == -1:
                                elem.custom_face.str_file_path = upd['name']
                                elem.custom_face.uint32_file_id = upd['file_id']
                                elem.custom_face.uint32_server_ip = upd['up_server_ip']
                                elem.custom_face.uint32_server_port = upd['up_server_port']
                                elem.custom_face.uint32_useful = 1
                                elem.custom_face.bytes_md5 = Coder.hexstr2str(upd['md5'])
                                elem.custom_face.biz_type = 3
                                elem.custom_face.image_type = get_pic_type(upd['type'])
                                elem.custom_face.uint32_height = upd['height']
                                elem.custom_face.uint32_width = upd['width']
                                elem.custom_face.uint32_source = 101
                                elem.custom_face.uint32_size = upd['size']
                                elem.custom_face.uint32_origin = 0
                                elem.custom_face.uint32_show_len = 0
                                elem.custom_face.uint32_download_len = 0
                            else:
                                elem.not_online_image.file_path = upd['name']
                                elem.not_online_image.file_len = upd['size']
                                elem.not_online_image.download_path = upd['up_resid']
                                elem.not_online_image.img_type = get_pic_type(upd['type'])
                                elem.not_online_image.pic_height = upd['height']
                                elem.not_online_image.pic_width = upd['width']
                                elem.not_online_image.res_id = upd['up_resid']
                                elem.not_online_image.original = 0
                                elem.not_online_image.biz_type = 3
                                elem.not_online_image.uint32_show_len = 0
                                elem.not_online_image.uint32_download_len = 0
                            pass
                        else:
                            elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                            elem.face.index = 182
                        break
            elif _m.startswith('[at'):
                 al = _m.replace('[at','').replace(']','').split(' ')
                 if len(al[0]) > 0 and task.to_code == -1:
                    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                    elem.text.str = al[1]
                    if long(al[0]) == 0: 
                        elem.text.attr_6_buf = Coder.hexstr2str('00010000' + Coder.num2hexstr(len(al[1])).rjust(4, '0') + '0100000000' + '0000')
                        pbSendMsgReq.msg_via = 1
                    else:
                        elem.text.attr_6_buf = Coder.hexstr2str('00010000' + Coder.num2hexstr(len(al[1])).rjust(4, '0') + Coder.num2hexstr(long(al[0])).rjust(10, '0') + '0000')
                 pass
            elif _m.startswith('[fid '):
                _fid = _m.replace('[fid ','').replace(']','')
                try:
                    if re.match('\d+', _fid):
                        _fid = int(_fid)
                        if _fid < 0 or _fid >212:
                            raise Exception('wrong face id')
                    else:
                        _fid = int(re.search('([0-9]+).*\|'+_fid+'\|', faceMapStr).group(1))
                    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                    elem.face.index = _fid
                except Exception,e:
                    _stub.log(traceback.format_exc())
                pass
            elif _m.startswith('[music '):
                pbSendMsgReq.content_head.pkg_num = 0
                _music = _m.replace('[music ','').replace(']','')
                _music = '\01' + zlib.compress(base64.b64decode(_music))
                #HexPacket(Coder.str2hexstr(_music)).dump(0)
                try:
                    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                    elem.rich_msg.bytes_template_1 = _music
                    elem.rich_msg.uint32_service_id = 2
                except Exception,e:
                    _stub.log(traceback.format_exc())
                pass
            elif _m.startswith('[voice '):
                _voice = _m.replace('[voice ','').replace(']','')
                for upd in task.uplist:
                    if upd['rawname'] == _voice:
                        if upd['up_succ'] == 1:
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_file_type = 4
                            pbSendMsgReq.msg_body.rich_text.ptt.bytes_file_md5 = Coder.hexstr2str(upd['md5'])
                            pbSendMsgReq.msg_body.rich_text.ptt.bytes_file_name = upd['name']
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_file_size = upd['size']
                            #pbSendMsgReq.msg_body.rich_text.ptt.bytes_reserve = ''
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_file_id = upd['file_id']
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_server_ip = upd['up_server_ip']
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_server_port = upd['up_server_port']
                            pbSendMsgReq.msg_body.rich_text.ptt.bool_valid = True
                            pbSendMsgReq.msg_body.rich_text.ptt.bytes_group_file_key = upd['file_key']
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_time = upd['len']
                            pbSendMsgReq.msg_body.rich_text.ptt.uint32_format = 1
                            pbSendMsgReq.msg_body.rich_text.ptt.bytes_pb_reserve = Coder.hexstr2str("08002800")
                            redpacket = upd['extra_channel']
                            if redpacket <> None and cmp(redpacket.type,'redpacket') == 0 and redpacket.msgtype in [13,18]:
                                redpacket_type = 13
                            if redpacket_type == 13:
                                pbSendMsgReq.msg_body.rich_text.ptt.uint64_src_uin = long(task.from_code)
                                ptt_resv = ptt_reserve.ReserveStruct()
                                ptt_resv.uint32_change_voice = 0
                                ptt_resv.uint32_redpack_type = redpacket.redtype
                                ptt_resv.bytes_redpack_score_id = 'sss'
                                pbSendMsgReq.msg_body.rich_text.ptt.bytes_pb_reserve = ptt_resv.SerializeToString()
                        else:
                            elem = pbSendMsgReq.msg_body.rich_text.elems.add()
                            elem.face.index = 182
                        break
            _content = _content[match.end():]
            match = re.search(_r, _content)
    except Exception,e:
        _stub.log(traceback.format_exc())

    if len(_content) > 0:
        elem = pbSendMsgReq.msg_body.rich_text.elems.add()
        elem.text.str = _content
        #_stub.log('['+_content+']')

    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
    if redpacket_type in [13,18]:
        elem.elem_flags2.uint32_vip_status = 0
    else:
        elem.elem_flags2.uint32_custom_font = 0
    
    elem = pbSendMsgReq.msg_body.rich_text.elems.add()
    if redpacket_type in [13,18]:
        elem.general_flags.uint64_pendant_id = 0
        generalflags_resv = generalflags.ResvAttr()
        generalflags_resv.uint32_mobile_custom_font = 0
        generalflags_resv.uint32_diy_font_timestamp = 0
        generalflags_resv.uint64_subfont_id = 0
        elem.general_flags.bytes_pb_reserve = generalflags_resv.SerializeToString()
    else:
        elem.general_flags.uint64_pendant_id = 0

    if task.to_code != -1:
        synCookie = SynCookie()
        synCookie.tag_01 = long(time.time())
        synCookie.tag_02 = synCookie.tag_01
        synCookie.tag_03 = 870427716
        synCookie.tag_04 = 1116489573
        synCookie.tag_05 = 3296982026
        synCookie.tag_09 = 512030200
        synCookie.tag_11 = 1657375545
        synCookie.tag_12 = 46
        synCookie.tag_13 = synCookie.tag_01
        synCookie.tag_14 = 0
        pbSendMsgReq.sync_cookie = synCookie.SerializeToString()

    #_stub.log(pbSendMsgReq)
    _msg = Coder.str2hexstr(pbSendMsgReq.SerializeToString())

    HexPacket(_msg).dump(0)

    packet = _stub.assemble_request_package(_stub.qq_cmd_messagesvc_pbsendmsg, _msg)
    _stub.log('send qq_cmd_messagesvc_pbsendmsg ({})'.format(_stub.qq_cmd_messagesvc_pbsendmsg))
    _stub.send_package(Coder.hexstr2str(packet))

def send_voiceredpackmatchreq_from_task(_stub, task):
    global qq_session
    group_code = task.group_code
    if group_code is None or group_code == -1:
        return
    try:
        for upd in task.uplist:
            if upd['up_succ'] == 1:
                redpacket = upd['extra_channel']
                if redpacket <> None and cmp(redpacket.type,'redpacket') == 0 and redpacket.msgtype in [13,18]:
                    _stub.log("assemble voiceredpackmatchreq title:{} md5:{}".format(redpacket.title,upd['md5']))
    except Exception,e:
        _stub.log(traceback.format_exc())

def get_pic_type(tstr):
    if tstr == 'jpeg':
        return 1000
    else:
        return 1000

def pic_upload_req(group_code, from_code, to_code, taskidx, fid, upd):
    global qq_session
    reqBody = None
    if to_code == -1:
        #upload pic in group
        reqBody = cmd0x388.ReqBody()
    else:
        #upload pic in c2c
        reqBody = cmd0x352.ReqBody()
    reqBody.uint32_subcmd = 1
    reqBody.uint32_net_type = 3
    rpt_msg_tryup_img_req = reqBody.rpt_msg_tryup_img_req.add()
    rpt_msg_tryup_img_req.uint64_src_uin = long(from_code)
    if to_code == -1:
        rpt_msg_tryup_img_req.uint64_group_code = long(group_code)
        rpt_msg_tryup_img_req.uint32_app_pic_type = get_pic_type(upd['type']) + 7
    else:
        rpt_msg_tryup_img_req.uint64_dst_uin = long(to_code)
        rpt_msg_tryup_img_req.bool_pic_original = False
        rpt_msg_tryup_img_req.bool_reject_tryfast = False
        rpt_msg_tryup_img_req.bool_address_book = False
    rpt_msg_tryup_img_req.uint64_file_id = taskidx << 8 | fid
    rpt_msg_tryup_img_req.bytes_file_md5 = Coder.hexstr2str(upd['md5'])
    rpt_msg_tryup_img_req.uint64_file_size = upd['size']
    rpt_msg_tryup_img_req.bytes_file_name = upd['name']
    rpt_msg_tryup_img_req.uint32_src_term = 5
    rpt_msg_tryup_img_req.uint32_platform_type = 9
    rpt_msg_tryup_img_req.uint32_bu_type = 1
    rpt_msg_tryup_img_req.uint32_pic_width = upd['width']
    rpt_msg_tryup_img_req.uint32_pic_height = upd['height']
    rpt_msg_tryup_img_req.uint32_pic_type = get_pic_type(upd['type'])
    rpt_msg_tryup_img_req.bytes_build_ver = "{}.500".format(qq_session.qq_version)
    rpt_msg_tryup_img_req.bytes_build_ver = qq_session.os_version
    rpt_msg_tryup_img_req.uint32_srv_upload = 0
    return reqBody

def ptt_upload_req(group_code, from_code, to_code, taskidx, fid, upd):
    global qq_session
    global c2c_ptt_seq
    reqBody = None

    return reqBody


def start_upload_task(_stub, taskidx):
    global media_upload_tasks
    upcount = 0
    task = media_upload_tasks[taskidx]
    for i in range(len(task.uplist)):
        upd = task.uplist[i]
        if upd['status'] == '':
            upcount += 1
            reqBody = None
            if cmp(upd['type'], 'voice') == 0:
                reqBody = ptt_upload_req(task.group_code, task.from_code, task.to_code, taskidx, i, upd)
                pass
            else:
                reqBody = pic_upload_req(task.group_code, task.from_code, task.to_code, taskidx, i, upd)
                pass
            if reqBody <> None:
                _msg = Coder.str2hexstr(reqBody.SerializeToString());
                send_msg = ''
                if task.to_code == -1:
                    if cmp(upd['type'], 'voice') == 0:
                        send_msg = _stub.qq_cmd_pttstore_grouppttup
                    else:
                        send_msg = _stub.qq_cmd_imgstore_grouppicup
                else:
                    if cmp(upd['type'], 'voice') == 0:
                        send_msg = _stub.qq_cmd_pttcentersvr_pb_pttcenter_CMD_REQ_APPLY_UPLOAD_500
                    else:
                        send_msg = _stub.qq_cmd_longconn_offpicup
                packet = _stub.assemble_request_package(send_msg, _msg)
                _stub.log('send ({})'.format(send_msg))
                upd['status'] = send_msg.lower()
                _stub.send_package(Coder.hexstr2str(packet))

def parse_pblongconnoffpicup(_stub, _cmd, bytes):
    global media_upload_tasks
    rspBody = cmd0x352.RspBody()
    rspBody.ParseFromString(bytes)
    for img_rsp in rspBody.rpt_msg_tryup_img_rsp:
        taskidx = img_rsp.uint64_file_id >> 8
        fileidx = img_rsp.uint64_file_id & 0xff
        task = media_upload_tasks[taskidx]
        upd = task.uplist[fileidx]
        if upd['status'] == _cmd.lower():
            upd['up_resid'] = img_rsp.bytes_up_resid
            upd['up_uuid'] = img_rsp.bytes_up_uuid
            if not img_rsp.bool_file_exit:
                upd['up_ukey'] = img_rsp.bytes_up_ukey
                upd['up_ip'] = []
                upd['up_port'] = []
                for i in range(len(img_rsp.rpt_uint32_up_ip)):
                    upd['up_ip'].append(img_rsp.rpt_uint32_up_ip[i])
                    upd['up_port'].append(img_rsp.rpt_uint32_up_port[i])
                    #print socket.inet_ntoa(struct.pack('>I',socket.htonl(num_ip)))
                upd['status'] = 'status_upload'
                upd['up_pos'] = 0
                upd['up_total'] = 0
            else:
                upd['status'] = 'status_done'
                upd['up_succ'] = 1
        else:
            upd['status'] = 'status_error'
            upd['up_succ'] = -1
        #_stub.log('taskidx:{}, fileidx:{}'.format(taskidx,fileidx))
        threading.Thread(target=pic_upload_daemon, args=(_stub, taskidx,fileidx,)).start()

def parse_pbimgstoregrouppicup(_stub, _cmd, bytes):
    global media_upload_tasks
    rspBody = cmd0x388.RspBody()
    rspBody.ParseFromString(bytes)
    try:
        for img_rsp in rspBody.rpt_msg_tryup_img_rsp:
            taskidx = img_rsp.uint64_file_id >> 8
            fileidx = img_rsp.uint64_file_id & 0xff
            task = media_upload_tasks[taskidx]
            upd = task.uplist[fileidx]
            if upd['status'] == _cmd.lower():
                upd['file_id'] = img_rsp.uint64_fileid
                if not img_rsp.bool_file_exit:
                    upd['up_ukey'] = img_rsp.bytes_up_ukey
                    upd['up_ip'] = []
                    upd['up_port'] = []
                    for i in range(len(img_rsp.rpt_uint32_up_ip)):
                        upd['up_ip'].append(img_rsp.rpt_uint32_up_ip[i])
                        upd['up_port'].append(img_rsp.rpt_uint32_up_port[i])
                        #print socket.inet_ntoa(struct.pack('>I',socket.htonl(num_ip)))
                    upd['status'] = 'status_upload'
                    upd['up_pos'] = 0
                    upd['up_total'] = 0
                else:
                    upd['up_server_ip'] = img_rsp.rpt_uint32_up_ip[0]
                    upd['up_server_port'] = img_rsp.rpt_uint32_up_port[0]
                    upd['status'] = 'status_done'
                    upd['up_succ'] = 1
            else:
                upd['status'] = 'status_error'
                upd['up_succ'] = -1
            #_stub.log('taskidx:{}, fileidx:{}'.format(taskidx,fileidx))
            threading.Thread(target=pic_upload_daemon, args=(_stub, taskidx,fileidx,)).start()
    except Exception,e:
        _stub.log(traceback.format_exc())

def parse_pbpttstoregrouppttup(_stub, _cmd, bytes):
    global media_upload_tasks
    rspBody = cmd0x388.RspBody()
    rspBody.ParseFromString(bytes)
    try:
        pass
    except Exception,e:
        _stub.log(traceback.format_exc())

def parse_pbpttcentersvrcmdreqapplyupload500(_stub, _cmd, bytes):
    global media_upload_tasks
    rspBody = cmd0x346.RspBody()
    rspBody.ParseFromString(bytes)
    try:
        pass
    except Exception,e:
        _stub.log(traceback.format_exc())

def parse_qqwalletvoicepack_macthvoice(_stub, _cmd, bytes):
    try:
        pass
    except Exception,e:
        _stub.log(traceback.format_exc())


global upload_seq
upload_seq = 21632
def get_upload_seq():
    global upload_seq
    upload_seq = upload_seq + 1
    if upload_seq > 65535:
        upload_seq = 1
    return upload_seq
def read_up_file(fname, rpos, rsize):
    with open(fname, "rb") as fh:
        fh.seek(rpos)
        rbytes = fh.read(rsize)
        if rbytes:
            return rbytes, len(rbytes)
        return '', 0

def recv_datahighway_block(the_socket):
    #data length is packed into 4 bytes
    sock_data=''
    rsize = 1
    wsize = 0
    while True:
        rdata = the_socket.recv(rsize)
        sock_data += rdata
        tsize = len(sock_data)
        if tsize <= 1:
            if sock_data[0] == '\x28':
                wsize = 4
                rsize = wsize
            else:
                raise Exception('recv_datahighway_block error : DataHighwayHead head error')
        elif wsize == 4:
            if tsize == 5:
                wsize = 4 + struct.unpack('>I', sock_data[1:5])[0]
                if wsize <= 4:
                    raise Exception('recv_datahighway_block error : DataHighwayHead len error')
                rsize = wsize
            else:
                rize = 5 - tsize
        elif wsize == 1:
            if sock_data[tsize-1] == '\x29':
                return sock_data
            else:
                raise Exception('recv_datahighway_block error : DataHighwayHead tail error')
        else:
            if tsize == wsize+5:
                wsize = 1
                rsize = wsize
            elif tsize < wize+5:
                rsize = wize+5 - tsize
            else:
                raise Exception('recv_datahighway_block error : block size error')
        pass
    return None

def pic_upload_daemon(_stub, taskidx, fileidx):
    global media_upload_tasks
    task = media_upload_tasks[taskidx]
    upd = task.uplist[fileidx]
    #_stub.log('pic_upload_daemon taskidx:{}  fileidx:{}'.format(taskidx, fileidx))
    if upd['status'] == 'status_upload':
        try:
            i = random.randint(0, len(upd['up_ip'])-1)
            bol = detect_endian()
            if bol == '<':
                _ip = socket.inet_ntoa(struct.pack('>I',socket.htonl(upd['up_ip'][i])))
            else:
                _ip = socket.inet_ntoa(struct.pack('<I',socket.htonl(upd['up_ip'][i])))

            _port = upd['up_port'][i]
            upd['up_server_ip'] = upd['up_ip'][i]
            upd['up_server_port'] = upd['up_port'][i]

            _stub.log('pic_upload_daemon ip:{}, port:{}'.format(_ip,_port))

            reqDataHighwayHead = CSDataHighwayHead.ReqDataHighwayHead()
            reqDataHighwayHead.msg_basehead.uint32_version = 1
            reqDataHighwayHead.msg_basehead.bytes_uin = str(task.from_code)
            reqDataHighwayHead.msg_basehead.bytes_command = "PicUp.Echo"
            reqDataHighwayHead.msg_basehead.uint32_seq = get_upload_seq()
            reqDataHighwayHead.msg_basehead.uint32_retry_times = 0
            reqDataHighwayHead.msg_basehead.uint32_appid = Coder.hexstr2num(_stub.appId)
            reqDataHighwayHead.msg_basehead.uint32_dataflag = 4096
            reqDataHighwayHead.msg_basehead.uint32_command_id = 0

            reqdh = reqDataHighwayHead.SerializeToString()
            pack = '\x28' + struct.pack('>II', len(reqdh), 0) + reqdh + '\x29'

            #HexPacket(Coder.str2hexstr(pack)).dump(0)

            address = (_ip, _port)
            #address = ('127.0.0.1', 9000)
            if 1 == 1:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(6)
                s.connect(address)

                #_stub.log('try to send echo')
                s.sendall(pack)

                data = recv_datahighway_block(s)
                #.log('receive echo')

                #HexPacket(Coder.str2hexstr(data)).dump(0)

                rspDataHighwayHead = CSDataHighwayHead.RspDataHighwayHead()
                rspDataHighwayHead.ParseFromString(data[9:-1])
                if rspDataHighwayHead.uint32_error_code != 0:
                    raise Exception('upload file error : echo error')

                reqDataHighwayHead = CSDataHighwayHead.ReqDataHighwayHead()
                reqDataHighwayHead.msg_basehead.uint32_version = 1
                reqDataHighwayHead.msg_basehead.bytes_uin = str(task.from_code)
                reqDataHighwayHead.msg_basehead.bytes_command = "PicUp.DataUp"
                reqDataHighwayHead.msg_basehead.uint32_retry_times = 0
                reqDataHighwayHead.msg_basehead.uint32_appid = Coder.hexstr2num(_stub.appId)
                reqDataHighwayHead.msg_basehead.uint32_dataflag = 4096
                
                if task.to_code == -1:
                    reqDataHighwayHead.msg_basehead.uint32_command_id = 2
                else:
                    reqDataHighwayHead.msg_basehead.uint32_command_id = 1

                while upd['up_total'] < upd['size']:
                    reqDataHighwayHead.msg_basehead.uint32_seq = get_upload_seq()

                    reqDataHighwayHead.msg_seghead.uint64_filesize = upd['size']
                    reqDataHighwayHead.msg_seghead.uint64_dataoffset = upd['up_pos']
                    upbytes, reqDataHighwayHead.msg_seghead.uint32_datalength = read_up_file(upd['path'], upd['up_pos'], 4096)
                    reqDataHighwayHead.msg_seghead.bytes_serviceticket = upd['up_ukey']
                    reqDataHighwayHead.msg_seghead.bytes_md5 = Coder.hexstr2str(md5hex(upbytes))
                    reqDataHighwayHead.msg_seghead.bytes_file_md5 = Coder.hexstr2str(upd['md5'])

                    #_stub.log(reqDataHighwayHead)
                    reqdh = reqDataHighwayHead.SerializeToString()
                    pack = '\x28' + struct.pack('>II', len(reqdh), len(upbytes)) + reqdh + upbytes + '\x29'

                    #HexPacket(Coder.str2hexstr(pack)).dump(0)
                    #_stub.log('try to send data size:{} sended size:{} total size:{}'.format(len(upbytes), upd['up_total'], upd['size']))
                    s.sendall(pack)

                    data = recv_datahighway_block(s)
                    #_stub.log('receive rsp')

                    rspDataHighwayHead = CSDataHighwayHead.RspDataHighwayHead()
                    rspDataHighwayHead.ParseFromString(data[9:-1])
                    if rspDataHighwayHead.uint32_error_code == 0:
                        upd['up_total'] += len(upbytes)
                        upd['up_pos'] = upd['up_total']
                    else:
                        _stub.log(rspDataHighwayHead)
                        raise Exception('upload file error')
                upd['up_succ'] = 1
                s.close()
                _stub.log('pic_upload_daemon upload file succ')
        except Exception, e:
            upd['up_succ'] = -1
            _stub.log('pic_upload_daemon ' + traceback.format_exc())
    else:
        pass

    for udp in task.uplist:
        #_stub.log(udp['up_succ'])
        if udp['up_succ'] == 0:
            return

    del media_upload_tasks[taskidx]
    send_mixmsg_from_task(_stub, task)
    return


def ptt_upload_daemon(_stub, taskidx, fileidx):
    global qq_session
    global media_upload_tasks
    task = media_upload_tasks[taskidx]
    upd = task.uplist[fileidx]
    #_stub.log('pic_upload_daemon taskidx:{}  fileidx:{}'.format(taskidx, fileidx))
    if upd['status'] == 'status_upload':
        pass
    else:
        pass

    for udp in task.uplist:
        #_stub.log(udp['up_succ'])
        if udp['up_succ'] == 0:
            return

    return

def post_data(url,param_dict,param_header,file = '',param_type = 'x-www-form-urlencode'):
    '''
    @功能：封装post方式
    @paramType:指传入参数类型，可以是form-data、x-www-form-urlencode、json
    '''
    respone_code = None
    respone = None
    try:
        if param_type == 'x-www-form-urlencode':
            params = urllib.urlencode(param_dict)
        elif param_type == 'json':
            params = json.dumps(param_dict)
        if len(file) == 0 :
            ret = requests.post(url, headers=param_header)
        else:
            #_files = {'file':open(file,'rb')}
            post_data = ''
            with open(file, 'rb') as f:
                post_data = f.read()
            ret = requests.post(url, data=post_data, headers=param_header)
        respone_code = ret.status_code
        respone = ret.text
    except requests.HTTPError, e:
        respone_code = e.getcode()
        respone = e.read().decode("utf-8")
    return respone_code,respone


######################################################################################################
def get_range(parameter_str):
    regInt='^0$|^[1-9]\d*$'
    regFloat='^0\.\d+$|^[1-9]\d*\.\d+$'
    range_point='({}|{})'.format(regInt,regFloat)
    range_range='(^{}|^{})-({}$|{}$)'.format(regInt.replace('^','').replace('$',''),regFloat.replace('^','').replace('$',''),regInt.replace('^','').replace('$',''),regFloat.replace('^','').replace('$',''))

    _range = str(parameters.get(parameter_str, '-1.0'))
    _range = _range.replace(" ", "")

    _from = None
    _to = None

    if _range.startswith('-'):
        _from = -1.0;
    elif re.search(range_point,_range):
        _from = float(_range)
    elif re.search(range_range,_range):
        sp = _range.index('-')
        _from = float(_range[:sp])
        _to = float(_range[sp+1:])
        if _from >= _to:
            _from = None
            _to = None
    else:
        _from = None
    return _from, _to

@qqterm_stub_func
def redpacket_pick(_stub, group_code, group_uin, from_code, to_code, content, extra_channel=None):
    global qq_session
    if cmp(content.type, 'redpacket') == 0:
        redpacket = dyobj("type redtype msgtype title group_name group_type pick_uin pick_uname sender_uin redpacket_id redpacket_channel redpacket_authkey from_code to_code")
        redpacket.type = 'redpacket'
        redpacket.redtype = content.redtype
        redpacket.msgtype = content.msgtype
        redpacket.title = content.title
        redpacket.pick_uin = _stub.qqcode 
        redpacket.pick_uname = _stub.nickname
        redpacket.group_name = group_code
        redpacket.group_type = str(content.group_type)
        redpacket.sender_uin = content.sender_uin
        redpacket.redpacket_id = content.redpacketid
        redpacket.redpacket_channel = content.redchannel
        redpacket.redpacket_authkey = content.authkey
        redpacket.from_code = from_code
        redpacket.to_code = to_code
        threading.Thread(target=redpacket_pick_thread, args=(_stub, qq_session, redpacket, extra_channel,)).start()
    pass

def redpacket_pick_thread(_stub, session, redpacket, extra_channel=None, immediately=False):
    _stub.log('pick down ......')
    pass

