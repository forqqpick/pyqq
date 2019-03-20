# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import time
import threading
import random
import binascii
import struct
import traceback
import logging
import re

import datetime
from datetime import timedelta

import ctypes

import json

from jcemessages import *

from Tools import Coder
from Tools import MD5
from Tools import TEA
from Tools import HexPacket
from Tools import Img
import Keys
from Tlv import Tlv
from RawSocket import RawSocket

from socket import * 

import socket
import slots

import zlib

import ssdp
  
SERVICE_NAME = 'pyqq_service'

def equalUtf8(coding):
    return coding is None or coding.lower() in ('utf8', 'utf-8', 'utf_8')

class CodingWrappedWriter(object):
    def __init__(self, coding, writer):
        self.flush = getattr(writer, 'flush', lambda : None)
        
        wcoding = getattr(writer, 'encoding', None)
        wcoding = 'gb18030' if (wcoding in ('gbk', 'cp936')) else wcoding
        if not equalUtf8(wcoding):
            self._write = lambda s: writer.write(
                s.decode(coding).encode(wcoding, 'ignore')
                #s.decode(coding).encode(sys.getfilesystemencoding())
            )
        else:
            self._write = lambda s: writer.write(
                s.decode(coding).encode(sys.getfilesystemencoding())
            )
            #self._write = writer.write
    
    def write(self, s):
        self._write(s)
        self.flush()

utf8Stdout = CodingWrappedWriter('utf8', sys.stdout)

global logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(utf8Stdout)  
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s:%(thread)d %(message)s")  
#thread.id = ctypes.CDLL('libc.so.6').syscall(186)
ch.setFormatter(formatter)  
logger.addHandler(ch) 
sck_mutex = threading.Lock()
dog_mutex = threading.Lock()

nowtime = lambda:int(round(time.time() * 1000))

class TeaDecodeException(Exception):
    pass

class SSDPServer():  
    def __init__(self):  
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
        self.__s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
  
        local_ip = ssdp.get_local_ip()
        any_ip = '0.0.0.0'  
  
        # 绑定到任意地址和SSDP组播端口上  
        self.__s.bind((any_ip, ssdp.SSDP_PORT))  
  
        # INFO: 使用默认值  
        # self.__s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 20)  
        # self.__s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, 1)  
        # self.__s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF,  
        #                     socket.inet_aton(intf) + socket.inet_aton('0.0.0.0'))  
        # INFO: 添加到多播组  
        self.__s.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,  
                            socket.inet_aton(ssdp.SSDP_ADDR) + socket.inet_aton(local_ip))  
        self.local_ip = local_ip  
  
    def ssdp_server_daemon(self):  
        while True:  
            data, addr = self.__s.recvfrom(2048)  
            conn = ssdp.Connection(SERVICE_NAME, self.__s, data, addr)  
            conn.handle_request()  
        self.__s.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP,  
                            socket.inet_aton(ssdp.SSDP_ADDR) + socket.inet_aton(self.local_ip))  
        self.__s.close() 

    def start(self):  
        threading.Thread(target=self.ssdp_server_daemon).start()  

class PyQQ(slots.slots):
    #MainService.java -> MsfMessagePair respMsg = MainService.this.msfSub.getServiceRespMsg();
    #public final MsfServiceSdk msfSub;
    #com.tencent.mobileqq.service.message

    '''android qq'''
    def __init__(self, qqnum, qqpwd,simulate,_version):

        super(PyQQ, self).__init__(self)

        self.ssdp = SSDPServer()  
        self.ssdp.start()

        self.sck_dog = 0
        self.heart_beat = 0

        self.server_time = Coder.num2hexstr(int(time.time()), 4)

        self.qqcode = long(qqnum)

        self.start_time = datetime.datetime.now()
        self.start_counter = 0
        self.session_file = "session.txt"

        self.session_data = self.load_dict(self.session_file)

        self.append_slot('on_server_message')

        self.cmd_type_login = 0
        self.cmd_type_online = 1
        self.cmd_type_normal = 2

        #cmd
        self.qq_cmd_login = 'wtlogin.login'
        self.qq_cmd_oidbsvc_7a20 = 'OidbSvc.0x7a2_0'
        self.qq_cmd_statsvc_register = 'StatSvc.register'
        self.qq_cmd_configpushsvc_pushreg = 'ConfigPushSvc.PushReq'
        self.qq_cmd_configpushsvc_pushdomain = 'ConfigPushSvc.PushDomain'

        self.qq_cmd_statsvc_get = 'StatSvc.get'

        self.qq_cmd_onlinepush_pbpushgroupmsg = 'OnlinePush.PbPushGroupMsg'
        self.qq_cmd_onlinepush_pbc2cmsgsync = 'OnlinePush.PbC2CMsgSync'

        self.qq_cmd_messagesvc_pushnotify = 'MessageSvc.PushNotify'
        self.qq_cmd_messagesvc_pushreaded = 'MessageSvc.PushReaded'
        self.qq_cmd_messagesvc_pbgetmsg = 'MessageSvc.PbGetMsg'
        self.qq_cmd_messagesvc_pbsendmsg = 'MessageSvc.PbSendMsg'
        self.qq_cmd_messagesvc_pushforceoffline = 'MessageSvc.PushForceOffline'
        self.qq_cmd_messagesvc_sendgroupmsg = 'MessageSvc.SendGroupMsg'

        self.qq_cmd_friendlist_gettrooplistreqv2 = 'FriendList.GetTroopListReqV2'
        self.qq_cmd_friendlist_gettroopmemberlist = 'FriendList.GetTroopMemberList'

        self.qq_cmd_imgstore_grouppicup = 'ImgStore.GroupPicUp'
        self.qq_cmd_longconn_offpicup = 'LongConn.OffPicUp'

        self.qq_cmd_pttstore_grouppttup = 'PttStore.GroupPttUp'
        self.qq_cmd_pttcentersvr_pb_pttcenter_CMD_REQ_APPLY_UPLOAD_500 = 'PttCenterSvr.pb_pttCenter_CMD_REQ_APPLY_UPLOAD-500'

        self.qq_cmd_qqwalletvoicepack_macthvoice = 'QQwalletVoicePack.macthVoice'

        #QQ
        self.qqnum = qqnum
        self.qqpwd = qqpwd
        self.vcode = ''
        self.qqHexstr = Coder.str2hexstr(qqnum)
        self.pwdMd5 = MD5.md5_hex(qqpwd)
        self.uin = Coder.qqnum2hexstr(qqnum)
        self.HEART_INTERVAL = 1*60 #心跳时间间隔 如果在手机QQ上注销/退出帐号后，一般10分钟左右您的QQ号就不会显示在线了

        self.alive = False
        self.online = False

        self.imei = Coder.str2hexstr('865336195797989')
        self.ksid = Coder.trim('')
        self.extBin = Coder.trim('')
        self.os_type = Coder.str2hexstr('android')
        self.os_version = Coder.str2hexstr('6.0.0')
        self.os_sdk = Coder.str2hexstr('sdk23')
        self.network_type = Coder.str2hexstr('')
        #self.sim_operator_name = Coder.str2hexstr('CMCC')
        self.sim_operator_name = Coder.str2hexstr('')
        self.apn = Coder.str2hexstr('wifi')
        self.wifi_name = Coder.str2hexstr('OOOOOOOOO')
        self.qq_guid = ''   
        self.qqw_libversion = ''

        self.web_user_agent = 'Mozilla/5.0'

        qq_simulate = simulate

        self.qqversion = '6.7.1'

        self.mobile_model = 'XXX-UL01'
        self.device = Coder.str2hexstr('Huawei P10')
        self.device_product = Coder.str2hexstr('Huawei')
        self.appId = Coder.num2hexstr(537050387, 4)                    
        self.package_name = Coder.str2hexstr('com.tencent.mobileqq')
        self.ver = Coder.str2hexstr('||A6.7.1.267720')                  
        self.ptag_touch = '00 00 00 0a 02 00 00 00 04'
        self.ptag_auth = '00 00 00 0a 01'
        self.ptag_online = '00 00 00 0b 01'

        if simulate in ['pad'] and _version in ['5.8.5']:
            self.qqversion = _version
            self.mobile_model = 'TTT-X10'
            self.device = Coder.str2hexstr('MediaPad M5')
            self.device_product = Coder.str2hexstr('Huawei')
            self.package_name = Coder.str2hexstr('com.tencent.minihd.qq')
            self.ver = Coder.str2hexstr('||A5.8.5.6793')
            self.ptag_touch = '00 00 00 08 02 00 00 00 04'
            self.ptag_auth = '00 00 00 08 01'
            self.ptag_online = '00 00 00 09 01'
            self.appId = Coder.num2hexstr(537060297, 4)
            self.web_user_agent = 'Mozilla/5.0 (Linux; Android {}; {} Build/; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.126 TBS/044433 Mobile Safari/537.36 V1_AND_SQ_{}_YYB_D QQ/{} NetType/WIFI WebP/0.3.0 Pixel/1440 StatusBarHeight/96'.format(self.os_version, self.device,self.qqversion,self.qqversion)

        if simulate in ['phone'] and _version in ['7.9.7']:
            self.qqversion = _version
            self.appId = Coder.num2hexstr(537060480, 4)
            self.qq_guid = '6CA44308BC049A8B880844E66F17588E'
            self.ver = Coder.str2hexstr('||A7.9.7.390142')
            self.qqw_libversion = '2018011001&2018011002'

        if simulate in ['ipad'] and _version in ['7.3.1.3']:
            self.qqversion = _version
            self.ptag_touch = '00 00 00 0c 02 00 00 00 04'
            self.ptag_auth = '00 00 00 0c 01'
            self.ptag_online = '00 00 00 0d 01'
            self.ver = Coder.str2hexstr('|00000|I7.3.1.3')
            self.os_type = Coder.str2hexstr('ios_ipad')
            self.os_version = Coder.str2hexstr('10.3.3')
            self.os_sdk = Coder.str2hexstr('')
            self.imei = Coder.str2hexstr('867776178797000')
            self.mobile_model = 'iPad 3G'
            self.device = Coder.str2hexstr('iPad')
            self.device_product = Coder.str2hexstr('apple')
            self.package_name = Coder.str2hexstr('com.tencent.mipadqq')
            self.appId = Coder.num2hexstr(537058006, 4)
            self.qq_guid = ''
            self.qqw_libversion = ''
            self.web_user_agent = 'IPadQQ/7.3.1.3 CFNetwork/811.5.4 Darwin/16.7.0'

        logger.info('qq simulate: {} @ {} {}'.format(qqnum, qq_simulate, self.qqversion))

        threading.Thread(target=self.qq_term).start()

        self.plug_module('message_handler')

        self.sck_dog = 99999
        threading.Thread(target=self.startHeart).start()

    def prepare_qq(self):
        self.alive = False
        self.online = False
        self.verify = False

        self.seq = 1000

        self.extBin = Coder.trim('')
        self.msgCookies = Coder.trim('D9 68 9D 1F')

        #Keys
        self.defaultKey = '00'*16     #qq.key
        self.randomKey = Coder.genBytesHexstr(16)
        self.keyId = random.randint(0, len(Keys.pubKeys)-1)
        self.pubKey = Keys.pubKeys[self.keyId]
        self.shareKey = Keys.shareKeys[self.keyId]
        self.pwdKey = Coder.hash_qqpwd_hexstr(self.qqnum, self.qqpwd)
        self.tgtKey = Coder.genBytesHexstr(16)
        self.sessionKey = ''
        self.pskey = ''

        self.grouplist = {}
        self.groupmemberlist = {}

        #debug
        logger.info('uin: '+ self.uin)
        
        logger.info('pwdMd5: ' + self.pwdMd5)
        logger.info('randomKey: ' + self.randomKey)
        logger.info('pubKey: ' + self.pubKey)
        logger.info('shareKey: ' + self.shareKey)
        logger.info('pwdKey: ' + self.pwdKey)
        logger.info('tgtKey: ' + self.tgtKey)

    def __del__(self):
        pass

    def log(self,info_str):
        logger.info(info_str)

    def plug_module(self, module_name):
        logger.info(self.Plug(module_name))
        try:
            self.on_server_message(self, '-=init=-', '')
            if self.online:
                self.on_server_message(self, '-=online=-', '')
        except Exception,e:
            logger.info(traceback.format_exc())
        pass
        
    def qq_term(self):
        HOST = ssdp.get_local_ip()  
        PORT = 8888  
        BUFSIZE = 1024  
          
        ADDR = (HOST,PORT)  
          
        udpSerSock = socket.socket(AF_INET, SOCK_DGRAM)  
        udpSerSock.bind(ADDR)  
        
        while True:  
            _data, addr = udpSerSock.recvfrom(BUFSIZE)  
            if len(_data) < 512:
                try:
                    m = re.findall(r"([^ ]+) ?(.*)?", _data)
                    if m: 
                        _method_name = m[0][0]
                        _method_params = m[0][1].strip()
                        if _method_name.startswith('module.'):
                            _eval_str = "getattr(self,'{}')({})".format(_method_name.replace('module.',''), _method_params)
                            _eval_str = _eval_str.decode(sys.getfilesystemencoding()).encode('utf8')
                            eval(_eval_str)
                        elif self.stub_func_table.has_key(_method_name):
                            _eval_str = "self.stub_func_table['{}']({})".format(_method_name, _method_params)
                            _eval_str = _eval_str.decode(sys.getfilesystemencoding()).encode('utf8')
                            eval(_eval_str)
                            pass
                        else:
                            logger.info('not found ' + _method_name)
                except Exception,e:
                    logger.info(traceback.format_exc())
                    pass
        udpSerSock.close()

    def do_qq_term_cmd(self, _cmd):
        if _cmd == 'get_group_list':
            self.qq_get_group_list()

    def byteify(self, input):
        if isinstance(input, dict):
            return {self.byteify(key):self.byteify(value) for key,value in input.iteritems()}
        elif isinstance(input, list):
            return [self.byteify(element) for element in input]
        elif isinstance(input, unicode):
            return input.encode('utf-8')
        else:
            return input

    def increase_sso_seq(self):
        if self.seq > 2147483647:
            self.seq = 10000
        else:
            self.seq += 1

    def try_to_start_qq(self, _delay = 1):
        logger.info('try_to_start_qq ...')
        self.online = False
        self.alive = False
        self.sck_dog = -1
        self.on_server_message(self, '-=offline=-', '')
        time.sleep(_delay)
        self.prepare_qq()
        time.sleep(1)
        #self.socket = RawSocket('113.108.90.53', 8080)
        while True:
            try:
                logger.info('try to connect server ...')
                self.socket = RawSocket('msfwifi.3g.qq.com', 8080)
                logger.info('socket@0x{:x} created ...'.format(id(self.socket)))
                if not self.socket.connect():
                    logger.info('socket connect error!')
                else:
                    self.start_counter += 1
                    logger.info('start recv_package thread ...')
                    threading.Thread(target=self.recv_package).start()
                    logger.info('try to send login package ...')
                    self.login()
                    return
            except Exception,e:
                logger.info(traceback.format_exc())
            time.sleep(3)
        pass

    def send_package(self, package):
        if sck_mutex.acquire():
            try:
                self.increase_sso_seq()
                #print string_to_hex_string(package)
                ret = self.socket.sendall(package)
                logger.info('socket@0x{:x} send {}({}) '.format(id(self.socket),ret, len(package)))
            except Exception,e:
                logger.info('socket@0x{:x} send error \n({}) '.format(id(self.socket),traceback.format_exc()))
            finally:
                sck_mutex.release()

    def recv_package(self):
        last_recv_time = 0
        _remain = 0
        _rdata = ''
        package = ''
        zero_counter = 0
        sck = self.socket
        logger.info('recv_package thread started ...')
        while True:
            if len(_rdata) == 0:
                try:
                    logger.info('socket@0x{:x} try to recv()'.format(id(self.socket)))
                    _rdata = self.socket.recv()
                    if sck <> self.socket:
                        logger.info('recv_package thread exit (socket not match) ... ')
                        return
                        pass
                    if last_recv_time > 0:
                        now_recv_time = nowtime()
                        if (now_recv_time - last_recv_time) > 3000:
                            last_recv_time = 0
                        else:
                            last_recv_time = now_recv_time
                            _rdata = ''
                            package = ''
                            continue
                    if len(_rdata) == 0:
                        zero_counter += 1
                        if zero_counter > 3:
                            raise Exception('recv data size=0')
                    else:
                        zero_counter = 0
                except Exception ,e:
                    logger.info(traceback.format_exc())
                    self.online = False
                    self.alive = False
                    if dog_mutex.acquire():
                        self.sck_dog = 99999
                        dog_mutex.release()
                    logger.info('socket@0x{:x} recv_package thread exit ...'.format(id(self.socket)))
                    return
                logger.info('socket@0x{:x} recv: {}'.format(id(self.socket), len(_rdata)))
            _rsize = len(_rdata)
            if _remain == 0:
                if _rsize < 4:
                    if len(package)+_rsize >= 4:
                        _rdata = package+_rdata
                        package = ''
                    else:
                        package += _rdata
                        _rdata = ''
                        continue
                else:
                    if len(package) > 0:
                        _rdata = package + _rdata
                        package = ''
                _len, = struct.unpack('>i',_rdata[:4])
                if _len < 0:
                    last_recv_time = nowtime()
                    _rdata = ''
                    package = ''
                    continue
                if _len > _rsize:
                    package = _rdata
                    _rdata = ''
                    _remain = _len - _rsize
                else:
                    package = _rdata[:_len]
                    _rdata = _rdata[_len:]
                    _remain = 0
            else:
                if _remain < _rsize:
                    package += _rdata[:_remain]
                    _rdata = _rdata[_remain:]
                    _remain = 0
                else:
                    package += _rdata
                    _rdata = ''
                    _remain -= _rsize
            if _remain == 0:
                #print string_to_hex_string(package)
                logger.info("_remain:0 _rdata size:{} package_len:{}".format(len(_rdata), len(package)))
                try:
                    self.upack_package(package)
                except TeaDecodeException,e:
                    print e
                    last_recv_time = nowtime()
                    _rdata = ''
                    package = ''
                    pass
                package = ''
            else:
                logger.info("_remain:{} _rdata size:{}".format(_remain,len(_rdata)))

    def send_SQQzoneSvc_MqqOnlineNtf():
        pass
    def startHeart(self):
        while True:
            time.sleep(1)
            if (self.alive and self.online) or self.sck_dog > 9000:
            #    pass
            #if 1==1:
                if self.sck_dog > 6:
                    if self.sck_dog < 9000:
                        logger.info('not receive heart beat echo , try to restart')
                    threading.Thread(target=self.try_to_start_qq, args=(3,)).start()
                else:
                    if dog_mutex.acquire():
                        if self.sck_dog >= 0:
                            self.sck_dog += 1
                        dog_mutex.release()
            if self.heart_beat > self.HEART_INTERVAL:
                if self.alive and self.online:
                    self.qq_send_heartbeat()
                    self.heart_beat = 0
                    if dog_mutex.acquire():
                        self.sck_dog = 0
                        dog_mutex.release()
            else:
                self.heart_beat += 1

    def upack_package(self, package):
        logger.info('upack_package len:{}'.format(len(package)))
        #HexPacket(Coder.str2hexstr(package)).dump(0)
        pack = HexPacket(Coder.str2hexstr(package))
        _pack = pack
        #返回包头
        pack.shr(4)
        pack.shr(8)
        pack.shr(2 + len(self.qqHexstr)/2)
        #返回包体

        #logger.info('tea body')
        #pack.dump(0)
        try:
            data = TEA.detea_hexstr(pack.remain(), self.defaultKey)
            if dog_mutex.acquire():
                self.sck_dog = -1
                dog_mutex.release()
        except Exception,e:
            logger.info('TEA.detea_hexstr Exception B ***************')
            logger.info(traceback.format_exc())
            _pack.dump(0)
            logger.info('package({}): {}'.format(len(package),Coder.str2hexstr(package)))
            logger.info('defaultKey: {}'.format(self.defaultKey))
            logger.info('TEA.detea_hexstr Exception E ***************')
            raise TeaDecodeException('tea decode error')

        pack = HexPacket(data)
        head = pack.shr(Coder.hexstr2num(pack.shr(4))-4)
        #logger.info('head len:{}'.format(len(head)/2))
        #HexPacket(head).dump(0)
        body = pack.remain(1)
        body_tail = pack.remain()
        #logger.info('body len:{}'.format(len(body)/2))
        #HexPacket(body).dump(0)
        #logger.info('body_tail len:{}'.format(len(body_tail)/2))
        #HexPacket(body_tail).dump(0)
        #head
        pack = HexPacket(head)
        sso_seq = Coder.hexstr2num(pack.shr(4)) #seq
        pack.shr(4)
        pack.shr(Coder.hexstr2num(pack.shr(4))-4)
        _cmd = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(4))-4)) #cmd
        #logger.info("unpack -> cmd :[{}]".format(_cmd))
        pack.shr(Coder.hexstr2num(pack.shr(4))-4)

        if _cmd == self.qq_cmd_login:
            self.unpackRecvLoginMessage(body)
            if self.alive: #登录成功
                self.qq_touch_online()
                return True
            elif self.verify: #需要验证码
                pass
            else:
                return False
            pass
        elif _cmd == self.qq_cmd_oidbsvc_7a20:
            self.qq_set_online()
            pass
        elif _cmd == self.qq_cmd_statsvc_register:
            self.heart_beat = 0
            self.online = True
            self.online_time = datetime.datetime.now()
            try:
                self.on_server_message(self, '-=online=-', '')
            except Exception,e:
                logger.info(traceback.format_exc())

            pass
        elif _cmd == self.qq_cmd_statsvc_get:
            logger.info('recv heartbeat ...')
            pass
        else:
            try:
                self.on_server_message(self, _cmd, body+body_tail)
            except Exception,e:
                logger.info(traceback.format_exc())
            pass

    def pack_package(self, _packet, _type):
        #_type 0 login  1 before online 2 after online
        packet = ''
        if _type == 0:
            #packet += Coder.trim('00 00 00 08 02 00 00 00 04')
            packet += Coder.trim(self.ptag_touch)
        elif _type == 1:
            #packet += Coder.trim('00 00 00 08 01')
            packet += Coder.trim(self.ptag_auth)
            packet += Coder.num2hexstr(len(self.token002c)/2+4, 4) + self.token002c
        else:
            #packet += Coder.trim('00 00 00 09 01')
            packet += Coder.trim(self.ptag_online)
            packet += Coder.num2hexstr(self.seq, 4)

        packet += Coder.trim('00')
        packet += Coder.num2hexstr(len(self.qqHexstr)/2+4, 4)
        packet += self.qqHexstr
        packet += _packet
        packet = Coder.num2hexstr(len(packet)/2+4, 4) + packet
        return packet

    def login(self, verifyCode=None):
        packet = self.pack_package(self.packLoginMessage(verifyCode), self.cmd_type_login)
        self.send_package(Coder.hexstr2str(packet))

    def unpackRecvLoginMessage(self, body):
        pack = HexPacket(body)
        pack.shr(4 + 1)
        lens = Coder.hexstr2num(pack.shr(2))
        logger.info('*** len:{}'.format(lens))
        pack.shr(10 + 2)
        retCode = Coder.hexstr2num(pack.shr(1))
        logger.info("retCode:{}".format(retCode))
        if retCode == 0: #登录成功
            self.unpackRecvLoginSucceedMessage(pack.remain())
            logger.info(u'登录成功: '+self.nickname)
            self.alive = True
            self.verify = False
        elif retCode == 2: #需要验证码
            self.unpackRecvLoginVerifyMessage(pack.remain())
            logger.info(self.verifyReason)
            self.alive = False
            self.verify = True
            threading.Thread(target=Img.showFromHexstr, args=(self.verifyPicHexstr, )).start()
            code = raw_input(u'请输入验证码：')
            self.login(Coder.str2hexstr(code))
        else: #登录失败
            pack = HexPacket(TEA.detea_hexstr(pack.remain(), self.shareKey))
            #pack = HexPacket(TEA.detea_hexstr(pack.shr(lens-16-1), self.shareKey))
            pack.dump(0)
            #pack.shr(2 + 1 + 4 + 2)
            if not (Coder.hexstr2num(pack.shr(2)) == 9):
                logger.info("unknown wtlogin.login return packet")
            _code = Coder.hexstr2num(pack.shr(1))
            if _code == 9:
                pack.shr(4 + 2)
                pack.shr(4) #type
                title = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(2))))
                logger.info(title)
                msg = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(2))))
                logger.info(title+ ': '+ msg)
            elif _code == 0xa0:
                tlv_num = Coder.hexstr2num(pack.shr(2))
                for i in xrange(tlv_num):
                    tlv_cmd = pack.shr(2)
                    tlv_data = pack.shr(Coder.hexstr2num(pack.shr(2)))
                    logger.info(tlv_cmd+ "      "+ tlv_data)
                    try:
                        #logger.info(Coder.hexstr2str(tlv_data).decode('utf8').encode(sys.getfilesystemencoding()))
                        logger.info(Coder.hexstr2str(tlv_data))
                    except Exception,e:
                        logger.info(traceback.format_exc())
                        pass
                    self.decodeTlv(tlv_cmd, tlv_data)
                pass
            else:
                logger.info("unknown wtlogin.login return packet -> {}".format(_code))
                pass
            self.alive = False
            self.verify = False

    def unpackRecvLoginVerifyMessage(self, data):
        data = TEA.detea_hexstr(data, self.shareKey)
        pack = HexPacket(data)
        pack.shr(3)
        tlv_num = Coder.hexstr2num(pack.shr(2))
        for i in xrange(tlv_num):
            tlv_cmd = pack.shr(2)
            tlv_data = pack.shr(Coder.hexstr2num(pack.shr(2)))
            self.decodeTlv(tlv_cmd, tlv_data)
        pass
    def unpackRecvLoginSucceedMessage(self, data):
        data = TEA.detea_hexstr(data, self.shareKey)
        pack = HexPacket(data)
        pack.shr(2 + 1 + 4)
        data = pack.shr(Coder.hexstr2num(pack.shr(2)))
        #TLV解包
        data = TEA.detea_hexstr(data, self.tgtKey)
        pack = HexPacket(data)
        tlv_num = Coder.hexstr2num(pack.shr(2))
        for i in xrange(tlv_num):
            tlv_cmd = pack.shr(2)
            tlv_data = pack.shr(Coder.hexstr2num(pack.shr(2))).upper()
            logger.info(tlv_cmd+ "      "+ tlv_data)
            try:
                #logger.info(Coder.hexstr2str(tlv_data).decode('utf8').encode(sys.getfilesystemencoding()))
                pass
            except Exception,e:
                logger.info(traceback.format_exc())
                pass
            self.decodeTlv(tlv_cmd, tlv_data)
        self.defaultKey = self.sessionKey
    def decodeTlv(self, cmd, data):
        if cmd == Coder.trim('01 6A'):
            pass
        elif cmd == Coder.trim('01 06'):
            pass
        elif cmd == Coder.trim('01 0C'):
            pass
        elif cmd == Coder.trim('01 0A'):
            self.token004c = data
            #logger.info('token004c: {}'.format(self.token004c))
            #logger.info('token004c: {}'.format(Coder.hexstr2str(self.token004c)))
        elif cmd == Coder.trim('01 0D'):
            pass
        elif cmd == Coder.trim('01 14'):
            pack = HexPacket(data)
            pack.shr(6)
            self.token0058 = pack.shr(Coder.hexstr2num(pack.shr(2)))
            #logger.info('token0058: {}'.format(self.token0058))
            #logger.info('token0058: {}'.format(Coder.hexstr2str(self.token0058)))
        elif cmd == Coder.trim('01 0E'):
            self.mst1Key = data
            #logger.info('mst1Key: {}'.format(self.mst1Key))
            #logger.info('mst1Key: {}'.format(Coder.hexstr2str(self.mst1Key)))
        elif cmd == Coder.trim('01 03'):
            self.stweb = data
            logger.info('stweb: {}'.format(self.stweb))
            #logger.info('stweb: {}'.format(Coder.hexstr2str(self.stweb)))
        elif cmd == Coder.trim('01 1F'):
            pass
        elif cmd == Coder.trim('01 38'):
            #logger.info('tlv_t138: {}'.format(data))
            pass
        elif cmd == Coder.trim('01 1A'):
            pack = HexPacket(data)
            pack.shr(2 + 1 + 1)
            self.nickname = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(1))))
        elif cmd == Coder.trim('01 20'):
            self.skey = data
            logger.info('skey: {}'.format(self.skey))
            #logger.info('skey: {}'.format(Coder.hexstr2str(self.skey)))
        elif cmd == Coder.trim('01 36'):
            self.vkey = data
            #logger.info('vkey: {}'.format(self.vkey))
            #logger.info('vkey: {}'.format(Coder.hexstr2str(self.vkey)))
        elif cmd == Coder.trim('03 05'):
            self.sessionKey = data
            #logger.info('sessionKey: {}'.format(self.sessionKey))
            #logger.info('sessionKey: {}'.format(Coder.hexstr2str(self.sessionKey)))
        elif cmd == Coder.trim('01 43'):
            #logger.info("set token002c begin *******************************")
            self.token002c = data
            #logger.info('token002c: {}'.format(self.token002c))
            #logger.info('token002c: {}'.format(Coder.hexstr2str(self.token002c)))
            #logger.info("set token002c end   *******************************")
        elif cmd == Coder.trim('01 64'):
            self.sid = data
            #logger.info('sid: {}'.format(self.sid))
            #logger.info('sid: {}'.format(Coder.hexstr2str(self.sid)))
        elif cmd == Coder.trim('01 18'):
            pass
        elif cmd == Coder.trim('01 63'):
            pass
        elif cmd == Coder.trim('01 30'):
            pack = HexPacket(data)
            pack.shr(2)
            self.server_time = pack.shr(4)
            self.ip = Coder.hexstr2ip(pack.shr(4))
        elif cmd == Coder.trim('01 05'):
            pack = HexPacket(data)
            self.verifyToken1 = pack.shr(Coder.hexstr2num(pack.shr(2)))
            self.verifyPicHexstr = pack.shr(Coder.hexstr2num(pack.shr(2)))
            #logger.info('verifyToken1: {}'.format(self.verifyToken1))
            #logger.info('verifyToken1: {}'.format(Coder.hexstr2str(self.verifyToken1)))
            #logger.info('verifyPicHexstr: {}'.format(self.verifyPicHexstr))
            #logger.info('verifyPicHexstr: {}'.format(Coder.hexstr2str(self.verifyPicHexstr)))
        elif cmd == Coder.trim('01 04'):
            self.verifyToken2 = data
            #logger.info('verifyToken2: {}'.format(self.verifyToken2))
            #logger.info('verifyToken2: {}'.format(Coder.hexstr2str(self.verifyToken2)))
        elif cmd == Coder.trim('01 65'):
            pack = HexPacket(data)
            pack.shr(4)
            title = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(1))))
            msg = Coder.hexstr2str(pack.shr(Coder.hexstr2num(pack.shr(4))))
            self.verifyReason = title + ": " + msg
        elif cmd == Coder.trim('01 08'):
            self.ksid = data
            #logger.info('ksid: {}'.format(self.ksid))
            #logger.info('ksid: {}'.format(Coder.hexstr2str(self.ksid)))
        elif cmd == Coder.trim('01 6D'):
            self.superKey = data
            #logger.info('superKey: {}'.format(self.superKey))
            #logger.info('superKey: {}'.format(Coder.hexstr2str(self.superKey)))
        elif cmd == Coder.trim('01 6C'):
            self.pskey = data
            #logger.info('pskey: {}'.format(self.pskey))
            #logger.info('pskey: {}'.format(Coder.hexstr2str(self.pskey)))
        else:
            logger.info('unknown tlv: ')
            logger.info(cmd+ ': '+ data)

    def make_msg_header(self, _cmd, _extBin, _ksid):
        msgHeader = ''
        __cmd = Coder.str2hexstr(_cmd)
        msgCookies = self.msgCookies
        #msgHeader += Coder.num2hexstr(self.seq+1, 4)
        msgHeader += Coder.num2hexstr(self.seq, 4)
        msgHeader += self.appId
        msgHeader += self.appId
        msgHeader += Coder.trim('01 00 00 00 00 00 00 00 00 00 00 00')
        msgHeader += Coder.num2hexstr(len(_extBin)/2+4, 4) + _extBin
        msgHeader += Coder.num2hexstr(len(__cmd)/2+4, 4) + __cmd
        msgHeader += Coder.num2hexstr(len(msgCookies)/2+4, 4) + msgCookies
        msgHeader += Coder.num2hexstr(len(self.imei)/2+4, 4) + self.imei
        msgHeader += Coder.num2hexstr(len(_ksid)/2+4, 4) + _ksid
        msgHeader += Coder.num2hexstr(len(self.ver)/2+2, 2) + self.ver
        msgHeader = Coder.num2hexstr(len(msgHeader)/2+4, 4) + msgHeader
        return msgHeader

    def make_request_header(self, _cmd):
        reqHeader = ''
        __cmd = Coder.str2hexstr(_cmd)
        msgCookies = self.msgCookies
        reqHeader += Coder.num2hexstr(len(__cmd)/2+4, 4) + __cmd
        reqHeader += Coder.num2hexstr(len(msgCookies)/2+4, 4) + msgCookies
        reqHeader = Coder.num2hexstr(len(reqHeader)/2+4, 4) + reqHeader
        return reqHeader

    def packLoginMessage(self, verifyCode=None):
        #MessageHead
        msgHeader = self.make_msg_header(self.qq_cmd_login, self.extBin, self.ksid)

        #Message
        msg = ''
        msg += Coder.trim('1F 41')
        msg += Coder.trim('08 10 00 01')
        msg += self.uin
        msg += Coder.trim('03 07 00 00 00 00 02 00 00 00 00 00 00 00 00 01 01')
        msg += self.randomKey
        msg += Coder.trim('01 02')
        msg += Coder.num2hexstr(len(self.pubKey)/2, 2) + self.pubKey
        #TEA加密的TLV
        msg += self.packLoginTlv(verifyCode)

        msg += Coder.trim('03')
        msg = Coder.num2hexstr(len(msg)/2+2+1, 2) + msg
        msg = Coder.trim('02') + msg
        msg = Coder.num2hexstr(len(msg)/2+4, 4) + msg

        packet = msgHeader + msg
        packet = TEA.entea_hexstr(packet, self.defaultKey)
        return packet
    def packLoginTlv(self, verifyCode=None):
        if verifyCode == None:
            tlv = ''
            tlv += Coder.trim('00 09')
            tlv += Coder.trim('00 14') #tlv包个数
            #tlv组包
            tlv += Tlv.tlv18(self.uin)
            tlv += Tlv.tlv1(self.uin, self.server_time)
            tlv += Tlv.tlv106(self.uin, self.server_time, self.pwdMd5, self.tgtKey, self.imei, self.appId, self.pwdKey)
            tlv += Tlv.tlv116()
            tlv += Tlv.tlv100()
            tlv += Tlv.tlv107()
            tlv += Tlv.tlv144(self.tgtKey, self.imei, self.os_type, self.os_version, self.network_type, self.sim_operator_name, self.apn, self.device, self.device_product)
            tlv += Tlv.tlv142(self.package_name)
            tlv += Tlv.tlv145(self.imei)
            tlv += Tlv.tlv154(self.seq)
            tlv += Tlv.tlv141(self.sim_operator_name, self.network_type, self.apn)
            tlv += Tlv.tlv8()
            tlv += Tlv.tlv16b()
            tlv += Tlv.tlv147()
            tlv += Tlv.tlv177()
            tlv += Tlv.tlv187()
            tlv += Tlv.tlv188()
            tlv += Tlv.tlv191()
            tlv += Tlv.tlv194()
            tlv += Tlv.tlv202(self.wifi_name)
            tlv = TEA.entea_hexstr(tlv, self.shareKey)
            return tlv
        else:
            tlv = ''
            tlv += Coder.trim('00 02')
            tlv += Coder.trim('00 04')
            #tlv组包
            tlv += Tlv.tlv2(verifyCode, self.verifyToken1)
            tlv += Tlv.tlv8()
            tlv += Tlv.tlv104(self.verifyToken2)
            tlv += Tlv.tlv116()
            tlv = TEA.entea_hexstr(tlv, self.shareKey)
            return tlv
    def logout(self):
        '''注销'''
        pass

    def getVcode(self):
        '''获取验证码'''
        pass

    def assemble_package(self, msg_cmd, msg_body, msg_token, msg_ksid, cmd_type):
        msgHeader = self.make_msg_header(msg_cmd, msg_token, msg_ksid)
        packet = ''
        packet = msgHeader + Coder.num2hexstr(len(msg_body)/2+4, 4) + msg_body
        packet = TEA.entea_hexstr(packet, self.defaultKey)
        packet = self.pack_package(packet, cmd_type)
        return packet

    def assemble_request_package(self, msg_cmd, msg_body, pack_msg_body_len = True):
        msgHeader = self.make_request_header(msg_cmd)
        packet = ''
        if pack_msg_body_len:
            packet = msgHeader + Coder.num2hexstr(len(msg_body)/2+4, 4) + msg_body
        else:
            packet = msgHeader + msg_body
        packet = TEA.entea_hexstr(packet, self.defaultKey)
        packet = self.pack_package(packet, self.cmd_type_normal)
        return packet

    def qq_touch_online(self):
        msg = ''
        msg += Coder.trim('08 A2 0F 10 00 18 00 22 02 08 00')

        packet = self.assemble_package(self.qq_cmd_oidbsvc_7a20, msg, self.token004c, self.ksid, self.cmd_type_online)
        logger.info('send qq_touch_online ({})'.format(self.qq_cmd_oidbsvc_7a20))
        self.send_package(Coder.hexstr2str(packet))


    def pack_statvc_register(self, _bid, _status, _timestamp):
        svr_req = jce_SvrReg()
        svr_req.reg = jce_SvcReqRegister()
        svr_req.reg.uin = long(self.qqnum)
        svr_req.reg.bid = _bid    #7 online 0 offline
        svr_req.reg.status = _status    #11 online 21 offline
        svr_req.reg.timestamp = _timestamp    #0 online 5 offline
        svr_req.reg.conntype = 0  
        svr_req.reg.other = ''  
        svr_req.reg.onlinepush = 0  
        svr_req.reg.isonline = 0  
        svr_req.reg.isshowonline = 0  
        svr_req.reg.kikpc = 0  
        svr_req.reg.kikweak = 0  
        svr_req.reg._11 = 15
        svr_req.reg._12 = 1
        svr_req.reg._13 = ''
        svr_req.reg._14 = 0
        svr_req.reg.imei = Coder.hexstr2str(self.imei)
        svr_req.reg._17 = 2052
        svr_req.reg._18 = 0
        svr_req.reg._19_device = Coder.hexstr2str(self.device)
        svr_req.reg._20_device = Coder.hexstr2str(self.device)
        svr_req.reg._21_sys_ver = Coder.hexstr2str(self.os_version)
        
        jce_map = jce_Map()
        _t = jce_SimpleList()
        _t.value = svr_req.dumps()
        jce_map.map = {"SvcReqRegister": _t}


        jce_req = jce_RequestPacket()
        jce_req.version = 3
        jce_req.packagetype = 0
        jce_req.messagetype = 0
        jce_req.requestid = 0
        jce_req.servantname = 'PushService'
        jce_req.funcname = 'SvcReqRegister'
        jce_req.buffer = jce_map.dumps()
        jce_req.timeout = 0
        jce_req.context = {}
        jce_req.status = {}

        return Coder.str2hexstr(jce_req.dumps())

    def pack_request_data(self, _version, _request_id, _servant_name, _func_name, _map_key, _map_data):

        jce_map = jce_Map()
        _t = jce_SimpleList()
        _t.value = jce_struct_wrap(_map_data, 0)
        jce_map.map = {_map_key: _t}


        jce_req = jce_RequestPacket()
        jce_req.version = _version
        jce_req.packagetype = 0
        jce_req.messagetype = 0
        jce_req.requestid = _request_id
        jce_req.servantname = _servant_name
        jce_req.funcname = _func_name
        jce_req.buffer = jce_map.dumps()
        jce_req.timeout = 0
        jce_req.context = {}
        jce_req.status = {}

        return Coder.str2hexstr(jce_req.dumps())

    def qq_set_online(self):
        msg = self.pack_statvc_register(7, 11, 0)
        packet = self.assemble_package(self.qq_cmd_statsvc_register, msg, self.token004c, self.ksid, self.cmd_type_online)
        logger.info('send qq_set_online ({} 7, 11, 0)'.format(self.qq_cmd_statsvc_register))
        self.send_package(Coder.hexstr2str(packet))
    def qq_set_offline(self):
        msg = self.pack_statvc_register(0, 21, 5)
        packet = self.assemble_package(self.qq_cmd_statsvc_register, msg, self.token004c, self.ksid, self.cmd_type_online)
        logger.info('send qq_set_offline ({} 0, 21, 5)'.format(self.qq_cmd_statsvc_register))
        self.send_package(Coder.hexstr2str(packet))
    def qq_send_heartbeat(self):
        jce_heartbeat = jce_HeartBeat()
        jce_heartbeat.qq = long(self.qqnum)
        jce_heartbeat.hb1 = 7
        jce_heartbeat.hb2 = ''
        jce_heartbeat.hb3 = 11
        jce_heartbeat.hb4 = 0
        jce_heartbeat.hb5 = 0
        jce_heartbeat.hb6 = 0
        jce_heartbeat.hb7 = 0
        jce_heartbeat.hb8 = 0
        jce_heartbeat.hb9 = 0
        jce_heartbeat.hb10 = 0
        jce_heartbeat.hb11 = 0
        
        #msg = self.pack_request_data( 3, 1819559151, 'PushService', 'SvcReqGet', 'SvcReqGet', jce_heartbeat.dumps())
        msg = self.pack_request_data( 3, self.seq, 'PushService', 'SvcReqGet', 'SvcReqGet', jce_heartbeat.dumps())

        packet = self.assemble_request_package(self.qq_cmd_statsvc_get, msg)
        logger.info('send qq_send_heartbeat ({})@{}'.format(self.qq_cmd_statsvc_get,self.start_counter))
        self.send_package(Coder.hexstr2str(packet))


def run_qq():
    qq_info = None
    try:
        with open("qq_json.json", 'r') as f:
          qq_info = json.loads(f.read())
    except Exception,e:
        logger.info(traceback.format_exc())
    if qq_info <> None:
        online = qq_info['online']
        qq = PyQQ(qq_info[online]['qq'], qq_info[online]['pwd'], qq_info[online]['simulate'], qq_info[online]['version'])
        pass

if __name__ == '__main__':
    run_qq()
