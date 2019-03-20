#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

import socket
import select
import sys

import ssdp  

SERVICE_NAME = 'pyqq_service' 

MS = 'M-SEARCH * HTTP/1.1\r\nHOST: %s:%d\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' \
     % (ssdp.SSDP_ADDR, ssdp.SSDP_PORT)  

#send_mixmsg self, 653643010, -1, 2981112017, -1, '[fid xyx]'

if 0 == 1:
    _data = 'qq_get_group_list 0, " ds "'
    _data = 'qq_get_group_list 5,9,"hello"'
    m = re.findall(r"([^ ]+) ?(.*)?", _data)
    if m: 
        _method_name = m[0][0]
        _method_params = m[0][1].strip()
        print _method_name
        print _method_params


class SSDPClient():  
    def __init__(self):  
        self.ssdp_server = None
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
  
        # INFO: 若绑定，服务端收到的是固定的地址和端口号  
        self.__s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        local_ip = ssdp.get_local_ip()
        self.__s.bind((local_ip, 50000))  
  
    def start(self):  
        self.__send_search()  
        while True:  
            reads, _, _ = select.select([self.__s], [], [], 5)  
            if reads:  
                data, addr = self.__s.recvfrom(2048)  
                conn = ssdp.Connection(SERVICE_NAME, self.__s, data, addr)  
                conn.handle_request()  
                if conn.is_find_service:  
                    self.ssdp_server = conn.ssdp_server
                    break  
            else:  # timeout  
                self.__send_search()  
        self.__s.close()  
  
    def __send_search(self):  
        print "Sending M-SEARCH..."  
        sys.stdout.flush()
        # INFO: 发送到SSDP组播地址上  
        self.__s.sendto(MS, (ssdp.SSDP_ADDR, ssdp.SSDP_PORT))  


port = SSDPClient()  
port.start()  

print 'pyqq_ssdp_server : ' , port.ssdp_server
sys.stdout.flush()
HOST = port.ssdp_server[0]  
PORT = 8888  
BUFSIZE = 1024  
  
ADDR = (HOST, PORT)  
  
udpCliSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
  
while True:  
    data = raw_input('>')  
    if not data:  
        break  
    udpCliSock.sendto(data,ADDR)  
  
udpCliSock.close() 