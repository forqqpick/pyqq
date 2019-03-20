# -*- coding: utf-8 -*-  
  
import sys
import socket
import logging

SSDP_ADDR = '239.255.255.250'  
SSDP_PORT = 1900  

def get_local_ip():
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

class Connection():  
    def __init__(self, svr_name, s, data, addr, logger = None):
        self.__svr_name = svr_name
        self.__s = s  
        self.__data = data  
        self.__addr = addr  
        self.is_find_service = False
        self.ssdp_server = None
        self.logger = logger
  
    def set_logger(self, logger):
        self.logger = logger

    def handle_request(self):  
        if self.__data.startswith('M-SEARCH * HTTP/1.1\r\n'):  
            self.__handle_search()  
        elif self.__data.startswith('HTTP/1.1 200 OK\r\n'):  
            self.__handle_ok()  
  
    def __handle_search(self):  
        props = self.__parse_props(['HOST', 'MAN', 'ST', 'MX'])  
        if not props:  
            return  
  
        if props['HOST'] != '%s:%d' % (SSDP_ADDR, SSDP_PORT) \
                or props['MAN'] != '"ssdp:discover"' \
                or props['ST'] != 'ssdp:all':  
            return  
  
        if self.logger:
            self.logger.info('RECV: %s' % str(self.__data))
            self.logger.info('ADDR: %s' % str(self.__addr))
  
        response = 'HTTP/1.1 200 OK\r\nST: %s\r\n\r\n' % self.__svr_name  
        self.__s.sendto(response, self.__addr)  
  
    def __handle_ok(self):  
        props = self.__parse_props(['ST'])  
        if not props:  
            return  
  
        if props['ST'] != self.__svr_name:  
            return  
        if self.logger:
            self.logger.info('RECV: %s' % str(self.__data))
            self.logger.info('ADDR: %s' % str(self.__addr))
            self.logger.info('Find service!!!!')
        self.ssdp_server = self.__addr
  
        self.is_find_service = True  
  
    def __parse_props(self, target_keys):  
        lines = self.__data.split('\r\n')  
  
        props = {}  
        for i in range(1, len(lines)):  
            if not lines[i]:  
                continue  
  
            index = lines[i].find(':')  
            if index == -1:  
                return None  
  
            props[lines[i][:index]] = lines[i][index + 1:].strip()  
  
        if not set(target_keys).issubset(set(props.keys())):  
            return None  
  
        return props  
