# -*- coding: utf-8 -*-  
  
import socket  
import time  
import select  
import ssdp  

SERVICE_NAME = 'pyqq_service' 

MS = 'M-SEARCH * HTTP/1.1\r\nHOST: %s:%d\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' \
     % (ssdp.SSDP_ADDR, ssdp.SSDP_PORT)  
  
  
class SSDPClient():  
    def __init__(self):  
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
                    break  
            else:  # timeout  
                self.__send_search()  
        self.__s.close()  
  
    def __send_search(self):  
        print "Sending M-SEARCH..."  
        # INFO: 发送到SSDP组播地址上  
        self.__s.sendto(MS, (ssdp.SSDP_ADDR, ssdp.SSDP_PORT))  
  
if __name__ == '__main__':  
    port = SSDPClient()  
    port.start()  