# -*- coding: utf-8 -*-  
  
import socket
import ssdp
  
SERVICE_NAME = 'pyqq_service'  
  
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
  
    def start(self):  
        while True:  
            data, addr = self.__s.recvfrom(2048)  
            conn = ssdp.Connection(SERVICE_NAME, self.__s, data, addr)  
            conn.handle_request()  
        self.__s.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP,  
                            socket.inet_aton(ssdp.SSDP_ADDR) + socket.inet_aton(self.local_ip))  
        self.__s.close()  
  
if __name__ == '__main__':  
    port = SSDPServer()  
    port.start()  