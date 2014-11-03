from . import AuthChannel, Message

import socket

class NUTSServer(object):

    def __init__(self, ip, port, shared_key):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = ip
        self.port = port
        self.id = '%s:%d' % (self.ip, self.port)
        self.auth_channel = AuthChannel(self.id, shared_key)


    def start(self):
        print 'Listening on %s:%d' % (self.ip, self.port)
        self.socket.bind( (self.ip, self.port) )
        try:
            while True:
                data, addr = self.socket.recvfrom(10240)
                if data:
                    print 'Data received from %s:%d' % addr
                    reply = self.auth_channel.receive(Message('%s:%d' % addr, self.id, data))
                    if reply:
                        print 'Answering...'
                        self.socket.sendto(reply.msg, addr)
        finally:
            self.socket.close()
