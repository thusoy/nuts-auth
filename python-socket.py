#!/usr/bin/env python

from __future__ import print_function

import SocketServer

class CamServer(SocketServer.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("Received message from {}:".format(self.client_address[0]))
        print(data)
        socket.sendto(data.upper(), self.client_address)


if __name__ == "__main__":
    HOST, PORT = "", 9999
    print('Listening on %s:%d' % (HOST, PORT))
    server = SocketServer.UDPServer((HOST, PORT), CamServer)
    server.serve_forever()
