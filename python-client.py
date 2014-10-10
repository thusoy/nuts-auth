#!/usr/bin/env python

import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(sys.argv[1], ('127.0.0.1', 9999))

# Listen for response
response, addr = sock.recvfrom(1024)
print 'Got response:'
print response
