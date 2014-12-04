#!/usr/bin/env python

from nuts import UDPAuthChannel

# Client
channel = UDPAuthChannel('secret')
with channel.connect( ('127.0.0.1', 8001) ) as session:
    session.send('Take 4 pics!')
    for i in range(4):
        img = session.receive()
        print '******************* Recieved img: %s' % img
