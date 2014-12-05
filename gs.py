#!/usr/bin/env python

from nuts import UDPAuthChannel
from nuts.utils import ascii_bin

# Client
channel = UDPAuthChannel('secret') # Re-key handling? Load key from file, or mutable struct?
with channel.connect( ('127.0.0.1', 8001) ) as session:
    session.send('Take 4 pics!')
    for i in range(4):
        msg = session.receive()
        print '******************* Received img: %s' % msg.msg
    session.rekey()
    print 'New shared key:', ascii_bin(session.shared_key)
