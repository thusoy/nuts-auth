#!/usr/bin/env python
"""
    This is the actual satellite software, protected by the NUTS auth layer.
"""

from nuts import UDPAuthChannel

channel = UDPAuthChannel('secret')
channel.listen( ('127.0.0.1', 8001) )
while True:
    msg = channel.receive()
    print('%s said: %s' % (msg.sender, msg))
    channel.send('Hello, world!', msg.sender)
