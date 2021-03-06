#!/usr/bin/env python
"""
    This is the actual satellite software, protected by the NUTS auth layer.
"""

from nuts import UDPAuthChannel

channel = UDPAuthChannel('keyfile')
channel.listen( ('', 8001) )
while True:
    msg = channel.receive()
    print('%s said: %s' % (msg.sender, msg))
    channel.send('Hello, world!', msg.sender)
