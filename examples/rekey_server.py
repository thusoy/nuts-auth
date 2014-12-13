#/usr/bin/env python
"""
    This example demonstrates how re-keying works.
"""

from nuts import UDPAuthChannel
from nuts.utils import ascii_bin

channel = UDPAuthChannel('keyfile')
channel.listen( ('', 8001) )
while True:
    channel.receive()
    print('My shared key is now: %s' % ascii_bin(msg))
