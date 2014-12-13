#/usr/bin/env python
"""
    This example demonstrates how re-keying works.
"""

from nuts import UDPAuthChannel
from nuts.utils import ascii_bin

channel = UDPAuthChannel('keyfile')
with channel.connect( ('10.0.0.1', 8001) ) as session:
    session.rekey()
    print('New shared secret: %s' % ascii_bin(session.shared_key))
