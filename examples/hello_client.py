#!/usr/bin/env python
"""
    This is a simple "Hello, world" test, client sends a "Hello, space!"
    message to the server, which replies with a "Hello, world!" message.
"""

from nuts import UDPAuthChannel

channel = UDPAuthChannel('secret')
with channel.connect( ('10.0.0.1', 8001) ) as session:
    session.send('Hello, space!')
    msg = session.receive()
    print('%s says: %s' % (msg.sender, msg))
