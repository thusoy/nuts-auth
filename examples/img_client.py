#!/usr/bin/env python
"""
    This example demonstrates a client fetching images from a server running img_server.py.

    The first packet contains the number of chunks to expect, and then that number of chunks is read.
    Lost packets are not handled in any way.

"""

from nuts import UDPAuthChannel

channel = UDPAuthChannel('secret') # Re-key handling? Load key from file, or mutable struct?
with channel.connect( ('10.0.0.1', 8001) ) as session:
    session.send('Take pic!')
    msg = session.receive()
    num_chunks = int(msg)
    with open('latest_img.jpg', 'wb') as img_fh:
        for i in range(num_chunks):
            chunk = session.receive()
            print('got chunk %d of %d' % (i + 1, num_chunks))
            img_fh.write(chunk)
