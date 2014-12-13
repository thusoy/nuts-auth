#!/usr/bin/env python
"""
    This example demonstrates a client fetching images from a server running img_server.py.

    The first packet contains the number of chunks to expect, and then that number of chunks is read.
    Lost packets are not handled in any way.

"""

from nuts import UDPAuthChannel

channel = UDPAuthChannel('keyfile', timeout=4)
with channel.connect( ('10.0.0.1', 8001) ) as session:
    session.send('Take pic!')
    msg = session.receive()
    num_chunks = int(msg)
    with open('latest_img.jpg', 'wb') as img_fh:
        for i in range(num_chunks):
            chunk = session.receive()
            print('got chunk %d of %d' % (i + 1, num_chunks))
            # Preferably, the msg received would support the buffer interface
            # and be writable directly, but it isn't
            img_fh.write(chunk.msg)
