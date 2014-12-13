#!/usr/bin/env python
"""
    This example implements a server taking a single image when receiving a message from the client.

    The image will be fragmented into chunks. The first packet sent contains the number of chunks to expect.
"""

import io
import picamera
import time
from nuts import UDPAuthChannel


def take_single_picture():
    # Create an in-memory stream
    my_stream = io.BytesIO()
    with picamera.PiCamera() as camera:
        camera.start_preview()
        # Camera warm-up time
        time.sleep(2)
        camera.capture(my_stream, 'jpeg')
    my_stream.seek(0)
    return my_stream.getvalue()


def ceildiv(dividend, divisor):
    return (dividend + divisor - 1) // divisor


channel = UDPAuthChannel('secret')
channel.listen( ('10.0.0.1', 8001) )
while True:
    msg = channel.receive()
    print('%s said: %s' % (msg.sender, msg))
    img = take_single_picture()
    num_chunks = ceildiv(len(img), msg.session.mtu)
    channel.send(str(num_chunks), msg.sender)
    for i in range(num_chunks):
        chunk = img[i*msg.session.mtu:(i+1)*msg.session.mtu]
        print('Sending chunk %d of %d' % (i, num_chunks))
        channel.send(chunk, msg.sender)
        time.sleep(0.1)
