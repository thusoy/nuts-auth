#!/usr/bin/env python
"""
    This is the actual satellite software, protected by the NUTS auth layer.
"""

import io
import threading
#import picamera
import time
import json


def take_single_picture():
    # Create an in-memory stream
    my_stream = io.BytesIO()
    with picamera.PiCamera() as camera:
        camera.start_preview()
        # Camera warm-up time
        time.sleep(2)
        camera.capture(my_stream, 'jpeg')
    my_stream.seek(0)
    return my_stream


def start_timelapse(number_of_pictures, seconds_between_pictures):
    timelapse_thread = threading.Thread(name='timelapse',
        target=do_timelapse,
        kwargs={
            'number_of_pictures': number_of_pictures,
            'seconds_between_pictures': seconds_between_pictures,
        })
    timelapse_thread.start()
    return json.dumps({
        'status': 'OK',
    })


def do_timelapse(number_of_pictures, seconds_between_pictures):
    with picamera.PiCamera() as camera:

        # Camera warm-up
        camera.start_preview()
        time.sleep(2)

        pictures_taken = 0
        while pictures_taken < number_of_pictures:
            pictures_taken += 1
            time.sleep(seconds_between_pictures)


from nuts import UDPAuthChannel

# Server
channel = UDPAuthChannel('secret') # How do you handle re-keying?
channel.listen( ('127.0.0.1', 8001) )
while True:
    msg = channel.receive()
    # How to terminate the session this message came over?
    print '**********************************', msg
    for i in range(4):
        channel.send('Pic %d' % i, msg.sender)
    #msg.session.terminate()?
