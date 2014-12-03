from nuts import AuthChannel

# Client
channel = AuthChannel('secret')
with channel.connect( ('127.0.0.1', 8001) ) as session:
    session.send('Take 4 pics!')
    for i in range(4):
        img = session.actual_receive()
        print 'Recieved img: %s' % img
