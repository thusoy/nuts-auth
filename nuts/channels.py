from . import AuthenticatedMessage
from .enums import ServerState
from .utils import ascii_bin
from .sessions import ClientSession, ServerSession

from contextlib import contextmanager
import socket

class AuthChannel(object):
    """ Generic, transport-agnostic authenticated channel. Needs to be overridden by class
    implementing `receive` and `listen`.
    """

    #: MACs supported by this satellite/server. Used in the SA negotiation, should be ordered
    #: by preference (strength).
    supported_macs = [
        'sha3_512',
        'sha3_384',
        'sha3_256',
        'hmac-sha1',
        'hmac-sha256',
    ]


    def __init__(self, shared_key):
        """ Create a new auth channel context to keep around. """
        self.shared_key = shared_key
        self.sessions = {}
        self._messages = []


    def receive(self):
        while not self._messages:
            print('Listening...')
            data, sender = self.read_data()
            message = AuthenticatedMessage(sender, data)
            self.handle_message(message)
        return self._messages.pop(0)


    @contextmanager
    def connect(self, address):
        session = ClientSession(address, self)
        session.connect()

        # Session setup complete, let client use the session
        yield session

        # Send terminate
        print('Terminating session...')
        session.terminate()


    def _send(self, data, address):
        self.send_data(data, address)


    def send(self, data, address):
        """ Externally exposed interface for sending data. """
        session = self.sessions[address]
        session.send(data)


    def handle_message(self, message):
        """ Handle incoming message on the channel. """
        if message.sender in self.sessions:
            session = self.sessions.get(message.sender)
        else:
            session = ServerSession(message.sender, self)
            self.sessions[message.sender] = session
        session.handle(message.msg)
        if session.state == ServerState.inactive:
            print('Terminating session with %s' % str(message.sender))
            del self.sessions[message.sender]
        elif session.state == ServerState.rekey_confirmed:
            print('Rekey confirmed, new master key in place, invalidating all existing sessions..')
            self.sessions = {}
            print('Session invalidated, shared key updated')
            self.shared_key = session.shared_key


class UDPAuthChannel(AuthChannel):

    def __init__(self, *args, **kwargs):
        super(UDPAuthChannel, self).__init__(*args, **kwargs)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)


    def listen(self, address):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(address)
            print('Bound to %s:%s' % address)
        except Exception as e:
            print(e)
            raise


    def send_data(self, data, address):
        print('Sending %s to %s' % (ascii_bin(data), address))
        self.sock.sendto(data, address)
        print("I'm now %s" % (self.sock.getsockname(),))


    def read_data(self):
        data, sender = self.sock.recvfrom(1024)
        print('Received data: %s from %s' % (ascii_bin(data), sender))
        return data, sender


class DummyAuthChannel(AuthChannel):
    """ Only return stuff locally, probably only useful for testing. """

    def __init__(self, *args, **kwargs):
        super(DummyAuthChannel, self).__init__(*args, **kwargs)
        self.sent_messages = []
        self.messages_to_receive = []


    def send_data(self, data, address):
        print('Sending data %s to %s' % (ascii_bin(data), address))
        self.sent_messages.append(AuthenticatedMessage(address, data))


    def read_data(self):
        """ Return pre-filled replies, or None. """
        if self.messages_to_receive:
            return self.messages_to_receive.pop(0)
