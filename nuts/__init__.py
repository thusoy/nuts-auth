from . import messages
from .hkdf import hkdf_expand

from collections import namedtuple
from itsdangerous import constant_time_compare
from functools import partial
import binascii
import quopri
import os
import string
import json
import hashlib
import sha3

MessageType = namedtuple('Message', ['byte', 'keyword', 'description'])


# Store messages passed back and forth for inspection
Message = namedtuple('Message', ['source', 'dest', 'msg'])
_messages = []

shared_key = shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')


def send(source, dest, msg):
    print 'Sending msg of length %d to %s: 0x%s' % (len(msg), dest, quopri.encodestring(msg))
    _messages.append( Message(source, dest, msg) )


def mac(key, msg):
    """ Create a secure MAC of the message with the key, using
    Keccak (SHA-3) 512 truncated to 64 bits.
    """
    print 'MACing 0x%s' % quopri.encodestring(msg)
    return hashlib.sha3_256(key + msg).digest()[:8]


def get_mac(mac_name, mac_len):
    """ Get the MAC function agreed upon in the SA. """
    mac_func = getattr(hashlib, mac_name)
    def _mac(key, msg):
        return mac_func(key + msg).digest()[:mac_len]
    return _mac


class NUTSAuthException(Exception):
    """ Base class for authentication-related exception in the auth channel. """


class SignatureException(NUTSAuthException):
    """ Invalid signature received. """


class AuthChannel(object):

    #: Version of the protocol supported. Client version is sent in the first
    #: CLIENT_HELLO message, if incompatible a VERSION_NOT_SUPPORTED message
    #: will be replied.
    version = 1

    #: MACs supported by this satellite/server. Used in the SA negotiation.
    supported_macs = [
        'sha3_512',
        'sha3_384',
        'sha3_256',
    ]

    def __init__(self, id_a, shared_key):
        """ Create a new auth channel context to keep around. """
        self.id_a = id_a
        self.shared_key = shared_key
        self.sessions = {}


    def receive(self, message):
        """ Handle incoming message on the channel. """
        if not message.dest == self.id_a:
            print 'Received message intended for someone else, ignoring...'
            return
        if message.source in self.sessions:
            session = self.sessions.get(message.source)
        else:
            session = Session(self.id_a, message.source, self.shared_key)
            self.sessions[message.source] = session
        return session.handle(message.msg)


class Session(object):
    """ A connection between a given satellite and groundstation. """

    def __init__(self, id_a, id_b, shared_key):
        self.id_a = id_a
        self.id_b = id_b
        self.shared_key = shared_key

        # Setup self.handlers dict
        self.handlers = {}
        for message_name in dir(messages):
            if message_name.startswith('_') or message_name[0] in string.ascii_lowercase:
                # Built-in, skip
                continue
            message = getattr(messages, message_name)
            server_is_destination = ord(message.byte) >> 7 == 0
            if not server_is_destination:
                continue
            handler_name = 'respond_to_' + message_name.lower()
            handler = getattr(self, handler_name)
            if not handler:
                raise ValueError('Connection implementation does not support messages of type 0x%s' % binascii.hexlify(message.byte))
            print 'Adding handler for 0x%s: %s' % (binascii.hexlify(message.byte), handler_name)
            self.handlers[message.byte] = handler


    def handle(self, message):
        """ Message has been received from client. It's assumed here that the link layer
        has filtered out messages not intended for us, or that has bit-errors.
        """
        msg_type_byte = message[0]
        handler = self.handlers.get(msg_type_byte, self.not_implemented)
        return handler(message[1:])


    def not_implemented(self, message):
        send(self.id_a, self.id_b, messages.MESSAGE_TYPE_NOT_SUPPORTED.byte)


    def respond_to_client_hello(self, message):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        self.R_a = self.rng(8)
        self.R_b = message[:8]

        # Verify incoming MAC
        expected_mac = self.mac(message[:8])
        if not constant_time_compare(expected_mac, message[8:]):
            incorrect_mac_message = messages.INVALID_MAC_FROM_CLIENT.byte
            incorrect_mac_message += self.mac(incorrect_mac_message)
            send(self.id_a, self.id_b, incorrect_mac_message)
            return

        msg = messages.SERVER_HELLO.byte + self.R_a
        h = self.mac(msg + self.R_b)
        msg = msg + h
        send(self.id_a, self.id_b, msg)


    def respond_to_invalid_mac_from_server(self, message):
        """ I seem to have sent an invalid MAC. This is weird. """
        print 'Invalid mac sent by server, no idea what just happened'


    def mac(self, mac_input):
        """ Shortcut for `mac(self.shared_key, self.id_a, self.id_b, mac_input)."""
        return mac(self.shared_key, self.id_a + self.id_b + mac_input)


    def respond_to_client_terminate(self, message):
        pass


    def respond_to_sa_proposal(self, message):
        pass


    def rng(self, num_bytes):
        """ Read `num_bytes` from the RNG. """
        if os.path.exists('/dev/hwrng'):
            with open('/dev/hwrng', 'r') as hwrng:
                return hwrng.read(num_bytes)
        else:
            return os.urandom(8)


    def challenge_reply_received(self, response):
        """ Response received from id_b, that is H_k(id_a, id_b, R_a, a). """
        self.session_key = hkdf_expand(shared_key + self.R_a + self.R_b, length=16)
        send(self.id_b, b'Go ahead' + mac(self.session_key, 'Go ahead'))


    def sa_proposal_received(self, response):
        msg, sig = response[:-8], response[-8:]
        if not constant_time_compare(mac(self.session_key, msg), sig):
            raise SignatureException()

        msg_data = json.loads(msg)
        suggested_macs = set(msg_data.get('macs', []))
        for supported_mac in Connection.supported_macs:
            if supported_mac in suggested_macs:
                selected_mac = supported_mac
                break
        else:
            raise "No MACs in common, aborting"
        suggested_mac_len = msg_data.get('mac_len', 8)
        try:
            suggested_mac_len = int(suggested_mac_len)
        except ValueError:
            raise ValueError("Suggested mac_len not an integer, was %s" % suggested_mac_len)
        if not (8 <= suggested_mac_len <= 32):
            raise ValueError("suggested mac outside permitted range of 8-32 bytes")
        # All jolly good, notify id_b of chosen MAC and signature length
        response = {
            'mac': selected_mac,
            'mac_len': suggested_mac_len,
        }
        self.sa_mac_len = suggested_mac_len
        response_msg = json.dumps(response)
        mac_func = get_mac(selected_mac, suggested_mac_len)
        self.mac = partial(mac_func, self.session_key)
        send(self.id_b, response_msg + self.mac(response_msg))


    def respond_to_message_type_not_supported(self, message):
        pass


    def respond_to_command(self, full_message):
        """Signed, operational command received. Verify signature and return message."""
        msg, sig = full_message[:-self.sa_mac_len], full_message[-self.sa_mac_len:]
        if not constant_time_compare(msg, self.mac(msg)):
            raise SignatureException()
