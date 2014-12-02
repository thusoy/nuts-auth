from . import messages
from .hkdf import hkdf_expand

from collections import namedtuple
from itsdangerous import constant_time_compare
from functools import partial
import msgpack
import binascii
import quopri
import os
import string
import hashlib
import sha3


# Store messages passed back and forth for inspection
Message = namedtuple('Message', ['source', 'msg'])
#class Message(object):
#
#    def __init__(self, source, raw_msg):
#        self.raw_msg = raw_msg
#        self.source = source

_messages = []
_packer = msgpack.Packer(use_bin_type=True)
_unpacker = msgpack.Unpacker()

def ascii_bin(binstr):
    return repr(quopri.encodestring(binstr))


def encode_version(version):
    """ Takes a versino like '1.0' or '2.1' and encodes it into a single byte. """
    major, minor = map(int, version.split('.'))
    if not (0 < major < 16 and 0 <= minor < 16):
        raise ValueError("Can't encode version %s, major or minor version outside range(0, 16)" % version)
    return chr(major << 4 | minor)


def decode_version(version):
    """ Takes a byte version and decodes it into human-readable <major>.<minor> format. """
    if len(version) != 1:
        raise ValueError('%s is an invalid version specifier.' % version)
    major = ord(version) >> 4
    minor = ord(version) & 15
    return '%d.%d' % (major, minor)


def send(dest, msg):
    print 'Sending msg of length %d to %s: %s' % (len(msg), dest, ascii_bin(msg))
    msg = Message(dest, msg)
    _messages.append(msg)
    return msg


def mac(key, msg, algo='sha3_256', mac_len=8):
    """ Create a secure MAC of the message with the key, using
    Keccak (SHA-3) 256 truncated to 64 bits.
    """
    print 'MACing %s with key %s (%d)' % (repr(quopri.encodestring(msg)), repr(quopri.encodestring(key)), len(key))
    hash_func = getattr(hashlib, algo)
    return hash_func(key + msg).digest()[:mac_len]


class NUTSAuthException(Exception):
    """ Base class for authentication-related exception in the auth channel. """


class SignatureException(NUTSAuthException):
    """ Invalid signature received. """


class AuthChannel(object):

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


    def receive(self, message):
        """ Handle incoming message on the channel. """
        if message.source in self.sessions:
            session = self.sessions.get(message.source)
        else:
            session = Session(message.source, self.shared_key)
            self.sessions[message.source] = session
        response = session.handle(message.msg)
        if session.terminate:
            print 'Terminating session with %s' % message.source
            del self.sessions[message.source]
        return response


class Session(object):
    """ A connection between a given satellite and groundstation. """

    #: Version of the protocol supported. Client version is sent in the first
    #: CLIENT_HELLO message, if incompatible a VERSION_NOT_SUPPORTED message
    #: will be replied.
    version = '1.0'

    def __init__(self, id_b, shared_key):
        self.id_b = id_b
        self.shared_key = shared_key
        self.terminate = False

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
        self.terminate = True
        return self.send(messages.MESSAGE_TYPE_NOT_SUPPORTED.byte)


    def respond_to_client_hello(self, message):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        # Verify that incoming packet has correct length
        if not len('\x00' + message) == 18:
            return

        # Verify incoming MAC
        expected_mac = self.mac('\x00' + message[:-8])
        if not constant_time_compare(expected_mac, message[-8:]):
            return

        # Check that version is supported
        client_version = decode_version(message[0])
        if not client_version == self.version:
            # reply with supported version, and copy of client's message
            return self.send(messages.VERSION_NOT_SUPPORTED.byte +
                encode_version(self.version) +
                message[:-8])


        self.R_a = self.rng(8)
        self.R_b = message[1:9]

        msg = messages.SERVER_HELLO.byte + self.R_a
        h = self.mac(msg + self.R_b)
        msg = msg + h
        return self.send(msg)


    def send(self, message):
        return send(self.id_b, message)


    def mac(self, mac_input):
        """ Shortcut for `mac(self.shared_key, self.id_a, self.id_b, mac_input)."""
        mac_len = getattr(self, 'sa_mac_len', 8)
        key = getattr(self, 'session_key', self.shared_key)
        mac_func = getattr(self, 'sa_mac', 'sha3_256')
        return mac(key, mac_input, algo=mac_func, mac_len=mac_len)


    def respond_to_client_terminate(self, message):
        self.terminate = True
        raise NotImplemented()


    def respond_to_sa_proposal(self, message):
        msg, sig = message[:-8], message[-8:]
        if not constant_time_compare(self.mac('\x01' + msg + self.R_a), sig):
            raise SignatureException()

        msg_data = _unpacker.unpack(msg)
        suggested_macs = set(msg_data.get('macs', []))
        # Pick the first MAC from supported_macs that's supported by both parties
        for supported_mac in AuthChannel.supported_macs:
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
        response_msg = '\x81' + _packer.pack(response)
        response = self.send(response_msg + self.mac(response_msg + self.R_a + self.R_b))
        self.sa_mac_len = suggested_mac_len
        self.sa_mac = selected_mac

        # Expand session key
        self.session_key = hkdf_expand(self.shared_key + self.R_a + self.R_b, length=16)

        # Initialize sequence numbers
        self.c_seq = self.s_seq = 1

        return response


    def respond_to_rekey(self, message):
        raise NotImplemented()


    def respond_to_rekey_confirm(self, message):
        raise NotImplemented()


    def rng(self, num_bytes):
        """ Read `num_bytes` from the RNG. """
        if os.path.exists('/dev/hwrng'):
            with open('/dev/hwrng', 'r') as hwrng:
                return hwrng.read(num_bytes)
        else:
            return os.urandom(8)


    def respond_to_message_type_not_supported(self, message):
        raise NotImplemented()


    def respond_to_command(self, message):
        """Signed, operational command received. Verify signature and return message."""
        msg, sig = message[:-self.sa_mac_len], message[-self.sa_mac_len:]
        if not constant_time_compare(sig, self.mac('\x02' + msg + str(self.c_seq))):
            raise SignatureException()

        # Perform command and send response
        #send(self)
