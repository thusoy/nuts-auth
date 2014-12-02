from __future__ import print_function

from . import messages
from .hkdf import HKDF
from .utils import ascii_bin, decode_version, encode_version
from .varint import encode_varint, decode_varint

from collections import namedtuple
from itsdangerous import constant_time_compare
from enum import Enum
from functools import partial
from nacl.c import crypto_scalarmult
from nacl.public import PrivateKey
import msgpack
import binascii
import hashlib
import os
import sha3
import six
import string


# The main message class that the AuthChannel operate on
Message = namedtuple('Message', ['source', 'msg'])


class ServerState(Enum):
    inactive = 1
    wait_for_sa_proposal = 2
    established = 3
    rekey = 4
    rekey_confirmed = 5


def send(dest, msg):
    print('Sending msg of length %d to %s: %s' % (len(msg), dest, ascii_bin(msg)))
    msg = Message(dest, msg)
    return msg


class AuthChannel(object):

    #: MACs supported by this satellite/server. Used in the SA negotiation, should be ordered
    #: by preference (strength).
    supported_macs = [
        b'sha3_512',
        b'sha3_384',
        b'sha3_256',
        b'hmac-sha1',
        b'hmac-sha256',
    ]

    def __init__(self, shared_key, app=None):
        """ Create a new auth channel context to keep around. """
        self.shared_key = shared_key
        self.sessions = {}
        self.app = app


    def set_app(self, app):
        self.app = app

        # Update app for all existing sessions
        for session in self.sessions.values():
            session.set_app(app)


    def receive(self, message):
        """ Handle incoming message on the channel. """
        if message.source in self.sessions:
            session = self.sessions.get(message.source)
        else:
            session = Session(message.source, self.shared_key, self.app)
            self.sessions[message.source] = session
        response = session.handle(message.msg)
        if session.state == ServerState.inactive:
            print('Terminating session with %s' % message.source)
            del self.sessions[message.source]
        if session.state == ServerState.rekey_confirmed:
            print('Rekey confirmed, new master key in place, invalidating all existing sessions..')
            self.sessions = {}
            print('Session invalidated, shared key updated')
            self.shared_key = session.shared_key
        return response


class Session(object):
    """ A connection between a given satellite and groundstation. """

    #: Version of the protocol supported. Client version is sent in the first
    #: CLIENT_HELLO message, if incompatible a VERSION_NOT_SUPPORTED message
    #: will be replied.
    version = b'1.0'

    def __init__(self, id_b, shared_key, app):
        self.id_b = id_b
        self.shared_key = shared_key
        self.state = ServerState.inactive
        self.app = app

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
            self.handlers[six.byte2int(message.byte)] = handler


    def set_app(self, app):
        self.app = app


    def handle(self, message):
        """ Message has been received from client. It's assumed here that the link layer
        has filtered out messages not intended for us, or that has bit-errors.

        Call the correct handler with the first byte of the message stripped.
        """
        msg_type_byte = six.byte2int(message)
        transition_map = {
            ServerState.inactive: [six.byte2int(messages.CLIENT_HELLO.byte)],
            ServerState.wait_for_sa_proposal: [six.byte2int(messages.SA_PROPOSAL.byte)],
            ServerState.established: [
                six.byte2int(messages.COMMAND.byte),
                six.byte2int(messages.REKEY.byte),
                six.byte2int(messages.CLIENT_TERMINATE.byte),
            ],
            ServerState.rekey: [six.byte2int(messages.REKEY_CONFIRM.byte)],
        }


        # Filter out messages sent that's not valid in the current state
        valid_types = transition_map.get(self.state, [])
        if not msg_type_byte in valid_types:
            print('Invalid state transition')
            return

        handler = self.handlers[msg_type_byte]
        return handler(message[1:])


    def verify_mac(self, message, **kwargs):
        mac_len = getattr(self, 'sa_mac_len', 8)
        expected_mac = self.get_mac(message[:-mac_len])
        mac = message[-mac_len:]
        return constant_time_compare(mac, expected_mac)


    def respond_to_client_hello(self, message):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        # Verify that incoming packet has correct length
        if not len(b'\x00' + message) == 18:
            return

        # Verify incoming MAC
        if not self.verify_mac(b'\x00' + message, algo='sha3_256', length=8):
            return

        # Check that version is supported
        client_version = decode_version(message[:1])
        if not client_version == self.version:
            # reply with supported version, and copy of client's message
            return self.send(messages.VERSION_NOT_SUPPORTED.byte +
                encode_version(self.version) +
                message[:-8])


        self.R_a = self.rng(8)
        self.R_b = message[1:9]

        msg = messages.SERVER_HELLO.byte + self.R_a
        mac = self.get_mac(msg, self.R_b)
        self.state = ServerState.wait_for_sa_proposal
        return self.send(msg + mac)


    def send(self, message):
        return send(self.id_b, message)


    def get_mac(self, *args, **kwargs):
        mac_len = getattr(self, 'sa_mac_len', 8)
        key = kwargs.get('key', getattr(self, 'session_key', self.shared_key))
        mac = getattr(self, 'sa_mac', 'sha3_256')
        mac_input = b''.join(args)
        print('MACing %s (%d) with key %s (%d)' % (ascii_bin(mac_input),
            len(mac_input), ascii_bin(key), len(key)))
        hash_func = getattr(hashlib, mac)
        #return mac(key, , algo=mac_func, mac_len=mac_len)
        return hash_func(key + mac_input).digest()[:mac_len]


    def respond_to_client_terminate(self, message):
        self.state = ServerState.inactive
        raise NotImplemented()


    def respond_to_sa_proposal(self, message):
        # Verify length
        if not 8 <= len(message) <= 255:
            print('Invalid length', len(message))
            return

        # Verify MAC
        msg, sig = message[:-8], message[-8:]
        expected_mac = self.get_mac(b'\x01', msg, self.R_a)
        if not constant_time_compare(sig, expected_mac):
            print('Invalid mac on sa proposal')
            return

        msg_data = {}

        # Verify msgpacked data is valid (has 'macs' which is a list)
        if msg:
            try:
                msg_data = msgpack.loads(msg)
            except ValueError:
                return

        # Verify that key 'macs' is a list
        if not isinstance(msg_data.get(b'macs', []), list):
            print('Not list')
            return

        # Merge client parameters with defaults
        suggested_macs = set([b'sha3_256'] + msg_data.get(b'macs', []))

        # Pick the first MAC from supported_macs that's supported by both parties
        selected_mac = b'sha3_256'
        for supported_mac in AuthChannel.supported_macs:
            if supported_mac in suggested_macs:
                selected_mac = supported_mac
                break

        # Verify that suggested MAC length is valid int
        suggested_mac_len = msg_data.get(b'mac_len', 8)
        if not isinstance(suggested_mac_len, int):
            print('mac_len not int')
            return
        if not 4 <= suggested_mac_len <= 32:
            print("suggested mac_len outside permitted range of 4-32 bytes")
            return

        # All jolly good, notify client of chosen MAC and signature length

        # Expand session key
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_key).expand(self.version, length=16)

        sa = {
            'mac': selected_mac,
            'mac_len': suggested_mac_len,
        }
        response = messages.SA.byte + msgpack.dumps(sa)
        response = self.send(response + self.get_mac(response))

        self.sa_mac = selected_mac.decode('ascii')
        self.sa_mac_len = suggested_mac_len

        # Initialize sequence numbers
        self.c_seq = self.s_seq = 0

        self.state = ServerState.established

        return response


    def respond_to_rekey(self, message):
        # Verify length
        if not len(message) == 32 + self.sa_mac_len:
            print('Invalid length of rekey')
            return

        # Verify MAC
        msg, sig = message[:-self.sa_mac_len], message[-self.sa_mac_len:]
        if not self.verify_mac(b'\x03' + message):
            print('Invalid MAC on rekey')
            return

        client_pubkey = msg
        pkey = PrivateKey.generate()
        self.new_master_key = crypto_scalarmult(pkey._private_key, client_pubkey)
        msg = messages.REKEY_RESPONSE.byte + pkey.public_key._public_key
        self.state = ServerState.rekey
        return self.send(msg + self.get_mac(msg))


    def respond_to_rekey_confirm(self, message):
        # Verify length
        if not len(message) == self.sa_mac_len:
            print('Invalid length of rekey confirm')
            return

        # Verify MAC
        msg, sent_mac = message[:-self.sa_mac_len], message[-self.sa_mac_len:]
        expected_mac = self.get_mac(b'\x04', key=self.new_master_key)
        if not constant_time_compare(sent_mac, expected_mac):
            print('Invalid MAC of rekey confirm')
            return

        # Update shared_key
        self.shared_key = self.new_master_key
        msg = messages.REKEY_COMPLETED.byte
        self.state = ServerState.rekey_confirmed
        return self.send(msg + self.get_mac(msg, key=self.shared_key))


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
        # Verify length
        if not self.sa_mac_len <= len(message) <= 2**16:
            print('Invalid length of message, was %s' % len(message))
            return

        # Verify MAC
        msg, sig = message[:-self.sa_mac_len], message[-self.sa_mac_len:]
        if not self.verify_mac(b'\x02' + message):
            print('Invalid mac')
            return

        # Verify sequence number
        seqnum_bytes = []
        for byte in six.iterbytes(msg):
            seqnum_bytes.append(byte)
            if byte >> 7 == 0:
                break
        client_seqnum = decode_varint(seqnum_bytes)
        if not client_seqnum == self.c_seq:
            print('Not expected sequence number, expected %d, was %d' % (self.c_seq, client_seqnum))
            # TODO: If future sequence number, either store it or deliver it to app immediately,
            # depending on config
            return

        # Check that we have an app to receive the message
        if not hasattr(self, 'app') or not self.app:
            print('No app set to receive messages')
            return

        # Increase expected sequence number
        self.c_seq += 1

        # Deliver the message
        try:
            # TODO: Test that this is correctly received by the app
            reply = self.app.got_message(msg[len(seqnum_bytes):])
        except:
            print('App crashed when receiving message..')
            return

        # Send reply from app if one was given
        if reply:
            msg = messages.REPLY.byte + encode_varint(self.s_seq) + reply
            self.s_seq += 1
            return self.send(msg + self.get_mac(msg))
