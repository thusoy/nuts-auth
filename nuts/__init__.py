from __future__ import print_function

from .hkdf import HKDF
from .utils import ascii_bin, decode_version, encode_version, rng
from .varint import encode_varint, decode_varint

from collections import namedtuple
from contextlib import contextmanager
from itsdangerous import constant_time_compare
from enum import Enum, IntEnum
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
import socket
import sys


# The main message class that the AuthChannel operate on
AuthenticatedMessage = namedtuple('Message', ['sender', 'msg'])

def handshake_mac(*args):
    return hashlib.sha3_256(b''.join(args)).digest()[:8]


class ServerState(Enum):
    inactive = 1
    wait_for_sa_proposal = 2
    established = 3
    rekey = 4
    rekey_confirmed = 5


class ClientState(Enum):
    wait_for_server_hello = 1
    wait_for_sa = 2
    established = 3
    rekey = 4


class Message(IntEnum):

    # Client messages

    #: First message from client, with challenge to server and protocol version.
    client_hello = 0x00
    #: Security association suggested by client.
    sa_proposal = 0x01
    #: Command from client.
    command = 0x02
    #: Generate new master key
    rekey = 0x03
    #: Confirm successful re-key by signing a random nonce with the new key
    rekey_confirm = 0x04
    #: Client is terminating the session.
    client_terminate = 0x0f

    # Server messages

    #: First response from server, responds to client challenge and challenges client
    server_hello = 0x80
    #: Negotiated security association from server.
    sa = 0x81
    #: Reply to command issued by client.
    reply = 0x82
    #: Respond to re-key command with satellites public key
    rekey_response = 0x83
    #: Complete the re-keying by invalidating all existing sessions
    rekey_completed = 0x84
    #: Version suggested by client is not supported by server.
    version_not_supported = 0x83
    #: Message type received from client is not supported by server.
    message_type_not_supported = 0x84
    #: Server is terminating the session.
    server_terminate = 0x8f



class NutsConnectionError(Exception):
    """ Something failed in the communication. """


class AuthChannel(object):
    """ Generic, transport-agnostic authenticated channel. Needs to be overridden by class
    implementing `receive` and `listen`.
    """

    #: MACs supported by this satellite/server. Used in the SA negotiation, should be ordered
    #: by preference (strength).
    supported_macs = [
        b'sha3_512',
        b'sha3_384',
        b'sha3_256',
        b'hmac-sha1',
        b'hmac-sha256',
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
        session = ClientSession(address, self.shared_key, self)
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
            session = Session(message.sender, self.shared_key, self)
            self.sessions[message.sender] = session
        response = session.handle(message.msg)
        if session.state == ServerState.inactive:
            print('Terminating session with %s' % str(message.sender))
            del self.sessions[message.sender]
        elif session.state == ServerState.rekey_confirmed:
            print('Rekey confirmed, new master key in place, invalidating all existing sessions..')
            self.sessions = {}
            print('Session invalidated, shared key updated')
            self.shared_key = session.shared_key
        if response:
            msg = AuthenticatedMessage(message.sender, response)
            self._messages.append(msg)
            return msg


class ClientSession(object):

    def __init__(self, id_a, shared_key, channel):
        self.id_a = id_a
        self.shared_key = shared_key
        self.channel = channel
        self._messages = []

        self.handlers = {
            Message.server_hello: self.do_sa_proposal,
            Message.sa: self.establish,
            Message.reply: self.respond_to_server_message,
            Message.server_terminate: self.respond_to_server_terminate,
        }


    def init_session_mac(self, key, func_name, length):
        func = getattr(hashlib, func_name)
        self._mac_key = key
        self._mac_func = func
        self._mac_length = length


    def get_mac(self, *args):
        print('MACing %s ' % ascii_bin(b''.join(args)))
        return self._mac_func(self._mac_key + b''.join(args)).digest()[:self._mac_length]


    def connect(self):
        self.do_client_hello()
        while self.state != ClientState.established:
            data, sender = self.channel.read_data()
            if sender != self.id_a:
                continue
            self.handle(data)
            print('State is now %s' % self.state)
        print('State is now %s' % self.state)


    def establish(self, data):
        print('Handling SA')
        expected_mac = handshake_mac(self.session_key, data[:-8])
        if not data[-8:] == expected_mac:
            raise NutsConnectionError('Invalid MAC on SA')

        sa = msgpack.loads(data[1:-8])
        self.init_session_mac(key=self.session_key, func_name=sa['mac'], length=sa['mac_len'])
        self.s_seq = self.c_seq = 0
        self.state = ClientState.established
        print('Session established')


    def verify_mac(self, message):
        expected_mac = self.get_mac(message[:-self._mac_length])
        return constant_time_compare(message[-self._mac_length:], expected_mac)


    def respond_to_server_message(self, message):
        # Verify length
        if not self._mac_length + 1 <= len(message) <= 2**16:
            print('Invalid length of reply')
            return

        # Verify MAC
        if not self.verify_mac(message):
            print('Invalid MAC on reply')

        # Verify sequence number
        seqnum_bytes = []
        for byte in six.iterbytes(message[1:]):
            seqnum_bytes.append(byte)
            if byte >> 7 == 0:
                break
        server_seqnum = decode_varint(seqnum_bytes)
        if not server_seqnum == self.s_seq:
            print('Not expected sequence number, expected %d, was %d' % (self.s_seq, server_seqnum))
            # TODO: If future sequence number, either store it or deliver it to app immediately,
            # depending on config
            return

        self.s_seq += 1

        data = message[1+len(seqnum_bytes):-self._mac_length]
        self._messages.append(data)


    def respond_to_server_terminate(self, message):
        raise NotImplemented()


    def receive(self):
        while not self._messages:
            data, sender = self.channel.read_data()
            if sender != self.id_a:
                continue
            self.handle(data)
        return self._messages.pop(0)


    def handle(self, message):
        msg_type_byte = six.byte2int(message)
        transition_map = {
            ClientState.wait_for_server_hello: [Message.server_hello],
            ClientState.wait_for_sa: [Message.sa],
            ClientState.established: [Message.reply, Message.server_terminate],
        }
        valid_transitions = transition_map.get(self.state, [])
        if not msg_type_byte in valid_transitions:
            # Ignore
            print('Ignoring invalid transition')
            return

        handler = self.handlers.get(msg_type_byte)
        handler(message)


    def do_client_hello(self):
        self.R_b = rng(8)
        msg = Message.client_hello + encode_version(b'1.0') + self.R_b
        mac = handshake_mac(self.shared_key, msg)
        self._send(msg + mac)
        self.state = ClientState.wait_for_server_hello


    def do_sa_proposal(self, data):
        print('Handling SERVER HELLO')
        print(ascii_bin(data))

        expected_mac = handshake_mac(self.shared_key, data[:-8], self.R_b)
        if not data[-8:] == expected_mac:
            raise NutsConnectionError('Invalid mac received from server, terminating...')
        self.R_a = data[1:-8]
        sa_msg = Message.sa_proposal
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_key).expand(info=b'1.0', length=16)
        print('Session key: %s' % ascii_bin(self.session_key))
        sa_mac = handshake_mac(self.shared_key, sa_msg, self.R_a)
        self._send(sa_msg + sa_mac)
        self.state = ClientState.wait_for_sa



    def terminate(self):
        terminate_msg = Message.client_terminate
        terminate_mac = self.get_mac(terminate_msg)
        self.send(terminate_msg + terminate_mac)


    def _send(self, data):
        """ Internal only, sends the data just as given. """
        self.channel._send(data, self.id_a)


    def send(self, data):
        """ Exposed externally to consumers. """
        msg = six.int2byte(Message.command) + encode_varint(self.c_seq) + data
        self._send(msg + self.get_mac(msg))
        self.c_seq += 1



class Session(object):
    """ A connection between a given satellite and groundstation. """

    #: Version of the protocol supported. Client version is sent in the first
    #: CLIENT_HELLO message, if incompatible a VERSION_NOT_SUPPORTED message
    #: will be replied.
    version = b'1.0'

    def __init__(self, id_b, shared_key, channel):
        print('Creating new session with %s...' % (id_b,))
        self.id_b = id_b
        self.shared_key = shared_key
        self.state = ServerState.inactive
        self.channel = channel

        #: A queue of messages received that haven't been consumed yet
        self._messages = []

        # Setup self.handlers dict
        self.handlers = {
            Message.client_hello: self.respond_to_client_hello,
            Message.sa_proposal: self.respond_to_sa_proposal,
            Message.command: self.respond_to_command,
            Message.rekey: self.respond_to_rekey,
            Message.rekey_confirm: self.respond_to_rekey_confirm,
            Message.client_terminate: self.respond_to_client_terminate,
        }


    def handle(self, message):
        """ Message has been received from client. It's assumed here that the link layer
        has filtered out messages not intended for us, or that has bit-errors.

        Call the correct handler with the first byte of the message stripped.
        """
        msg_type_byte = six.byte2int(message)
        transition_map = {
            ServerState.inactive: [Message.client_hello],
            ServerState.wait_for_sa_proposal: [Message.sa_proposal],
            ServerState.established: [
                Message.command,
                Message.rekey,
                Message.client_terminate,
            ],
            ServerState.rekey: [Message.rekey_confirm],
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
            print('Wrong length of client hello')
            return

        # Verify incoming MAC
        if not self.verify_mac(b'\x00' + message, algo='sha3_256', length=8):
            print('Incorrect mac for client hello')
            return

        # Check that version is supported
        client_version = decode_version(message[:1])
        if not client_version == self.version:
            # reply with supported version, and copy of client's message
            print('Unsupported version of client hello')
            msg = (six.int2byte(Message.version_not_supported) +
                encode_version(self.version) +
                message[:-8])
            msg_with_mac = msg + self.get_mac(msg)
            self._send(msg_with_mac)
            return msg_with_mac


        self.R_a = rng(8)
        self.R_b = message[1:9]

        msg = six.int2byte(Message.server_hello) + self.R_a
        mac = self.get_mac(msg, self.R_b)
        self.state = ServerState.wait_for_sa_proposal
        self._send(msg + mac)
        return msg + mac


    def _send(self, data):
        self.channel._send(data, self.id_b)


    def send(self, data):
        """ Called from AuthChannel when it needs to send data through this session. This method adds type,
        sequence number and MAC.
        """
        msg = six.int2byte(Message.reply) + encode_varint(self.s_seq) + data
        self._send(msg + self.get_mac(msg))
        self.s_seq += 1


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
        print('Session key: %s' % ascii_bin(self.session_key))

        sa = {
            'mac': selected_mac,
            'mac_len': suggested_mac_len,
        }
        response = six.int2byte(Message.sa) + msgpack.dumps(sa)
        msg = response + self.get_mac(response)
        self._send(msg)

        self.sa_mac = selected_mac.decode('ascii')
        self.sa_mac_len = suggested_mac_len

        # Initialize sequence numbers
        self.c_seq = self.s_seq = 0

        self.state = ServerState.established
        return msg


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

        # TODO: Needs to have verifiable seqnum to prevent DoS due to repeating the rekey msg

        client_pubkey = msg
        pkey = PrivateKey.generate()
        self.new_master_key = crypto_scalarmult(pkey._private_key, client_pubkey)
        msg = six.int2byte(Message.rekey_response) + pkey.public_key._public_key
        self.state = ServerState.rekey
        full_msg = msg + self.get_mac(msg)
        self._send(full_msg)
        return full_msg


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
        msg = six.int2byte(Message.rekey_completed)
        self.state = ServerState.rekey_confirmed
        full_msg = msg + self.get_mac(msg, key=self.shared_key)
        self._send(full_msg)
        return full_msg


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
            print('Invalid mac on command')
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

        # Increase expected sequence number
        self.c_seq += 1

        # Strip seqnum
        msg = msg[len(seqnum_bytes):]
        self._send(msg)


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


    def read_data(self, *args):
        data, sender = self.sock.recvfrom(1024)
        print('Received data: %s from %s' % (ascii_bin(data), sender))
        return data, sender


class DummyAuthChannel(AuthChannel):
    """ Only return stuff locally, probably only useful for testing. """

    def send_data(self, data, address):
        print('Sending data %s to %s' % (ascii_bin(data), address))

