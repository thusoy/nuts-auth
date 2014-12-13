from __future__ import unicode_literals

from . import AuthenticatedMessage, NutsMessageTooLarge, NutsInvalidState
from .enums import ClientState, ServerState, Message
from .hkdf import HKDF
from .utils import ascii_bin, decode_version, encode_version, rng, encode_varint, decode_varint

from enum import Enum, IntEnum
from functools import partial
from itsdangerous import constant_time_compare
from logging import getLogger
from nacl.c import crypto_scalarmult
from nacl.public import PrivateKey
import cbor
import hashlib
import os
import sha3
import six
import socket
import string
import sys


_logger = getLogger('nuts.session')


def handshake_mac(*args):
    _logger.debug('Client handshake MACing %s (%d) with key %s (%d)' % (
        ascii_bin(b''.join(args[1:])),
        len(b''.join(args[1:])),
        ascii_bin(args[0]),
        len(args[0])))
    return hashlib.sha3_256(b''.join(args)).digest()[:8]


class Session(object):

    version = b'1.0'
    #: Maxiumum length of the sequence numbers. Used both for sanity checks of
    #: incoming data and calculatino of max MTU
    max_seqnum_length = 4

    def generate_and_set_session_key(self):
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_key).expand(self.version, length=16)


    def handle(self, message):
        """ Message has been received from sender. It's assumed here that the link layer
        has filtered out messages not intended for us, or that has bit-errors.
        """
        if not message:
            return
        msg_type_byte = six.byte2int(message)
        valid_transitions = self.transition_map.get(self.state, [])
        if not msg_type_byte in valid_transitions:
            # Ignore
            _logger.info('Ignoring invalid transition')
            return

        handler = self.handlers.get(msg_type_byte)
        _logger.debug('Handling data %s' % ascii_bin(message))
        handler(message)


    def extract_message_data(self, data):
        """ Strips type, sequence numbers and MAC and returns the upper-layer protocol data. """
        seqnum_bytes = 0
        for byte in six.iterbytes(data[1:]):
            seqnum_bytes += 1
            if byte >> 7 == 0:
                break
        return data[1+seqnum_bytes:-self._mac_length]


    def validate_and_update_others_seqnum(self, data):
        seqnum_bytes = []
        for byte in six.iterbytes(data[1:]):
            seqnum_bytes.append(byte)
            if len(seqnum_bytes) > self.max_seqnum_length:
                return False
            if byte >> 7 == 0:
                break
        seqnum = decode_varint(seqnum_bytes)
        valid = seqnum >= self.other_seq
        if valid:
            self.other_seq = seqnum + 1
        return valid


    def init_session_mac(self, key, func_name, length):
        func = getattr(hashlib, func_name)
        self._mac_key = key
        self._mac_func = func
        self._mac_length = length
        _logger.info('Mac set to %s (%d)', func_name, length)


    def get_mac(self, *args, **kwargs):
        key = kwargs.get('key') or self._mac_key
        _logger.debug('Client MACing %s ', ascii_bin(b''.join(args)))
        return self._mac_func(key + b''.join(args)).digest()[:self._mac_length]


    def verify_mac(self, message):
        expected_mac = self.get_mac(message[:-self._mac_length])
        return constant_time_compare(message[-self._mac_length:], expected_mac)


    def send(self, data):
        """ Called from AuthChannel when it needs to send data through this
        session, or from the client-side application. This method adds type,
        sequence number and MAC.

        Throws a NutsInvalidState if the session is not established.
        """
        if not self.state in (ClientState.established, ServerState.established):
            raise NutsInvalidState("Session needs to be established to be able"
                " to send data, call .connect(address) first (was %s)" % self.state)
        if self.mtu and len(data) > self.mtu:
            raise NutsMessageTooLarge('Message of %d bytes is too long to be '
                'sent through this session, maximum size supported is %d '
                'bytes.' % (len(data), self.mtu))
        msg = six.int2byte(self.outgoing_command) + encode_varint(self.my_seq) + data
        self._send(msg + self.get_mac(msg))
        self.my_seq += 1


    @property
    def mtu(self):
        """ Get the maximum transmission unit (MTU) for this session. Returns
        None if there's no upper limit, or the maximum size in bytes.

        The MTU is calculated as the MTU of the channel minus the overhead of
        the session.
        """
        if self.channel.mtu:
            session_overhead = 1 + self._mac_length + self.max_seqnum_length
            session_mtu = self.channel.mtu - session_overhead
            return session_mtu


    def derive_shared_key(self, other_party_pubkey):
        return crypto_scalarmult(self.pkey._private_key, other_party_pubkey)


class ClientSession(Session):

    outgoing_command = Message.command


    def __init__(self, id_a, channel):
        self.id_a = id_a
        self.shared_key = channel.shared_key
        self.channel = channel
        self._messages = []
        self.state = ClientState.inactive

        self.handlers = {
            Message.server_hello: self.respond_to_server_hello,
            Message.sa: self.respond_to_sa,
            Message.reply: self.respond_to_server_message,
            Message.server_terminate: self.respond_to_server_terminate,
            Message.rekey_response: self.respond_to_rekey_response,
            Message.rekey_completed: self.respond_to_rekey_completed,
        }
        self.transition_map = {
            ClientState.wait_for_server_hello: [Message.server_hello],
            ClientState.wait_for_sa: [Message.sa],
            ClientState.established: [Message.reply, Message.server_terminate],
            ClientState.rekey: [Message.rekey_response],
            ClientState.wait_for_rekey_complete: [Message.rekey_completed],
        }


    def connect(self):
        self.do_client_hello()
        while self.state != ClientState.established:
            data, sender = self.channel.read_data()
            if sender != self.id_a:
                continue
            self.handle(data)
            _logger.debug('State is now %s' % self.state)


    def respond_to_sa(self, data):
        # Verify MAC
        expected_mac = handshake_mac(self.session_key, data[:-8])
        if not data[-8:] == expected_mac:
            _logger.info('Invalid MAC on SA')
            return

        # Verify that the cbored data has both 'mac' and 'mac_len' set to valid values
        try:
            sa = cbor.loads(data[1:-8])
            if not isinstance(sa, dict):
                _logger.info('SA not a dict')
                return
        except:
            _logger.info('Decoding cbored data from SA failed')
            return
        if not ('mac' in sa and 'mac_len' in sa):
            _logger.info('SA missing mac and/or mac_len')
            return
        if not isinstance(sa['mac'], six.string_types):
            _logger.info('SA mac not a string')
            return
        if not isinstance(sa['mac_len'], six.integer_types):
            _logger.info('mac_len not an int')
            return
        if not 4 <= sa['mac_len'] <= 32:
            _logger.info('mac_len outside range of 4-32 bytes')
            return
        if not sa['mac'] in self.channel.supported_macs:
            _logger.info('mac %s not supported by this client', sa['mac'])
            return

        self.init_session_mac(key=self.session_key, func_name=sa['mac'], length=sa['mac_len'])
        self.other_seq = self.my_seq = 0
        self.state = ClientState.established
        _logger.info('Session established')


    def rekey(self):
        self.send_rekey()
        while self.state != ClientState.terminated:
            data, sender = self.channel.read_data()
            if sender != self.id_a:
                continue
            self.handle(data)
        # Initialize new session with the same session object
        self.shared_key = self.channel.shared_key
        self.connect()


    def send_rekey(self):
        self.pkey = PrivateKey.generate()
        msg = six.int2byte(Message.rekey) + encode_varint(self.my_seq) + self.pkey.public_key._public_key
        mac = self.get_mac(msg)
        self.my_seq += 1
        self._send(msg + mac)
        self.state = ClientState.rekey


    def respond_to_rekey_response(self, data):
        # Verify length
        if len(data) != 33 + len(encode_varint(self.other_seq)) + self._mac_length:
            _logger.info('Invalid length of rekey response, was %d', len(data))
            return

        # Verify MAC
        if not self.verify_mac(data):
            _logger.info('Invalid MAC on rekey response')
            return

        # Verify seqnum
        if not self.validate_and_update_others_seqnum(data):
            _logger.info('Invalid sequence number on rekey response')
            return

        # Compute new shared key
        server_pubkey = data[2:-self._mac_length]
        self.new_master_key = self.derive_shared_key(server_pubkey)
        msg = six.int2byte(Message.rekey_confirm)
        mac = self.get_mac(msg, key=self.new_master_key)
        self._send(msg + mac)
        self.my_seq += 1
        self.state = ClientState.wait_for_rekey_complete


    def respond_to_rekey_completed(self, data):
        # Verify length
        if len(data) != 1 + self._mac_length:
            _logger.info('Invalid length of rekey completed, was %d', len(data))
            return

        # Verify MAC
        expected_mac = self.get_mac(data[:-self._mac_length], key=self.new_master_key)
        if not constant_time_compare(data[-self._mac_length:], expected_mac):
            _logger.info('Invalid MAC on rekey completed')
            return

        self.channel.shared_key = self.new_master_key
        self.state = ClientState.terminated
        del self.new_master_key
        del self.pkey


    def respond_to_server_message(self, message):
        # Verify length (type + minimum 1 byte of seqnum + mac)
        if not self._mac_length + 2 <= len(message) <= 2**16:
            _logger.info('Invalid length of reply (was %d)', len(message))
            return

        # Verify MAC
        if not self.verify_mac(message):
            _logger.info('Invalid MAC on reply')
            return

        # Verify sequence number
        if not self.validate_and_update_others_seqnum(message):
            _logger.info('Not expected sequence number, expected %d', self.other_seq)
            # TODO: If future sequence number, either store it or deliver it to app immediately,
            # depending on config
            return

        data = self.extract_message_data(message)
        self.deliver(data)
        _logger.debug('Message added to _messages: %s' % self._messages)


    def deliver(self, data):
        self._messages.append(AuthenticatedMessage(self.id_a, data, self))


    def respond_to_server_terminate(self, message):
        raise NotImplemented()


    def receive(self):
        """ Exposed to consumer to get incoming messages. """
        while not self._messages:
            data, sender = self.channel.read_data()
            if sender != self.id_a:
                continue
            self.handle(data)
        return self._messages.pop(0)



    def do_client_hello(self):
        self.R_b = rng(8)
        msg = six.int2byte(Message.client_hello) + encode_version(self.version) + self.R_b
        mac = handshake_mac(self.shared_key, msg)
        self._send(msg + mac)
        self.state = ClientState.wait_for_server_hello


    def respond_to_server_hello(self, data):
        # Verify length
        if not len(data) == 17:
            _logger.info('Invalid length of SERVER_HELLO')
            return

        # Verify MAC
        expected_mac = handshake_mac(self.shared_key, data[:-8], self.R_b)
        if not constant_time_compare(data[-8:], expected_mac):
            _logger.info('Invalid mac on SERVER_HELLO')
            return

        self.R_a = data[1:-8]
        sa_msg = six.int2byte(Message.sa_proposal)
        self.generate_and_set_session_key()
        sa_mac = handshake_mac(self.shared_key, sa_msg, self.R_a)
        self._send(sa_msg + sa_mac)
        self.state = ClientState.wait_for_sa


    def terminate(self):
        msg = six.int2byte(Message.client_terminate) + encode_varint(self.my_seq)
        mac = self.get_mac(msg)
        self._send(msg + mac)
        self.my_seq += 1


    def _send(self, data):
        """ Internal only, sends the data just as given. """
        self.channel._send(data, self.id_a)


class ServerSession(Session):
    """ A connection between a given satellite and groundstation. """

    outgoing_command = Message.reply

    def __init__(self, id_b, channel):
        _logger.info('Creating new session with %s...', id_b)
        self.id_b = id_b
        self.shared_key = channel.shared_key
        self.state = ServerState.inactive
        self.channel = channel

        # Setup self.handlers dict
        self.handlers = {
            Message.client_hello: self.respond_to_client_hello,
            Message.sa_proposal: self.respond_to_sa_proposal,
            Message.command: self.respond_to_command,
            Message.rekey: self.respond_to_rekey,
            Message.rekey_confirm: self.respond_to_rekey_confirm,
            Message.client_terminate: self.respond_to_client_terminate,
        }
        self.transition_map = {
            ServerState.inactive: [Message.client_hello],
            ServerState.wait_for_sa_proposal: [Message.sa_proposal],
            ServerState.established: [
                Message.command,
                Message.rekey,
                Message.client_terminate,
            ],
            ServerState.rekey: [Message.rekey_confirm],
        }


    def _send(self, data):
        self.channel._send(data, self.id_b)


    def deliver(self, message):
        self.channel._messages.append(AuthenticatedMessage(self.id_b, message, self))


    def respond_to_client_hello(self, message):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        # Verify that incoming packet has correct length
        if not len(message) == 18:
            _logger.info('Wrong length of client hello')
            return

        # Verify incoming MAC
        expected_mac = handshake_mac(self.shared_key, message[:-8])
        if not constant_time_compare(message[-8:], expected_mac):
            _logger.info('Incorrect mac for client hello')
            return

        # Check that version is supported
        client_version = decode_version(message[1:2])
        if not client_version == self.version:
            # reply with supported version, and copy of client's message
            _logger.info('Unsupported version of client hello')
            msg = (six.int2byte(Message.version_not_supported) +
                encode_version(self.version) +
                message[2:10])
            mac = handshake_mac(self.shared_key, msg)
            self._send(msg + mac)
            return

        self.R_a = rng(8)
        self.R_b = message[2:10]

        msg = six.int2byte(Message.server_hello) + self.R_a
        mac = handshake_mac(self.shared_key, msg, self.R_b)
        self.state = ServerState.wait_for_sa_proposal
        self._send(msg + mac)


    def respond_to_client_terminate(self, message):
        # Verify length
        if len(message) != 2 + self._mac_length:
            _logger.info('Invalid length of client terminate')
            return

        # Verify MAC
        if not self.verify_mac(message):
            _logger.info('Invalid MAC on client termiante')
            return

        # Verify sequence number
        if not self.validate_and_update_others_seqnum(message):
            _logger.info('Invalid sequence number on client terminate')
            return

        self.state = ServerState.inactive
        msg = six.int2byte(Message.server_terminate)
        mac = self.get_mac(msg)
        self._send(msg + mac)


    def respond_to_sa_proposal(self, message):
        # Verify length
        if not 9 <= len(message) <= 255:
            _logger.info('Invalid length %d', len(message))
            return

        # Verify MAC
        msg, sig = message[:-8], message[-8:]
        expected_mac = handshake_mac(self.shared_key, msg, self.R_a)
        if not constant_time_compare(sig, expected_mac):
            _logger.info('Invalid mac on sa proposal')
            return

        msg_data = {}

        # Verify cbor data is valid (has 'macs' which is a list)
        if msg[1:]:
            try:
                msg_data = cbor.loads(msg[1:])
            except:
                _logger.info('Invalid cbor data given in sa proposal')
                return

        # Verify that the data loaded is a dict
        if not isinstance(msg_data, dict):
            _logger.info('SA proposal not a dict')
            return

        # Verify that key 'macs' is a list
        if not isinstance(msg_data.get('macs', []), list):
            _logger.info('macs given was not a list')
            return

        # Merge client parameters with defaults
        suggested_macs = set(['sha3_256'] + msg_data.get('macs', []))

        # Pick the first MAC from supported_macs that's supported by both parties
        selected_mac = 'sha3_256'
        for supported_mac in self.channel.supported_macs:
            if supported_mac in suggested_macs:
                selected_mac = supported_mac
                break

        # Verify that suggested MAC length is valid int
        suggested_mac_len = msg_data.get('mac_len', 8)
        if not isinstance(suggested_mac_len, six.integer_types):
            _logger.info('mac_len not int: %s', type(suggested_mac_len))
            return
        if not 4 <= suggested_mac_len <= 32:
            _logger.info("suggested mac_len outside permitted range of 4-32 bytes")
            return

        # All jolly good, notify client of chosen MAC and signature length

        # Expand session key
        self.generate_and_set_session_key()

        sa = {
            'mac': selected_mac,
            'mac_len': suggested_mac_len,
        }
        msg = six.int2byte(Message.sa) + cbor.dumps(sa)
        mac = handshake_mac(self.session_key, msg)
        self.init_session_mac(key=self.session_key, func_name=sa['mac'], length=sa['mac_len'])
        self._send(msg + mac)

        # Initialize sequence numbers
        self.other_seq = self.my_seq = 0

        self.state = ServerState.established


    def respond_to_rekey(self, message):
        # Verify length
        if not len(message) == 34 + self._mac_length:
            _logger.info('Invalid length of rekey')
            # TODO: Multi-byte asequence numbers should also be allowed
            return

        # Verify MAC
        msg, sig = message[:-self._mac_length], message[-self._mac_length:]
        if not self.verify_mac(message):
            _logger.info('Invalid MAC on rekey')
            return

        # Verify sequence number
        if not self.validate_and_update_others_seqnum(msg):
            _logger.info('Invalid sequence number on rekey')
            return

        client_pubkey = msg[2:]
        self.pkey = PrivateKey.generate()
        self.new_master_key = self.derive_shared_key(client_pubkey)
        msg = six.int2byte(Message.rekey_response) + encode_varint(self.my_seq) + self.pkey.public_key._public_key
        self.state = ServerState.rekey
        full_msg = msg + self.get_mac(msg)
        self._send(full_msg)
        self.my_seq += 1


    def respond_to_rekey_confirm(self, message):
        # Verify length
        if not len(message) == self._mac_length + 1:
            _logger.info('Invalid length of rekey confirm')
            return

        # Verify MAC
        msg, sent_mac = message[:-self._mac_length], message[-self._mac_length:]
        expected_mac = self.get_mac(msg, key=self.new_master_key)
        if not constant_time_compare(sent_mac, expected_mac):
            _logger.info('Invalid MAC of rekey confirm')
            return

        # Update shared_key
        self.shared_key = self.new_master_key
        msg = six.int2byte(Message.rekey_completed)
        self.state = ServerState.rekey_confirmed
        full_msg = msg + self.get_mac(msg, key=self.shared_key)
        self._send(full_msg)
        del self.new_master_key
        del self.pkey


    def respond_to_message_type_not_supported(self, message):
        raise NotImplemented()


    def respond_to_command(self, message):
        """Signed, operational command received. Verify signature and return message."""
        # Verify length
        if not self._mac_length + 1 <= len(message) <= 2**16:
            _logger.info('Invalid length of message, was %d', len(message))
            return

        # Verify MAC
        msg, sig = message[:-self._mac_length], message[-self._mac_length:]
        if not self.verify_mac(message):
            _logger.info('Invalid mac on command')
            return

        # Verify sequence number
        if not self.validate_and_update_others_seqnum(message):
            _logger.info('Not expected sequence number, expected %d', self.other_seq)
            # TODO: If future sequence number, either store it or deliver it to app immediately,
            # depending on config
            return

        # Strip seqnum
        msg = self.extract_message_data(message)
        self.deliver(msg)
