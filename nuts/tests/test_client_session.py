from nuts import DummyAuthChannel, ClientSession, ClientState
from nuts.hkdf import HKDF
from nuts.utils import ascii_bin

import unittest
import hashlib
import sha3
import six
import cbor

def handshake_mac(*args):
    print('Test MACing %s (%d) with key %s (%d)' % (
        ascii_bin(b''.join(args[1:])),
        len(b''.join(args[1:])),
        args[0],
        len(args[0])))
    return hashlib.sha3_256(b''.join(args)).digest()[:8]


class BaseTestCase(unittest.TestCase):

    shared_secret = b'secret'

    def assert_message_type(self, response, expected_type):
        self.assertEqual(six.byte2int(response), expected_type)


    def get_response(self, message):
        self.session.handle(message)
        if self.channel.sent_messages:
            return self.channel.sent_messages.pop(0)


class ClientHelloTest(BaseTestCase):

    def setUp(self):
        self.channel = DummyAuthChannel(self.shared_secret)
        self.session = ClientSession('source', self.channel)


    def test_client_hello(self):
        self.session.do_client_hello()
        response = self.channel.sent_messages.pop(0).msg
        self.assert_message_type(response, 0x00)
        self.assertEqual(len(response), 18)
        expected_mac = handshake_mac(self.shared_secret, response[:-8])
        self.assertEqual(response[-8:], expected_mac)


class ServerHelloTest(BaseTestCase):

    def setUp(self):
        self.channel = DummyAuthChannel(self.shared_secret)
        self.session = ClientSession('source', self.channel)
        self.session.do_client_hello()
        self.R_b = self.channel.sent_messages.pop(0).msg[2:-8]


    def test_response_to_valid_server_hello(self):
        msg = b'\x80' + b'\x00'*8
        mac = handshake_mac(self.shared_secret, msg, self.R_b)
        response = self.get_response(msg + mac).msg
        self.assert_message_type(response, 0x01)
        expected_mac = handshake_mac(self.shared_secret, response[:-8], b'\x00'*8)
        self.assertEqual(response[-8:], expected_mac)


    def test_server_hello_invalid_length(self):
        msg = b'\x80'
        mac = handshake_mac(self.shared_secret, msg, self.R_b)
        response = self.get_response(msg + mac)
        self.assertIsNone(response)


    def test_server_hello_invalid_mac(self):
        msg = b'\x80' + b'\x00'*16
        response = self.get_response(msg)
        self.assertIsNone(response)


class SATest(BaseTestCase):

    def setUp(self):
        self.channel = DummyAuthChannel(self.shared_secret)
        self.session = ClientSession('source', self.channel)
        self.session.do_client_hello()
        self.R_b = self.channel.sent_messages.pop(0).msg[2:-8]
        server_hello = b'\x80' + b'\x00'*8
        server_hello_mac = handshake_mac(self.shared_secret, server_hello, self.R_b)
        self.session_key = HKDF(b'\x00'*8 + self.R_b, self.shared_secret).expand(info=b'1.0', length=16)
        self.session.handle(server_hello + server_hello_mac)
        self.channel.sent_messages.pop(0)


    def test_response_to_valid_sa(self):
        msg = b'\x81' + cbor.dumps({'mac': 'sha3_256', 'mac_len': 8})
        mac = handshake_mac(self.session_key, msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 0)
        self.assertEqual(self.session.state, ClientState.established)


    def test_sa_invalid_mac(self):
        msg = b'\x81' + cbor.dumps({'mac': 'sha3_256', 'mac_len': 8}) + b'\x00'*8
        self.session.handle(msg)
        self.assertEqual(self.session.state, ClientState.wait_for_sa)


    def test_sa_invalid_cbor_data(self):
        test_data = [
            b'',
            b'\x00',
            cbor.dumps({}),
            cbor.dumps([]),
            cbor.dumps({'mac': 'foobar'}),
            cbor.dumps({'mac_len': -1}),
            cbor.dumps({'mac': 'invalid', 'mac_len': 8})
        ]
        for data in test_data:
            msg = b'\x81' + data
            mac = handshake_mac(self.session_key, msg)
            self.session.handle(msg + mac)
            self.assertEqual(self.session.state, ClientState.wait_for_sa)




#class ReplyTest(BaseTestCase):
#
#    def setUp(self):
#        self.channel = DummyAuthChannel(self.shared_secret)
#        self.session = ClientSession('source', self.channel)
#        self.session.do_client_hello()
#        R_b = self.channel.sent_messages.pop(0).msg[2:-8]
#        server_hello = b'\x80' + b'\x00'*8
#        server_hello_mac = handshake_mac(self.shared_secret, server_hello, R_b)
#        self.session.handle(server_hello + server_hello_mac)
#        self.channel.sent_messages.pop(0)
#        sa = b'\x81' + cbor.dumps({'mac': 'sha3_256', 'mac_len': 8})
#        self.session_key = HKDF(b'\x00'*8 + R_b, self.shared_secret).expand(info=b'1.0', length=16)
#        sa_mac = handshake_mac(self.session_key, sa)
#        self.session.handle(sa + sa_mac)
#        self.channel.sent_messages.pop(0)
#
#
#    def test_server_message(self):
#        msg = b'\x82\x00' + b'Hello, earthling'
#        self.session.handle(msg)
#        self.assertEqual(self.session.s_seq,)
