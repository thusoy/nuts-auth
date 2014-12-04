from nuts import DummyAuthChannel, ClientSession
from nuts.utils import ascii_bin

import unittest
import hashlib
import sha3
import six

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


class ClientHelloTest(BaseTestCase):

    def setUp(self):
        self.channel = DummyAuthChannel(self.shared_secret)
        self.session = ClientSession('source', self.shared_secret, self.channel)


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
        self.session = ClientSession('source', self.shared_secret, self.channel)
        self.session.do_client_hello()
        self.R_b = self.channel.sent_messages.pop(0).msg[2:-8]


    def get_response(self, message):
        self.session.handle(message)
        if self.channel.sent_messages:
            return self.channel.sent_messages.pop(0)


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
