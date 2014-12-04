from nuts import ClientState
from nuts.channels import DummyAuthChannel
from nuts.hkdf import HKDF
from nuts.sessions import ClientSession
from nuts.utils import ascii_bin

import cbor
import hashlib
import sha3
import six
import unittest
from nacl.c import crypto_scalarmult
from nacl.public import PrivateKey

def handshake_mac(*args):
    print('Test MACing %s (%d) with key %s (%d)' % (
        ascii_bin(b''.join(args[1:])),
        len(b''.join(args[1:])),
        ascii_bin(args[0]),
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
            # invalid data
            b'',
            b'\xff',
            # wrong type
            cbor.dumps([]),
            # missing parameters
            cbor.dumps({}),
            cbor.dumps({'mac': 'sha3_256'}),
            cbor.dumps({'mac_len': 8}),
            # invalid mac
            cbor.dumps({'mac': 'foobar', 'mac_len': 8}),
            cbor.dumps({'mac': -1, 'mac_len': 8}),
            # invalid mac_len
            cbor.dumps({'mac_len': 'foobar', 'mac': 'sha3_256'}),
            cbor.dumps({'mac_len': -1, 'mac': 'sha3_256'}),
        ]
        for data in test_data:
            msg = b'\x81' + data
            mac = handshake_mac(self.session_key, msg)
            self.session.handle(msg + mac)
            self.assertEqual(self.session.state, ClientState.wait_for_sa)


class EstablishedSessionTestCase(BaseTestCase):

    def setUp(self):
        self.channel = DummyAuthChannel(self.shared_secret)
        self.session = ClientSession('source', self.channel)
        self.session.do_client_hello()
        R_b = self.channel.sent_messages.pop(0).msg[2:-8]
        server_hello = b'\x80' + b'\x00'*8
        server_hello_mac = handshake_mac(self.shared_secret, server_hello, R_b)
        self.session.handle(server_hello + server_hello_mac)
        self.channel.sent_messages.pop(0)
        sa = b'\x81' + cbor.dumps({'mac': 'sha3_256', 'mac_len': 8})
        self.session_key = HKDF(b'\x00'*8 + R_b, self.shared_secret).expand(info=b'1.0', length=16)
        sa_mac = handshake_mac(self.session_key, sa)
        self.session.handle(sa + sa_mac)


    def get_mac(self, data):
        return hashlib.sha3_256(self.session_key + data).digest()[:8]


class ReplyTest(EstablishedSessionTestCase):

    def test_server_message(self):
        msg = b'\x82\x00' + b'Hello, earthling'
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 1)

        msg = b'\x82\x01' + b'Hello, again'
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 2)


    def test_server_message_invalid_mac(self):
        msg = b'\x82\x00' + b'\x00'*8
        self.session.handle(msg)
        self.assertEqual(self.session.s_seq, 0)


    def test_server_message_replay(self):
        msg = b'\x82\x00' + b'Hello, earthling'
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 1)


    def test_server_message_invalid_length(self):
        # Missing seqnum
        msg = b'\x82'
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 0)


class RekeyTest(EstablishedSessionTestCase):

    def test_sends_valid_rekey_message(self):
        self.session.send_rekey()
        rekey_msg = self.channel.sent_messages.pop(0).msg
        self.assert_message_type(rekey_msg, 0x03)
        self.assertEqual(len(rekey_msg), 42)
        # Sequence number should be 0
        self.assertEqual(six.byte2int(rekey_msg[1:]), 0x00)
        expected_mac = self.get_mac(rekey_msg[:-8])
        self.assertEqual(rekey_msg[-8:], expected_mac)


    @unittest.skip('Skip until we can run a full client vs. server UDP test')
    def test_rekey(self):
        old_shared_key = self.channel.shared_key
        self.session.rekey()
        self.assertNotEqual(self.channel.shared_key, old_shared_key)


class RekeyResponseTest(EstablishedSessionTestCase):

    def setUp(self):
        super(RekeyResponseTest, self).setUp()
        self.session.send_rekey()
        rekey_msg = self.channel.sent_messages.pop(0).msg
        self.client_pubkey = rekey_msg[2:-8]


    def test_responds_to_valid_rekey_response(self):
        pkey = PrivateKey.generate()
        msg = b'\x83\x00' + pkey.public_key._public_key
        mac = self.get_mac(msg)
        response = self.get_response(msg + mac).msg
        self.assert_message_type(response, 0x04)
        self.assertEqual(len(response), 9)
        shared_key = crypto_scalarmult(pkey._private_key, self.client_pubkey)
        expected_mac = hashlib.sha3_256(shared_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)
        self.assertEqual(self.session.state, ClientState.wait_for_rekey_complete)


    def test_rekey_response_invalid_length(self):
        msg = b'\x83\x00'
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 0)


    def test_rekey_response_invalid_mac(self):
        msg = b'\x83\x00' + b'\x00'*40
        self.session.handle(msg)
        self.assertEqual(self.session.s_seq, 0)


    def test_rekey_response_bad_sequence_number(self):
        msg = b'\x83\x01' + b'\x00'*32
        mac = self.get_mac(msg)
        self.session.handle(msg + mac)
        self.assertEqual(self.session.s_seq, 0)


class RekeyCompleteTest(EstablishedSessionTestCase):

    def setUp(self):
        super(RekeyCompleteTest, self).setUp()
        self.session.send_rekey()
        rekey_msg = self.channel.sent_messages.pop(0).msg
        self.client_pubkey = rekey_msg[2:-8]
        pkey = PrivateKey.generate()
        msg = b'\x83\x00' + pkey.public_key._public_key
        mac = self.get_mac(msg)
        response = self.get_response(msg + mac).msg
        self.new_shared_key = crypto_scalarmult(pkey._private_key, self.client_pubkey)


    def test_response_to_rekey_complete(self):
        msg = b'\x84'
        mac = hashlib.sha3_256(self.new_shared_key + msg).digest()[:8]
        self.session.handle(msg + mac)
        self.assertEqual(self.channel.shared_key, self.new_shared_key)
        self.assertEqual(self.session.state, ClientState.terminated)
