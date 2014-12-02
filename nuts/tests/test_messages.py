import unittest
import hashlib
import sha3

from nuts import AuthChannel, Message

class MessagesTest(unittest.TestCase):

    def setUp(self):
        self.shared_secret = 'secret'
        self.channel = AuthChannel(self.shared_secret)


    def test_client_hello(self):
        R_b = '\x00'*8
        version = '\x10'
        msg = '\x00' + version + R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = '\x80'
        self.assertEqual(len(response), 17)
        self.assertEqual(response[0], expected_type)
        expected_mac = hashlib.sha3_256(self.shared_secret + response[:-8] + R_b).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)


    def test_client_hello_invalid_mac(self):
        msg = '\x00\x10' + '\x00'*8 + '\x00'*8 # invalid mac
        response = self.channel.receive(Message('source', msg))
        self.assertIsNone(response)

    def test_client_hello_invalid_length(self):
        # Test both too short and too long messages
        for msg in ['\x00\x10', '\x00\x10' + '\x00'*20]:
            response = self.channel.receive(Message('source', msg))
            self.assertIsNone(response)


    def test_client_hello_unsupported_version(self):
        R_b = '\x00'*8
        version = '\x20'
        msg = '\x00' + version + R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = '\x83'
        self.assertEqual(response[0], expected_type)
