import unittest
import hashlib
import sha3
import msgpack

from nuts import AuthChannel, Message
from nuts.hkdf import HKDF

class ClientHelloTest(unittest.TestCase):

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


    def test_client_hello_invalid_type(self):
        msg = '\x01\x10' + '\x00'*8 + '\x00'*8
        response = self.channel.receive(Message('source', msg))
        self.assertIsNone(response)


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


class SAProposalTest(unittest.TestCase):

    def setUp(self):
        self.shared_secret = 'secret'
        self.channel = AuthChannel(self.shared_secret)

        # Send valid client_hello to get channel into correct state
        self.R_b = '\x00'*8
        msg = '\x00\x10' + self.R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.R_a = response.msg[1:9]


    def test_sa_proposal(self):
        # Test with default parameters (empty SA)
        msg = '\x01'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = '\x81'
        self.assertEqual(response[0], expected_type)
        session_key = HKDF(self.R_a + self.R_b, self.shared_secret).expand('1.0', length=16)

        # Should have valid MAC
        expected_mac = hashlib.sha3_256(session_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)

        sa = msgpack.loads(response[1:-8])

        # Should have selected Keccak-256 as default
        self.assertEqual(sa['mac'], 'sha3_256')

        # Should have defaulted to 8 byte MACs
        self.assertEqual(sa['mac_len'], 8)


    def test_sa_proposal_invalid_length(self):
        for msg in ['\x01' + '\x00'*2, '\x01' + '\x00'*1024]:

            # Reset session to correct state
            self.setUp()

            response = self.channel.receive(Message('source', msg))
            self.assertIsNone(response)


    def test_sa_proposal_invalid_mac(self):
        msg = '\x01' + '\x00'*8
        response = self.channel.receive(Message('source', msg))
        self.assertIsNone(response)


    def test_sa_proposal_macs(self):
        msg = '\x01' + msgpack.dumps({'macs': ['sha3_512']})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        sa = msgpack.loads(response[1:-8])
        self.assertEqual(sa['mac'], 'sha3_512')
        self.assertEqual(sa['mac_len'], 8)


    def test_sa_proposal_invalid_macs(self):
        msg = '\x01' + msgpack.dumps({'macs': '\x00'*16})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_sa_proposal_mac_len(self):
        for length in [4, 8, 9, 32]:

            # Reset channel between each test
            self.setUp()

            msg = '\x01' + msgpack.dumps({'mac_len': length})
            sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
            response = self.channel.receive(Message('source', msg + sig)).msg
            sa = msgpack.loads(response[1:-8])
            self.assertEqual(sa['mac'], 'sha3_256')
            self.assertEqual(sa['mac_len'], length)


    def test_sa_proposal_unsupported_macs(self):
        msg = '\x01' + msgpack.dumps({'macs': ['hmac-md5']})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        sa = msgpack.loads(response[1:-8])
        self.assertEqual(sa['mac'], 'sha3_256')
        self.assertEqual(sa['mac_len'], 8)


    def test_sa_proposal_invalid_mac_len(self):
        for length in [-1, 0, 3, 33, 2**32, '\x00', '\xff'*16]:
            msg = '\x01' + msgpack.dumps({'mac_len': length})
            sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
            response = self.channel.receive(Message('source', msg + sig))
            self.assertIsNone(response)


    def test_sa_proposal_malformed_msgpack_data(self):
        msg = '\x01' + '\x00\x00'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_sa_proposal_invalid_type(self):
        msg = '\x00'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)
