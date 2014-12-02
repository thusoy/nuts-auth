import unittest
import hashlib
import sha3
import six
import msgpack
from nacl.public import PrivateKey
from nacl.c import crypto_scalarmult

from nuts import AuthChannel, Message
from nuts.hkdf import HKDF

try:
    from unittest import mock
except ImportError:
    # Python 2
    import mock

class ClientHelloTest(unittest.TestCase):

    def setUp(self):
        self.shared_secret = b'secret'
        self.channel = AuthChannel(self.shared_secret)


    def test_client_hello(self):
        R_b = b'\x00'*8
        version = b'\x10'
        msg = b'\x00' + version + R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = ord(b'\x80')
        self.assertEqual(len(response), 17)
        self.assertEqual(six.byte2int(response), expected_type)
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
        R_b = b'\x00'*8
        version = b'\x20'
        msg = b'\x00' + version + R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = ord(b'\x83')
        self.assertEqual(six.byte2int(response), expected_type)


class SAProposalTest(unittest.TestCase):

    def setUp(self):
        self.shared_secret = b'secret'
        self.channel = AuthChannel(self.shared_secret)

        # Send valid client_hello to get channel into correct state
        self.R_b = b'\x00'*8
        msg = b'\x00\x10' + self.R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.R_a = response.msg[1:9]


    def test_sa_proposal(self):
        # Test with default parameters (empty SA)
        msg = b'\x01'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        if response:
            response = response.msg
        expected_type = ord(b'\x81')
        self.assertEqual(six.byte2int(response), expected_type)
        session_key = HKDF(self.R_a + self.R_b, self.shared_secret).expand(b'1.0', length=16)

        # Should have valid MAC
        expected_mac = hashlib.sha3_256(session_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)

        sa = msgpack.loads(response[1:-8])

        # Should have selected Keccak-256 as default
        self.assertEqual(sa[b'mac'], b'sha3_256')

        # Should have defaulted to 8 byte MACs
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_length(self):
        for msg in [b'\x01' + b'\x00'*2, b'\x01' + b'\x00'*1024]:

            # Reset session to correct state
            self.setUp()

            response = self.channel.receive(Message('source', msg))
            self.assertIsNone(response)


    def test_sa_proposal_invalid_mac(self):
        msg = b'\x01' + b'\x00'*8
        response = self.channel.receive(Message('source', msg))
        self.assertIsNone(response)


    def test_sa_proposal_macs(self):
        msg = b'\x01' + msgpack.dumps({'macs': ['sha3_512']})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        sa = msgpack.loads(response[1:-8])
        self.assertEqual(sa[b'mac'], b'sha3_512')
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_macs(self):
        msg = b'\x01' + msgpack.dumps({b'macs': b'\x00'*16})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_sa_proposal_mac_len(self):
        for length in [4, 8, 9, 32]:

            # Reset channel between each test
            self.setUp()

            msg = b'\x01' + msgpack.dumps({'mac_len': length})
            sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
            response = self.channel.receive(Message('source', msg + sig)).msg
            sa = msgpack.loads(response[1:-8])
            self.assertEqual(sa[b'mac'], b'sha3_256')
            self.assertEqual(sa[b'mac_len'], length)


    def test_sa_proposal_unsupported_macs(self):
        msg = b'\x01' + msgpack.dumps({'macs': ['hmac-md5']})
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        sa = msgpack.loads(response[1:-8])
        self.assertEqual(sa[b'mac'], b'sha3_256')
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_mac_len(self):
        for length in [-1, 0, 3, 33, 2**32, '\x00', b'\xff'*16]:
            msg = b'\x01' + msgpack.dumps({b'mac_len': length})
            sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
            response = self.channel.receive(Message('source', msg + sig))
            self.assertIsNone(response)


    def test_sa_proposal_malformed_msgpack_data(self):
        msg = b'\x01' + b'\x00\x00'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_sa_proposal_invalid_type(self):
        msg = b'\x00'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


class CommandTest(unittest.TestCase):

    def setUp(self):
        self.shared_secret = b'secret'

        class TestApp(mock.Mock):

            def got_message(self, message):
                return b'Hello, earthlings'

        self.app = TestApp()
        self.channel = AuthChannel(self.shared_secret, app=self.app)

        # Put channel in established state
        self.R_b = b'\x00'*8
        msg = b'\x00\x10' + self.R_b
        sig = hashlib.sha3_256(self.shared_secret + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.R_a = response.msg[1:9]
        msg = b'\x01'
        sig = hashlib.sha3_256(self.shared_secret + msg + self.R_a).digest()[:8]
        self.channel.receive(Message('source', msg + sig))
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_secret).expand(b'1.0', length=16)


    def test_command(self):
        msg = b'\x02\x00' + b'Hello, space'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        expected_mac = hashlib.sha3_256(self.session_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)
        seq_num = six.byte2int(response)
        self.assertEqual(seq_num, 0)
        self.assertEqual(response[1:-8], b'Hello, earthlings')

        # second command should have different seqnums
        msg = b'\x02\x01' + b'Hello again!'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        expected_mac = hashlib.sha3_256(self.session_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)
        seq_num = six.byte2int(response)
        self.assertEqual(seq_num, 1)
        self.assertEqual(response[1:-8], b'Hello, earthlings')


    def test_command_invalid_type(self):
        for type in [b'\x00', b'\x01', b'\x04', b'\x80']:
            msg = type + b'Hello, world'
            response = self.send_with_mac(msg)
            self.assertIsNone(response)


    def test_command_replay(self):
        msg = b'\x02\x00' + b'Hello, space'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig)).msg
        expected_mac = hashlib.sha3_256(self.session_key + response[:-8]).digest()[:8]
        self.assertEqual(response[-8:], expected_mac)
        seq_num = six.byte2int(response)
        self.assertEqual(seq_num, 0)
        self.assertEqual(response[1:-8], b'Hello, earthlings')

        # replay first message
        msg = b'\x02\x00' + b'Hello again!'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_command_invalid_length(self):
        msg = b'\x02'
        response = self.channel.receive(Message('source', msg))
        self.assertIsNone(response)


    def test_command_invalid_mac(self):
        msg = b'\x02'
        sig = b'\x00'*8
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_command_no_app(self):
        self.channel.set_app(None)
        msg = b'\x02'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_command_app_crash(self):
        class CrashingApp(object):
            def got_message(self, message):
                1/0

        self.channel.set_app(CrashingApp())
        msg = b'\x02'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def test_command_mute_app(self):
        class MuteApp(object):
            def got_message(self, message):
                return None
        self.channel.set_app(MuteApp())
        msg = b'\x02'
        sig = hashlib.sha3_256(self.session_key + msg).digest()[:8]
        response = self.channel.receive(Message('source', msg + sig))
        self.assertIsNone(response)


    def sha3mac(self, *args):
        return hashlib.sha3_256(self.session_key + b''.join(args)).digest()[:8]


    def get_response(self, msg):
        return self.channel.receive(Message('source', msg))


    def send_with_mac(self, msg):
        mac = self.sha3mac(msg)
        return self.get_response(msg + mac)


class RekeyTest(CommandTest):

    def test_rekey(self):
        pkey = PrivateKey.generate()
        msg = b'\x03' + pkey.public_key._public_key
        response = self.send_with_mac(msg).msg
        expected_mac = self.sha3mac(response[:-8])
        self.assertEqual(response[-8:], expected_mac)
        expected_type = 0x83
        self.assertEqual(six.byte2int(response), expected_type)
        server_pubkey = response[1:-8]
        new_shared_secret = crypto_scalarmult(pkey._private_key, server_pubkey)

        # Send confirm
        self.session_key = new_shared_secret
        msg = b'\x04'
        response = self.send_with_mac(msg).msg
        expected_type = 0x84
        self.assertEqual(six.byte2int(response), expected_type)
        expected_mac = self.sha3mac(response[:-8])
        self.assertEqual(response[-8:], expected_mac)
        self.assertEqual(self.session_key, self.channel.shared_key)
