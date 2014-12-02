import unittest
import hashlib
import sha3
import six
import msgpack
from nacl.public import PrivateKey
from nacl.c import crypto_scalarmult

from nuts import AuthChannel, Message
from nuts.hkdf import HKDF
from nuts.utils import ascii_bin

class BaseMessageTestCase(unittest.TestCase):

    # These are overrideable to run tests and helpers with different parameters
    mac = 'sha3_256'
    mac_len = 8

    def assertMessageType(self, response, expected_type):
        self.assertEqual(six.byte2int(response), expected_type)



    def get_mac(self, *args, **kwargs):
        algo = kwargs.get('algo', self.mac)
        length = kwargs.get('length', self.mac_len)
        hash = getattr(hashlib, algo)
        if hasattr(self, 'session_key'):
            key = self.session_key
        else:
            key = self.shared_secret
        return hash(key + b''.join(args)).digest()[:length]


    def get_response(self, msg):
        return self.channel.receive(Message('source', msg))


    def send_with_mac(self, msg, **kwargs):
        mac = self.get_mac(msg, **kwargs)
        return self.get_response(msg + mac)


    def assertCorrectMAC(self, response):
        expected_mac = self.get_mac(response[:-self.mac_len])
        self.assertEqual(response[-self.mac_len:], expected_mac)


class EstablishedSessionTestCase(BaseMessageTestCase):
    """ Helper TestCase for running tests on an established session. """


    def setUp(self):
        self.shared_secret = b'secret'

        class TestApp(object):
            def got_message(self, message):
                return b'Hello, earthlings'

        self.channel = AuthChannel(self.shared_secret, app=TestApp())

        # Put channel in established state
        self.R_b = b'\x00'*8
        msg = b'\x00\x10' + self.R_b
        response = self.send_with_mac(msg, algo='sha3_256', length=8)
        self.R_a = response.msg[1:9]
        msg = b'\x01' + msgpack.dumps({'macs': [self.mac], 'mac_len': self.mac_len})
        mac = self.get_mac(msg, self.R_a, algo='sha3_256', length=8)
        self.get_response(msg + mac)
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_secret).expand(b'1.0', length=16)


class ClientHelloTest(BaseMessageTestCase):

    def setUp(self):
        self.shared_secret = b'secret'
        self.channel = AuthChannel(self.shared_secret)


    def test_client_hello(self):
        R_b = b'\x00'*8
        version = b'\x10'
        msg = b'\x00' + version + R_b
        response = self.send_with_mac(msg).msg
        self.assertEqual(len(response), 17)
        self.assertMessageType(response, 0x80)
        expected_mac = self.get_mac(response[:-self.mac_len], R_b)
        self.assertEqual(response[-self.mac_len:], expected_mac)


    def test_client_hello_invalid_type(self):
        msg = '\x01\x10' + '\x00'*8 + '\x00'*8
        response = self.get_response(msg)
        self.assertIsNone(response)


    def test_client_hello_invalid_mac(self):
        msg = '\x00\x10' + '\x00'*8 + '\x00'*8 # invalid mac
        response = self.get_response(msg)
        self.assertIsNone(response)


    def test_client_hello_invalid_length(self):
        # Test both too short and too long messages
        for msg in ['\x00\x10', '\x00\x10' + '\x00'*20]:
            response = self.get_response(msg)
            self.assertIsNone(response)


    def test_client_hello_unsupported_version(self):
        R_b = b'\x00'*8
        for version in [0x20, 0x00, 0xff]:
            msg = b'\x00' + six.int2byte(version) + R_b
            response = self.send_with_mac(msg).msg
            self.assertMessageType(response, 0x83)


class SAProposalTest(BaseMessageTestCase):

    def setUp(self):
        self.shared_secret = b'secret'
        self.channel = AuthChannel(self.shared_secret)

        # Send valid client_hello to get channel into correct state
        self.R_b = b'\x00'*8
        msg = b'\x00\x10' + self.R_b
        response = self.send_with_mac(msg)
        self.R_a = response.msg[1:9]


    def test_sa_proposal(self):
        # Test with default parameters (empty SA)
        msg = b'\x01'
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac).msg
        self.session_key = HKDF(self.R_a + self.R_b, self.shared_secret).expand(b'1.0', length=16)
        self.assertCorrectMAC(response)
        self.assertMessageType(response, 0x81)

        sa = msgpack.loads(response[1:-self.mac_len])

        # Should have selected Keccak-256 as default
        self.assertEqual(sa[b'mac'], b'sha3_256')

        # Should have defaulted to 8 byte MACs
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_length(self):
        for msg in [b'\x01' + b'\x00'*2, b'\x01' + b'\x00'*1024]:

            # Reset session to correct state
            self.setUp()

            response = self.get_response(msg)
            self.assertIsNone(response)


    def test_sa_proposal_invalid_mac(self):
        msg = b'\x01' + b'\x00'*8
        response = self.get_response(msg)
        self.assertIsNone(response)


    def test_sa_proposal_macs(self):
        msg = b'\x01' + msgpack.dumps({'macs': ['sha3_512']})
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac).msg
        sa = msgpack.loads(response[1:-8])
        self.assertEqual(sa[b'mac'], b'sha3_512')
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_macs(self):
        msg = b'\x01' + msgpack.dumps({b'macs': b'\x00'*16})
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac)
        self.assertIsNone(response)


    def test_sa_proposal_mac_len(self):
        for length in [4, 8, 9, 32]:

            # Reset channel between each test
            self.setUp()

            msg = b'\x01' + msgpack.dumps({'mac_len': length})
            mac = self.get_mac(msg, self.R_a)
            response = self.get_response(msg + mac).msg
            sa = msgpack.loads(response[1:-self.mac_len])
            self.assertEqual(sa[b'mac'], b'sha3_256')
            self.assertEqual(sa[b'mac_len'], length)


    def test_sa_proposal_unsupported_macs(self):
        msg = b'\x01' + msgpack.dumps({'macs': ['hmac-md5']})
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac).msg
        sa = msgpack.loads(response[1:-self.mac_len])
        self.assertEqual(sa[b'mac'], b'sha3_256')
        self.assertEqual(sa[b'mac_len'], 8)


    def test_sa_proposal_invalid_mac_len(self):
        for length in [-1, 0, 3, 33, 2**32, '\x00', b'\xff'*16]:
            msg = b'\x01' + msgpack.dumps({b'mac_len': length})
            mac = self.get_mac(msg, self.R_a)
            response = self.get_response(msg + mac)
            self.assertIsNone(response)


    def test_sa_proposal_malformed_msgpack_data(self):
        msg = b'\x01' + b'\x00\x00'
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac)
        self.assertIsNone(response)


    def test_sa_proposal_invalid_type(self):
        msg = b'\x00'
        mac = self.get_mac(msg, self.R_a)
        response = self.get_response(msg + mac)
        self.assertIsNone(response)


class CommandTest(EstablishedSessionTestCase):

    def test_command(self):
        msg = b'\x02\x00' + b'Hello, space'
        response = self.send_with_mac(msg).msg
        self.assertMessageType(response, 0x82)
        self.assertCorrectMAC(response)
        seq_num = six.byte2int(response[1:])
        self.assertEqual(seq_num, 0)
        self.assertEqual(response[2:-self.mac_len], b'Hello, earthlings')

        # second command should have different seqnums
        msg = b'\x02\x01' + b'Hello again!'
        response = self.send_with_mac(msg).msg
        self.assertCorrectMAC(response)
        seq_num = six.byte2int(response[1:])
        self.assertEqual(seq_num, 1)
        self.assertEqual(response[2:-self.mac_len], b'Hello, earthlings')


    def test_command_invalid_type(self):
        for type in [b'\x00', b'\x01', b'\x04', b'\x80']:
            msg = type + b'Hello, world'
            response = self.send_with_mac(msg)
            self.assertIsNone(response)


    def test_command_replay(self):
        msg = b'\x02\x00' + b'Hello, space'
        response = self.send_with_mac(msg).msg
        self.assertCorrectMAC(response)
        print('Response: %s' % ascii_bin(response))
        seq_num = six.byte2int(response[1:])
        self.assertEqual(seq_num, 0)
        self.assertEqual(response[2:-self.mac_len], b'Hello, earthlings')

        # replay first message
        msg = b'\x02\x00' + b'Hello again!'
        response = self.send_with_mac(msg)
        self.assertIsNone(response)


    def test_command_invalid_length(self):
        msg = b'\x02'
        response = self.get_response(msg)
        self.assertIsNone(response)


    def test_command_invalid_mac(self):
        msg = b'\x02' + b'\x00'*8
        response = self.get_response(msg)
        self.assertIsNone(response)


    def test_command_no_app(self):
        self.channel.set_app(None)
        response = self.send_with_mac(b'\x02')
        self.assertIsNone(response)


    def test_command_app_crash(self):
        class CrashingApp(object):
            def got_message(self, message):
                1/0

        self.channel.set_app(CrashingApp())
        response = self.send_with_mac(b'\x02')
        self.assertIsNone(response)


    def test_command_mute_app(self):
        class MuteApp(object):
            def got_message(self, message):
                return None
        self.channel.set_app(MuteApp())
        response = self.send_with_mac(b'\x02')
        self.assertIsNone(response)


class RekeyTest(EstablishedSessionTestCase):

    def test_rekey(self):
        pkey = PrivateKey.generate()
        msg = b'\x03' + pkey.public_key._public_key
        response = self.send_with_mac(msg).msg
        self.assertCorrectMAC(response)
        self.assertMessageType(response, 0x83)
        server_pubkey = response[1:-self.mac_len]
        new_shared_secret = crypto_scalarmult(pkey._private_key, server_pubkey)

        # Send confirm
        self.session_key = new_shared_secret
        msg = b'\x04'
        response = self.send_with_mac(msg).msg
        self.assertCorrectMAC(response)
        self.assertMessageType(response, 0x84)
        self.assertEqual(self.session_key, self.channel.shared_key)


    def test_rekey_invalid_length(self):
        for pubkey in [b'\x00', b'\x00'*34]:
            msg = b'\x03' + pubkey
            response = self.send_with_mac(msg)
            self.assertIsNone(response)


    def test_rekey_invalid_mac(self):
        msg = b'\x03' + b'\x00'*32
        mac = b'\x00'*self.mac_len
        response = self.get_response(msg + mac)
        self.assertIsNone(response)


class NonDefaultParametersSessionTest(CommandTest, RekeyTest):
    """ Re-run all the tests from established state with non-default mac and mac_len. """

    mac = 'sha3_512'
    mac_len = 16
