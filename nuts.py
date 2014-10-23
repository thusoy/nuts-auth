import hmac
from collections import namedtuple
from itsdangerous import constant_time_compare
from functools import partial
import os
import json

import hashlib
import sha3

def hkdf_extract(salt, input_key_material, hash=hashlib.sha512):
    '''
    Extract a pseudorandom key suitable for use with hkdf_expand
    from the input_key_material and a salt using HMAC with the
    provided hash (default SHA-512).

    salt should be a random, application-specific byte string. If
    salt is None or the empty string, an all-zeros string of the same
    length as the hash's block size will be used instead per the RFC.

    See the HKDF draft RFC and paper for usage notes.
    '''
    hash_len = hash().digest_size
    if salt == None or len(salt) == 0:
        salt = chr(0) * hash_len
    return hmac.new(salt, input_key_material, hash).digest()

def hkdf_expand(pseudo_random_key, info="", length=32, hash=hashlib.sha512):
    '''
    Expand `pseudo_random_key` and `info` into a key of length `bytes` using
    HKDF's expand function based on HMAC with the provided hash (default
    SHA-512). See the HKDF draft RFC and paper for usage notes.
    '''
    hash_len = hash().digest_size
    length = int(length)
    if length > 255 * hash_len:
        raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" %\
            (hash_len, 255 * hash_len))
    blocks_needed = length / hash_len + (0 if length % hash_len == 0 else 1) # ceil
    okm = ""
    output_block = ""
    for counter in range(blocks_needed):
        output_block = hmac.new(pseudo_random_key, output_block + info + chr(counter + 1), hash).digest()
        okm += output_block
    return okm[:length]

class Hkdf(object):
    '''
    Wrapper class for HKDF extract and expand functions
    '''
    def __init__(self, salt, input_key_material, hash=hashlib.sha256):
        '''
        Extract a pseudorandom key from `salt` and `input_key_material` arguments.

        See the HKDF draft RFC for guidance on setting these values. The constructor
        optionally takes a `hash` arugment defining the hash function use,
        defaulting to hashlib.sha256.
        '''
        self._hash = hash
        self._prk = hkdf_extract(salt, input_key_material, self._hash)
    def expand(self, info="", length=32):
        '''
        Generate output key material based on an `info` value

        Arguments:
        - info - context to generate the OKM
        - length - length in bytes of the key to generate

        See the HKDF draft RFC for guidance.
        '''
        return hkdf_expand(self._prk, info, length, self._hash)


# Store messages passed back and forth for inspection

Message = namedtuple('Message', ['dest', 'msg'])
_messages = []

shared_key = shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')


def send(dest, msg):
    print 'Sending msg of length %d to %s' % (len(msg), dest)
    _messages.append( Message(dest, msg) )

def mac(key, msg):
    """ Create a secure MAC of the message with the key, using
    Keccak (SHA-3) 512 truncated to 64 bits.
    """
#    import pdb; pdb.set_trace()
    return hashlib.sha3_256(key + msg).digest()[:8]


def get_mac(mac_name, mac_len):
    """ Get the MAC function agreed upon in the SA. """
    mac_func = getattr(hashlib, mac_name)
    def _mac(key, msg):
        return mac_func(key + msg).digest()[:mac_len]
    return _mac


class NUTSAuthException(Exception):
    """ Base class for authentication-related exception in the auth channel. """

class SignatureException(NUTSAuthException):
    """ Invalid signature received. """


class Connection(object):

    supported_macs = [
        'sha3_512',
        'sha3_384',
        'sha3_256',
    ]

    def __init__(self, id_a, id_b, initial_msg_from_b):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        self.id_a = id_a
        self.id_b = id_b

        self.R_a = os.urandom(8)
        self.R_b = initial_msg_from_b

        msg = self.id_a + self.id_b + self.R_b
        h = mac(shared_key, msg)
        a = self.R_a + h
        send(id_b, a)


    def challenge_reply_received(self, response):
        """ Response received from id_b, that is H_k(id_a, id_b, R_a, a). """
        self.session_key = hkdf_expand(shared_key + self.R_a + self.R_b, length=16)
        send(self.id_b, b'Go ahead' + mac(self.session_key, 'Go ahead'))


    def sa_proposal_received(self, response):
        msg, sig = response[:-8], response[-8:]
        if not constant_time_compare(mac(self.session_key, msg), sig):
            raise SignatureException()

        msg_data = json.loads(msg)
        suggested_macs = set(msg_data.get('macs', []))
        for supported_mac in Connection.supported_macs:
            if supported_mac in suggested_macs:
                selected_mac = supported_mac
                break
        else:
            raise "No MACs in common, aborting"
        suggested_mac_len = msg_data.get('mac_len', 8)
        try:
            suggested_mac_len = int(suggested_mac_len)
        except ValueError:
            raise ValueError("Suggested mac_len not an integer, was %s" % suggested_mac_len)
        if not (8 <= suggested_mac_len <= 32):
            raise ValueError("suggested mac outside permitted range of 8-32 bytes")
        # All jolly good, notify id_b of chosen MAC and signature length
        response = {
            'mac': selected_mac,
            'mac_len': suggested_mac_len,
        }
        self.sa_mac_len = suggested_mac_len
        response_msg = json.dumps(response)
        mac_func = get_mac(selected_mac, suggested_mac_len)
        self.mac = partial(mac_func, self.session_key)
        send(self.id_b, response_msg + self.mac(response_msg))


    def command_received(self, full_message):
        """Signed, operational command received. Verify signature and return message."""
        msg, sig = full_message[:-self.sa_mac_len], full_message[-self.sa_mac_len:]
        if not constant_time_compare(msg, self.mac(msg)):
            raise SignatureException()
