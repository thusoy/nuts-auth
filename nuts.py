import hmac
from collections import Namedtuple
import os

import hashlib

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

Message = Namedtuple('Message', ['dest', 'msg'])
_messages = []

shared_key = shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')


def send(dest, msg):
    _messages.append( Message(dest, msg) )


class Connection(object):

    def __init__(self, id_a, id_b, initial_msg_from_b):
        """ Establishing new connection to id_b, send a 128 bit response consisting of
        8 bytes challenge, and a H_k(id_a, id_b, R_a) truncated to 8 bytes.
        """
        self.id_a = id_a
        self.id_b = id_b

        self.R_a = os.urandom(8)
        self.R_b = initial_msg_from_b

        h = hmac.sha256(shared_key)
        h.update(id_a)
        h.update(id_b)
        h.update(self.R_b)
        a = self.R_a + h.digest()[:8]
        send(id_b, a)


    def challenge_reply_received(self, response):
        """ Response received from id_b, that is H_k(id_a, id_b, R_a, a). """
        session_key = Hkdf(shared_key + self.R_a + self.R_b)
        send(self.id_b, b'Go ahead' + hmac.sha256(session_key).update('Go ahead').digest())
