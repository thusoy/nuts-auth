import hashlib
import quopri
import sha3
import six


def ascii_bin(binstr):
    return repr(quopri.encodestring(binstr))


def encode_version(version):
    """ Takes a version like '1.0' or '2.1' and encodes it into a single byte. """
    major, minor = map(int, version.split(b'.'))
    if not (0 < major < 16 and 0 <= minor < 16):
        raise ValueError("Can't encode version %s, major or minor version outside range(0, 16)" % version)
    return six.int2byte(major << 4 | minor)


def decode_version(version):
    """ Takes a byte version and decodes it into human-readable <major>.<minor> format. """
    if len(version) != 1:
        raise ValueError("Can only decode a single byte!")
    major = six.byte2int(version) >> 4
    minor = six.byte2int(version) & 15
    return ('%d.%d' % (major, minor)).encode('ascii')


def mac(key, msg, algo='sha3_256', mac_len=8):
    """ Create a secure MAC of the message with the key, using
    Keccak (SHA-3) 256 truncated to 64 bits.
    """
    print('MACing %s with key %s (%d)' % (repr(quopri.encodestring(msg)), repr(quopri.encodestring(key)), len(key)))
    hash_func = getattr(hashlib, algo)
    return hash_func(key + msg).digest()[:mac_len]
