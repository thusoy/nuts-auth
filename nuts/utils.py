import os
import quopri
import six
import quopri


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


def rng(num_bytes):
    """ Read `num_bytes` from the RNG. """
    if os.path.exists('/dev/hwrng'):
        with open('/dev/hwrng', 'r') as hwrng:
            return hwrng.read(num_bytes)
    else:
        return os.urandom(8)


def encode_varint(i):
    """ Encode a positiv integer to a variable length byte string. """
    if i < 0:
        raise ArgumentError('Cannot encode negative numbers as varint!')
    res = [six.int2byte(i % 128)]
    while i > 127:
        i >>= 7
        res.append(six.int2byte((i % 128) | 128))

    return b''.join(reversed(res))


def decode_varint(s):
    """ Decode a variable length byte string into a positive integer.

    Note that input must be an array of ints (the way python 3 iterates over a byte string).
    """
    res = 0
    for exp, c in enumerate(reversed(s)):
        res += (c & 127)<<(exp*7)
    return res
