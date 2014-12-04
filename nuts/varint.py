"""
    Helper module for working with variable-sized byte representations of
    integers.

    Integers < 128 will be encoded using 1 byte, then one byte more for each
    7 bits that needs to be added.

    MSB can be used to detect whether more bytes follow or not.
"""

import six

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
