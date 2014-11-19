import sys

def encode_varint(i):
    """ Encode a positiv integer to a variable length byte string. """
    if i < 0:
        raise ArgumentError('Cannot encode negative numbers as varint!')
    res = [chr(i % 128)]
    while i > 127:
        i = i >> 7
        res.append(chr((i % 128) | 128))

    return ''.join(reversed(res))


def decode_varint(s):
    """ Decode a variable length byte string into a positive integer. """
    res = 0
    for exp, c in enumerate(reversed(s)):
        res += (ord(c) & 127)<<(exp*7)
    return res


if __name__ == '__main__':
    i = int(sys.argv[1], 10)
    var = encode_varint(i)
    print i, var.encode('hex'), decode_varint(var)
    i = 1
    while True:
        var = encode_varint(i)
        print i, var.encode('hex'), decode_varint(var)
        i += 1
