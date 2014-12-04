import unittest
import six

from nuts import encode_version, decode_version
from nuts.varint import encode_varint, decode_varint

class NutsCoreTest(unittest.TestCase):

    def test_encode_version(self):
        for valid_version, expected in [(b'1.0', b'\x10'),
                                        (b'3.1', b'\x31'),
                                        (b'15.15', b'\xff')]:
            self.assertEqual(encode_version(valid_version), expected)


    def test_encode_invalid_version(self):
        for invalid_version in [b'-1.0', b'0.0', b'16.0', b'3.-1', b'aa', b'3', b'1.']:
            self.assertRaises(ValueError, encode_version, invalid_version)


    def test_decode_version(self):
        for valid_version, expected in [(b'\x10', b'1.0'),
                                        (b'\x31', b'3.1'),
                                        (b'\xff', b'15.15')]:
            self.assertEqual(decode_version(valid_version), expected)


    def test_decode_invalid_version(self):
        for invalid_version in [b'aa', b'\x00\x00', b'']:
            print(invalid_version)
            self.assertRaises(ValueError, decode_version, invalid_version)


    def test_varint_encode(self):
        tests = [
            (0, b'\x00'),
            (1, b'\x01'),
            (127, b'\x7f'),
            (128, b'\x81\x00'),
            (16383, b'\xff\x7f'),
            (16384, b'\x81\x80\x00'),
        ]
        for integer, bytes in tests:
            self.assertEqual(encode_varint(integer), bytes)


    def test_varint_decode(self):
        tests = [
            (b'\x00', 0),
            (b'\x01', 1),
            (b'\x7f', 127),
            (b'\x81\x00', 128),
            (b'\xff\x7f', 16383),
            (b'\x81\x80\x00', 16384),
        ]
        for bytes, integer in tests:
            self.assertEqual(decode_varint(list(six.iterbytes(bytes))), integer)


if __name__ == '__main__':
    unittest.main()
