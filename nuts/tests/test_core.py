import unittest

from nuts import encode_version, decode_version

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


if __name__ == '__main__':
    unittest.main()
