import unittest

from nuts import encode_version, decode_version

class NutsCoreTest(unittest.TestCase):

    def test_encode_version(self):
        for valid_version, expected in [('1.0', '\x10'),
                                        ('3.1', '\x31'),
                                        ('15.15', '\xff')]:
            self.assertEqual(encode_version(valid_version), expected)


    def test_encode_invalid_version(self):
        for invalid_version in ['-1.0', '0.0', '16.0', '3.-1', 'aa', '3', '1.']:
            self.assertRaises(ValueError, encode_version, invalid_version)


    def test_decode_version(self):
        for valid_version, expected in [('\x10', '1.0'),
                                        ('\x31', '3.1'),
                                        ('\xff', '15.15')]:
            self.assertEqual(decode_version(valid_version), expected)


    def test_decode_invalid_version(self):
        for invalid_version in ['aa', '\x00\x00', '']:
            self.assertRaises(ValueError, decode_version, invalid_version)


if __name__ == '__main__':
    unittest.main()
