from base64 import b64encode, b64decode
from os import urandom
from unittest import TestCase

from mcleece.crypto_box import PrivateKey, PublicKey, SealedBox


class CryptoBoxTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.pk = PrivateKey.generate()

    def test_roundtrip(self):
        box = SealedBox(self.pk)
        data = b'0123456789' * 10
        ciphertext = box.encrypt(data)

        self.assertTrue(ciphertext)

        box2 = SealedBox(self.sk)
        msg = box2.decrypt(ciphertext)
        self.assertTrue(msg)

        self.assertEqual(data, msg)

    def test_encrypt_with_sk_box_throws(self):
        box = SealedBox(self.sk)
        data = b'0123456789' * 10

        with self.assertRaises(Exception) as e:
            ciphertext = box.encrypt(data)

        self.assertEqual(str(e.exception), 'not initialized for encryption!')

    def test_decrypt_with_pk_box_throws(self):
        box = SealedBox(self.pk)
        data = b'0123456789' * 10

        with self.assertRaises(Exception) as e:
            msg = box.decrypt(data)

        self.assertEqual(str(e.exception), 'not initialized for decryption!')
