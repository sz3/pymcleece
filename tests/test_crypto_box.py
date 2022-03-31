from unittest import TestCase

from mcleece.crypto_box import PrivateKey, PublicKey, SealedBox


class CryptoBoxTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.pk = PrivateKey.generate()

    def test_serialize_keys(self):
        pk = PublicKey(bytes(self.pk))
        self.assertEqual(pk.data, self.pk.data)

        sk = PrivateKey(bytes(self.sk))
        self.assertEqual(sk.data, self.sk.data)

    def test_roundtrip(self):
        box = SealedBox(self.pk)
        self.assertEqual(314, box.message_header_size())

        data = b'0123456789' * 10
        ciphertext = box.encrypt(data)

        self.assertTrue(ciphertext)
        self.assertEqual(len(data) + 314, len(ciphertext))

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
