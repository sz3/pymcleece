import ctypes
from ctypes import c_int

from .lib import libmcleece


class PublicKey:
    def __init__(self, data):
        # check that length matches libmcleece length
        self.data = data

    def __bytes__(self):
        return self.data

    @classmethod
    def size(cls):
        return c_int.in_dll(libmcleece(), 'mcleece_simple_PUBLIC_KEY_SIZE').value

class PrivateKey:
    def __init__(self, data):
        # check that length matches libmcleece length
        self.data = data

    def __bytes__(self):
        return self.data

    @classmethod
    def size(cls):
        return c_int.in_dll(libmcleece(), 'mcleece_simple_SECRET_KEY_SIZE').value

    @classmethod
    def generate(cls):
        pk_size = PublicKey.size()
        sk_size = cls.size()
        pk = (ctypes.c_uint8 * pk_size)()
        sk = (ctypes.c_uint8 * sk_size)()
        res = libmcleece().mcleece_simple_keypair(ctypes.byref(pk), ctypes.byref(sk))
        if res != 0:
            return None
        return PrivateKey(bytes(sk)), PublicKey(bytes(pk))


class SealedBox:
    def __init__(self, key):
        ''' do something with the key here...
        the decryption part is interesting, because libsodium needs both public+private keys
        to do the decryption, but mcleece doesn't care about needing the public key.
        But the *interface* doesn't have a good way to communicate that at the moment...
        '''
        self.public_key = self.secret_key = None
        if isinstance(key, PublicKey):
            self.public_key = (ctypes.c_uint8 * len(key.data)).from_buffer_copy(key.data)

        elif isinstance(key, PrivateKey):
            self.secret_key = (ctypes.c_uint8 * len(key.data)).from_buffer_copy(key.data)

    @classmethod
    def message_header_size(cls):
        return c_int.in_dll(libmcleece(), 'mcleece_simple_MESSAGE_HEADER_SIZE').value

    def encrypt(self, msg):
        if not self.public_key or len(self.public_key) < PublicKey.size():
            raise Exception('not initialized for encryption!')

        msg_size = len(msg)
        msg = (ctypes.c_uint8 * msg_size).from_buffer_copy(msg)
        ciphertext_size = msg_size + self.message_header_size()
        ciphertext = (ctypes.c_uint8 * ciphertext_size)()

        res = libmcleece().mcleece_simple_encrypt(
            ctypes.byref(ciphertext), ctypes.byref(msg), ctypes.c_uint32(msg_size), ctypes.byref(self.public_key)
        )
        if res != 0:
            return None
        return bytes(bytearray(ciphertext))

    def decrypt(self, ciphertext):
        if not self.secret_key or len(self.secret_key) < PrivateKey.size():
            raise Exception('not initialized for decryption!')

        ciphertext_size = len(ciphertext)
        ciphertext = (ctypes.c_uint8 * ciphertext_size).from_buffer_copy(ciphertext)
        msg_size = ciphertext_size - self.message_header_size()
        msg = (ctypes.c_uint8 * msg_size)()

        res = libmcleece().mcleece_simple_decrypt(
            ctypes.byref(msg), ctypes.byref(ciphertext), ctypes.c_uint32(ciphertext_size), ctypes.byref(self.secret_key)
        )
        if res != 0:
            return None

        return bytes(bytearray(msg))
