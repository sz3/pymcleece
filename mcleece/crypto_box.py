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
        return c_int.in_dll(libmcleece(), 'mcleece_crypto_box_PUBLIC_KEY_SIZE').value

class PrivateKey:
    def __init__(self, data):
        # check that length matches libmcleece length
        self.data = data

    def __bytes__(self):
        return self.data

    @classmethod
    def size(cls):
        return c_int.in_dll(libmcleece(), 'mcleece_crypto_box_SECRET_KEY_SIZE').value

    @classmethod
    def generate(cls):
        pk_size = PublicKey.size()
        sk_size = cls.size()
        pk = (ctypes.c_uint8 * pk_size)()
        sk = (ctypes.c_uint8 * sk_size)()
        res = libmcleece().mcleece_crypto_box_keypair(ctypes.byref(pk), ctypes.byref(sk))
        if res != 0:
            return None
        return PrivateKey(bytes(sk)), PublicKey(bytes(pk))

    def get_nacl_public_key(self):
        # truncate a copy of self.data, and pass to PrivateKey here...
        from nacl.public import PrivateKey as nacl_PrivateKey
        sodium_pkey_size = c_int.in_dll(libmcleece(), 'mcleece_crypto_box_SODIUM_PUBLIC_KEY_SIZE').value
        return bytes(nacl_PrivateKey(self.data[:sodium_pkey_size]).public_key)


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
            pubkey = key.get_nacl_public_key()
            self.public_key = (ctypes.c_uint8 * len(pubkey)).from_buffer_copy(pubkey)

    @classmethod
    def message_header_size(cls):
        return c_int.in_dll(libmcleece(), 'mcleece_crypto_box_MESSAGE_HEADER_SIZE').value

    def encrypt(self, msg):
        if not self.public_key or len(self.public_key) < PublicKey.size():
            raise Exception('not initialized for encryption!')

        buffer_size = len(msg) + self.message_header_size()
        padmsg = bytes(msg) + b'\0'*(buffer_size - len(msg))
        buff = (ctypes.c_uint8 * buffer_size).from_buffer_copy(padmsg)
        scratch_size = len(msg) + c_int.in_dll(libmcleece(), 'mcleece_crypto_box_SODIUM_MESSAGE_HEADER_SIZE').value
        scratch = (ctypes.c_uint8 * scratch_size)()
        '''
        allocate buffer for ciphertext
        put msg into it(!)
        allocate scratch buffer for intermediate result
        make C call, and if it succeeds, return ciphertext result
        '''

        res = libmcleece().mcleece_inplace_crypto_box_seal(
            ctypes.byref(buff), ctypes.c_uint32(buffer_size), ctypes.byref(scratch), ctypes.byref(self.public_key)
        )
        if res != 0:
            return None
        return bytes(bytearray(buff))

    def decrypt(self, ciphertext):
        if not self.secret_key or len(self.secret_key) < PrivateKey.size():
            raise Exception('not initialized for decryption!')

        buffer_size = len(ciphertext)
        buff = (ctypes.c_uint8 * buffer_size).from_buffer_copy(ciphertext)
        scratch_size = len(ciphertext) - c_int.in_dll(libmcleece(), 'mcleece_simple_MESSAGE_HEADER_SIZE').value
        scratch = (ctypes.c_uint8 * scratch_size)()

        '''
        allocate buffer for ciphertext
        put ciphertext into it
        allocate scratch buffer for intermediate result
        make C call, and if it succeeds, return msg result
        '''
        res = libmcleece().mcleece_inplace_crypto_box_seal_open(
            ctypes.byref(buff), ctypes.c_uint32(buffer_size), ctypes.byref(scratch),
            ctypes.byref(self.public_key), ctypes.byref(self.secret_key)
        )
        if res != 0:
            return None

        msg_size = buffer_size - self.message_header_size()
        return bytes(bytearray(buff)[:msg_size])
