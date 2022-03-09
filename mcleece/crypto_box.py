import ctypes

from nacl.public import PrivateKey as nacl_PrivateKey, PublicKey as nacl_PublicKey

from .lib import libmcleece


class PublicKey:
    def __init__(self, data):
        # check that length matches libmcleece length
        self.data = data


class PrivateKey:
    def __init__(self, data):
        # check that length matches libmcleece length
        self.data = data

    def get_nacl_public_key(self):
        # truncate a copy of self.data, and pass to PrivateKey here...
        sodium_pkey_size = mcleece().mcleece_crypto_box_SODIUM_PUBLIC_KEY_SIZE
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


    def encrypt(msg):
        if not self.public_key:
            raise Excepion('not initialized for encryption!')

        buffer_size = len(msg) + mcleece().mcleece_crypto_box_MESSAGE_HEADER_SIZE
        buff = (ctypes.c_uint8 * buffer_size).from_buffer_copy(msg)
        scratch_size = len(msg) + mcleece().mcleece_crypto_box_SODIUM_MESSAGE_HEADER_SIZE
        scratch = (ctypes.c_uint8 * scratch_size)()
        '''
        allocate buffer for ciphertext
        put msg into it(!)
        allocate scratch buffer for intermediate result
        make C call, and if it succeeds, return ciphertext result
        '''

        res = mcleece().mcleece_inplace_crypto_box_seal(
            ctypes.byref(buff), ctypes.c_uint32(buffer_size), ctypes.byref(scratch), ctypes.byref(self.public_key)
        )
        if res != 0:
            return None
        return bytes(bytearray(buff))

    def decrypt(ciphertext):
        if not self.secret_key:
            raise Excepion('not initialized for decryption!')

        buffer_size = len(ciphertext)
        buff = (ctypes.c_uint8 * buffer_size).from_buffer_copy(ciphertext)
        scratch_size = len(ciphertext) - mcleece().mcleece_simple_MESSAGE_HEADER_SIZE
        scratch = (ctypes.c_uint8 * scratch_size)()

        '''
        allocate buffer for ciphertext
        put ciphertext into it
        allocate scratch buffer for intermediate result
        make C call, and if it succeeds, return msg result
        '''
        res = mcleece().mcleece_inplace_crypto_box_seal_open(
            ctypes.byref(buff), ctypes.c_uint32(buffer_size), ctypes.byref(scratch),
            ctypes.byref(self.public_key), ctypes.byref(self.secret_key)
        )
        if res != 0:
            return None

        msg_size = buffer_size - mcleece_crypto_box_MESSAGE_HEADER_SIZE
        return bytes(bytearray(buff)[:msg_size])
