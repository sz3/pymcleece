## pymcleece

A python wrapper for the [libmcleece](https://github.com/sz3/libmcleece) encryption C/C++ library. C++ dependencies (libmcleece, libsodium) are included as a git submodule.

```
git clone --recursive https://github.com/sz3/pymcleece.git
python setup.py build
python setup.py install
```
or with pip:
```
pip install mcleece
```

... linux should work, macOS *could* work, windows is unknown at the moment.

## Usage

```
from mcleece.crypto_box import PrivateKey, PublicKey, SealedBox
sk, pk = PrivateKey.generate()

ebox = SealedBox(pk)
ciphertext = ebox.encrypt(b'helloworld')

dbox = SealedBox(sk)
recoveredtext = dbox.decrypt(ciphertext)
```

