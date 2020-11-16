# PyChacha20Poly1305
A pure Python 3 implementation of the Chacha20 Poly1305 AEAD as outlined by rfc7539.

Usage:
```python
>>> from pychacha20poly1305 import encrypt, decrypt
>>> data = encrypt("Hello, world!", "password goes here")
>>> data
b'\x88!\xfc:\xd6\xdc\xf3\xb3z\xd48\x1c\xbcG\xa1.\x0b\xebLg\xc3\xe2\xc8\xbao\xc8\xef\xa2\x0c\x00\x03\xd8Q\xaf\xb8\x08\x8b=\xcf\xe6\xf7'
>>> decrypt(data, "password goes here")
b'Hello, world!'
>>> decrypt(data, "invalid password")
...
raise InvalidTagException(
pychacha20poly1305.InvalidTagException: Invalid tag, either key is invalid or the data is corrupted
```

# Warning
One of the basic rules of cryptography is to "never roll your own crypto". I'm by no means a cryptography expert, this code could be and probably is horribly broken. I only made this to satisfy my curiosity, you shouldn't use this in production or anywhere serious.

![I have no idea what I'm doing dog](https://i.kym-cdn.com/photos/images/original/000/234/765/b7e.jpg)