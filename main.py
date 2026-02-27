import base64
from nacl.secret import SecretBox
from nacl.utils import random

class SimpleFernet:
    def __init__(self, key: bytes):
        self.box = SecretBox(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        token = self.box.encrypt(plaintext)
        return base64.urlsafe_b64encode(token)

    def decrypt(self, token: bytes) -> bytes:
        data = base64.urlsafe_b64decode(token)
        return self.box.decrypt(data)