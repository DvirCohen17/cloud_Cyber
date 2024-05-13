import base64
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import sys
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python script.py <mode> <msg>")
        sys.exit(1)

    mode = sys.argv[1]
    msg  = sys.argv[2]

    chifer = AESCipher("Quartz wolves frame icy lakes on hills")
    if mode == "encrypt":
        a = chifer.encrypt(msg)
        print(a)
    if mode == "decrypt":
        msg = bytes(msg[2:-1], 'utf-8')
        b = chifer.decrypt(msg)
        print(b[1:-1])
