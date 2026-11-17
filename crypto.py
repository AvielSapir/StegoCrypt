import os
import hashlib
import hmac

class CryptoEngine:
    def __init__(self, passphrase: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)
        self.salt = salt
        derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), self.salt, 100000, 64)
        self.enc_key = derived[:32]
        self.mac_key = derived[32:]

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = hashlib.sha256(self.enc_key + nonce + counter.to_bytes(4, byteorder="big")).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(16)
        keystream = self._keystream(nonce, len(plaintext))
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        tag = hmac.new(self.mac_key, self.salt + nonce + ciphertext, hashlib.sha256).digest()
        return self.salt + nonce + tag + ciphertext

    @classmethod
    def decrypt(cls, data: bytes, passphrase: str) -> bytes:
        if len(data) < 64:
            raise ValueError("Data too short")
        salt = data[:16]
        nonce = data[16:32]
        tag = data[32:64]
        ciphertext = data[64:]
        
        derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100000, 64)
        enc_key = derived[:32]
        mac_key = derived[32:]
        
        expected_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication tag verification failed")
            
        stream = bytearray()
        counter = 0
        while len(stream) < len(ciphertext):
            block = hashlib.sha256(enc_key + nonce + counter.to_bytes(4, byteorder="big")).digest()
            stream.extend(block)
            counter += 1
        keystream = bytes(stream[:len(ciphertext)])
        return bytes([c ^ k for c, k in zip(ciphertext, keystream)])
