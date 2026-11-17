import unittest
from PIL import Image
from crypto import CryptoEngine
from envelope import Envelope
from stego import StegoEngine

class TestCryptoEngine(unittest.TestCase):
    def test_encrypt_decrypt(self):
        engine = CryptoEngine("super_secret_password")
        data = b"Covert military intelligence payload"
        encrypted = engine.encrypt(data)
        decrypted = CryptoEngine.decrypt(encrypted, "super_secret_password")
        self.assertEqual(data, decrypted)

    def test_tamper_detection(self):
        engine = CryptoEngine("password123")
        encrypted = bytearray(engine.encrypt(b"Secret"))
        encrypted[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            CryptoEngine.decrypt(bytes(encrypted), "password123")

class TestEnvelope(unittest.TestCase):
    def test_envelope_pack_unpack(self):
        payload = b"Sample Binary Data \x00\xff\xaa"
        packed = Envelope.pack(payload)
        unpacked = Envelope.unpack(packed)
        self.assertEqual(payload, unpacked)

class TestStegoEngine(unittest.TestCase):
    def test_embed_and_extract_text(self):
        img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        secret_msg = b"Deepmind advanced cybersecurity showcase."
        passphrase = "TopSecretPassword2026"
        
        stego_img = StegoEngine.embed(img, secret_msg, passphrase)
        recovered_msg = StegoEngine.extract(stego_img, passphrase)
        self.assertEqual(secret_msg, recovered_msg)

    def test_wrong_passphrase_fails(self):
        img = Image.new("RGB", (100, 100), color=(50, 100, 150))
        secret_msg = b"Confidential payload"
        stego_img = StegoEngine.embed(img, secret_msg, "correct_pass")
        with self.assertRaises(ValueError):
            StegoEngine.extract(stego_img, "wrong_pass")

if __name__ == "__main__":
    unittest.main()
