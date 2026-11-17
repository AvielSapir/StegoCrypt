import random
from PIL import Image
from crypto import CryptoEngine
from envelope import Envelope

class StegoEngine:
    @staticmethod
    def _get_pixel_sequence(width: int, height: int, seed: bytes) -> list:
        indices = [(x, y, c) for y in range(height) for x in range(width) for c in range(3)]
        rng = random.Random(seed)
        rng.shuffle(indices)
        return indices

    @classmethod
    def embed(cls, img: Image.Image, payload: bytes, passphrase: str) -> Image.Image:
        crypto = CryptoEngine(passphrase)
        encrypted_data = crypto.encrypt(payload)
        envelope_data = Envelope.pack(encrypted_data)
        
        bits = []
        for byte in envelope_data:
            for bit_idx in range(7, -1, -1):
                bits.append((byte >> bit_idx) & 1)
                
        img = img.convert("RGB")
        width, height = img.size
        total_capacity = width * height * 3
        
        if len(bits) > total_capacity:
            raise ValueError("Payload exceeds image capacity")
            
        seed = passphrase.encode("utf-8")
        pixel_sequence = cls._get_pixel_sequence(width, height, seed)
        
        pixels = img.load()
        for idx, bit in enumerate(bits):
            x, y, c = pixel_sequence[idx]
            rgb = list(pixels[x, y])
            rgb[c] = (rgb[c] & ~1) | bit
            pixels[x, y] = tuple(rgb)
            
        return img

    @classmethod
    def extract(cls, img: Image.Image, passphrase: str) -> bytes:
        img = img.convert("RGB")
        width, height = img.size
        seed = passphrase.encode("utf-8")
        pixel_sequence = cls._get_pixel_sequence(width, height, seed)
        
        pixels = img.load()
        header_len = 12
        header_bits = []
        for idx in range(header_len * 8):
            x, y, c = pixel_sequence[idx]
            bit = pixels[x, y][c] & 1
            header_bits.append(bit)
            
        header_bytes = bytearray()
        for i in range(0, len(header_bits), 8):
            val = 0
            for b in header_bits[i:i + 8]:
                val = (val << 1) | b
            header_bytes.append(val)
            
        from envelope import ENVELOPE_STRUCT, MAGIC
        magic, data_len, crc = ENVELOPE_STRUCT.unpack(bytes(header_bytes))
        if magic != MAGIC:
            raise ValueError("Invalid stego signature")
            
        total_bytes_needed = header_len + data_len
        if total_bytes_needed * 8 > len(pixel_sequence):
            raise ValueError("Corrupt metadata: payload larger than image")
            
        all_bits = []
        for idx in range(total_bytes_needed * 8):
            x, y, c = pixel_sequence[idx]
            bit = pixels[x, y][c] & 1
            all_bits.append(bit)
            
        all_bytes = bytearray()
        for i in range(0, len(all_bits), 8):
            val = 0
            for b in all_bits[i:i + 8]:
                val = (val << 1) | b
            all_bytes.append(val)
            
        encrypted_payload = Envelope.unpack(bytes(all_bytes))
        plaintext = CryptoEngine.decrypt(encrypted_payload, passphrase)
        return plaintext
