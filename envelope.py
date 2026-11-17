import struct
import zlib

MAGIC = b"STEG"
ENVELOPE_STRUCT = struct.Struct("!4sII")

class Envelope:
    @staticmethod
    def pack(payload: bytes) -> bytes:
        data_len = len(payload)
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        header = ENVELOPE_STRUCT.pack(MAGIC, data_len, crc)
        return header + payload

    @staticmethod
    def unpack(raw_data: bytes) -> bytes:
        if len(raw_data) < ENVELOPE_STRUCT.size:
            raise ValueError("Data insufficient for header")
        magic, data_len, crc = ENVELOPE_STRUCT.unpack(raw_data[:ENVELOPE_STRUCT.size])
        if magic != MAGIC:
            raise ValueError("Invalid magic bytes")
        payload = raw_data[ENVELOPE_STRUCT.size:ENVELOPE_STRUCT.size + data_len]
        if len(payload) != data_len:
            raise ValueError("Payload length mismatch")
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != crc:
            raise ValueError("CRC32 integrity check failed")
        return payload
