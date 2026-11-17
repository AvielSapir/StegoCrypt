# StegoCrypt

A cryptographically hardened LSB image steganography tool in Python. It hides arbitrary text or binary files inside lossless PNG images without noticeable visual distortion, combining authenticated encryption with pseudo-random pixel scattering.

## How it works

Unlike basic LSB tools that write bits sequentially (making them easy to spot with Chi-Square statistical analysis), **StegoCrypt** runs the payload through a multi-layered pipeline:

1. **Key derivation & encryption (`crypto.py`)** – Derives separate 32-byte encryption and MAC keys from your passphrase using `PBKDF2-HMAC-SHA256` (100,000 iterations), encrypts with a SHA-256 CTR keystream, and authenticates with `HMAC-SHA256` (Encrypt-then-MAC).
2. **Binary envelope (`envelope.py`)** – Wraps the ciphertext with a magic header (`STEG`), payload length, and a `CRC-32` checksum to catch corruption early.
3. **PRNG pixel scattering (`stego.py`)** – Uses a passphrase-seeded Fisher-Yates shuffle over all `(x, y, channel)` coordinates so payload bits are spread across the entire image rather than clustered at the top.

### LSB embedding & capacity

For each RGB channel value $C \in [0, 255]$ and payload bit $b \in \lbrace 0, 1 \rbrace$, only the least significant bit is replaced:

$$
C_{\text{new}} = (C \ \text{AND} \ \text{0xFE}) \ \text{OR} \ b
$$

This changes each channel by at most $\pm 1$ (< 0.4% intensity), which is invisible to the human eye. The maximum storage capacity of an RGB carrier image is:

$$
\text{Capacity} = \frac{\text{Width} \times \text{Height} \times 3}{8} \text{ bytes}
$$

For example, a standard `1920x1080` PNG can hide roughly **777 KB** of encrypted data.

## Quick start

Install the only external dependency:
```bash
pip install Pillow
```

Run the unit tests:
```bash
python test_stego.py
```

Embed a secret message or file:
```bash
python main.py embed --image carrier.png --output secret.png --passphrase "my-secret" --message "Hello world"
```

Extract it back:
```bash
python main.py extract --image secret.png --passphrase "my-secret"
```

## Project structure

- `main.py` – CLI for embedding and extracting text or files
- `stego.py` – PRNG coordinate scattering and LSB bit manipulation
- `crypto.py` – PBKDF2 key derivation, SHA-256 CTR encryption, and HMAC-SHA256 verification
- `envelope.py` – Binary framing (`STEG` header + length + `CRC-32`)
- `test_stego.py` – Unit tests covering encryption, framing, and steganography
