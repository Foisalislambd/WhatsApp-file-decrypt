#!/usr/bin/env python3

import argparse
import base64
import hashlib
import sys
from typing import Tuple

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MEDIA_TYPE_TO_INFO = {
    "image": b"WhatsApp Image Keys",
    "video": b"WhatsApp Video Keys",
    "audio": b"WhatsApp Audio Keys",
    "document": b"WhatsApp Document Keys",
    "sticker": b"WhatsApp Image Keys",  # stickers use image keys
    # aliases
    "ptt": b"WhatsApp Audio Keys",
    "voice": b"WhatsApp Audio Keys",
}


def hkdf_derive_keys(media_key: bytes, media_type: str) -> Tuple[bytes, bytes, bytes]:
    media_type_norm = media_type.strip().lower()
    info = MEDIA_TYPE_TO_INFO.get(media_type_norm)
    if info is None:
        raise ValueError(f"Unsupported media type '{media_type}'. Supported: {sorted(MEDIA_TYPE_TO_INFO.keys())}")

    # WhatsApp uses HKDF-SHA256 with 32 zero salt, length 112, and media-type-specific info string
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=112,
        salt=b"\x00" * 32,
        info=info,
    )
    okm = hkdf.derive(media_key)
    iv = okm[0:16]
    cipher_key = okm[16:48]
    mac_key = okm[48:80]
    # okm[80:112] is ref key, not needed for decrypt
    return iv, cipher_key, mac_key


def compute_sha256_base64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def verify_mac(enc_without_mac: bytes, mac_tail: bytes, iv: bytes, mac_key: bytes) -> None:
    # mac is first 10 bytes of HMAC-SHA256(mac_key, iv || ciphertext)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(iv + enc_without_mac)
    full_mac = h.finalize()
    expected = full_mac[:10]
    if expected != mac_tail:
        raise ValueError("MAC verification failed: computed MAC does not match file trailer")


def pkcs7_unpad(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("Decryption produced empty output")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return padded[:-pad_len]


def decrypt_media(enc_with_mac: bytes, iv: bytes, cipher_key: bytes, mac_key: bytes) -> bytes:
    if len(enc_with_mac) <= 10:
        raise ValueError("Encrypted payload is too short to contain MAC")
    enc_without_mac = enc_with_mac[:-10]
    mac_tail = enc_with_mac[-10:]

    verify_mac(enc_without_mac, mac_tail, iv, mac_key)

    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(enc_without_mac) + decryptor.finalize()
    return pkcs7_unpad(padded_plain)


def download_bytes(url: str, timeout: int = 60) -> bytes:
    headers = {
        # Some CDNs are picky; provide a neutral UA
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0 Safari/537.36",
        "Accept": "*/*",
    }
    with requests.get(url, headers=headers, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        return r.content


def main():
    parser = argparse.ArgumentParser(description="Decrypt WhatsApp media file using mediaKey and URL")
    parser.add_argument("--url", required=True, help="Direct media URL (e.g., mmg.whatsapp.net ... .enc)")
    parser.add_argument("--media-key", required=True, help="Base64 mediaKey from message (32 bytes in b64)")
    parser.add_argument("--media-type", default="audio", help="Media type: audio, image, video, document, sticker, ptt, voice")
    parser.add_argument("--out", required=True, help="Output filename (e.g., output.ogg)")
    parser.add_argument("--file-sha256", default=None, help="Optional: expected b64 SHA256 of decrypted file for verification")
    parser.add_argument("--file-enc-sha256", default=None, help="Optional: expected b64 SHA256 of encrypted file for verification")
    parser.add_argument("--insecure-skip-mac", action="store_true", help="Skip MAC verification (not recommended)")

    args = parser.parse_args()

    try:
        media_key = base64.b64decode(args.media_key)
    except Exception as e:
        print(f"Failed to decode mediaKey base64: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        iv, cipher_key, mac_key = hkdf_derive_keys(media_key, args.media_type)
    except Exception as e:
        print(f"Key derivation error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        enc_bytes = download_bytes(args.url)
    except Exception as e:
        print(f"Download error: {e}", file=sys.stderr)
        sys.exit(3)

    # Optional check against encrypted SHA256
    if args.file_enc_sha256:
        got = compute_sha256_base64(enc_bytes)
        if got != args.file_enc_sha256:
            print(f"Warning: Encrypted SHA256 mismatch. expected={args.file_enc_sha256} got={got}")

    try:
        if args.insecure_skip_mac:
            enc_without_mac = enc_bytes[:-10] if len(enc_bytes) > 10 else b""
            cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plain = decryptor.update(enc_without_mac) + decryptor.finalize()
            plain = pkcs7_unpad(padded_plain)
        else:
            plain = decrypt_media(enc_bytes, iv, cipher_key, mac_key)
    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        sys.exit(4)

    # Optional check against decrypted SHA256
    if args.file_sha256:
        got = compute_sha256_base64(plain)
        if got != args.file_sha256:
            print(f"Warning: Decrypted SHA256 mismatch. expected={args.file_sha256} got={got}")

    try:
        with open(args.out, "wb") as f:
            f.write(plain)
    except Exception as e:
        print(f"Failed to write output file: {e}", file=sys.stderr)
        sys.exit(5)

    print(f"Decrypted media saved to: {args.out}")


if __name__ == "__main__":
    main()