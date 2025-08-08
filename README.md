## WhatsApp media decrypt

A simple CLI to decrypt WhatsApp media (audio, image, video, document, sticker) when you have the direct media URL and the message's mediaKey.

- **AES-256-CBC decryption** with **HKDF-SHA256** key derivation
- **MAC verification** (first 10 bytes of HMAC-SHA256 over IV || ciphertext)
- Supports media types: `audio`, `image`, `video`, `document`, `sticker` (aliases: `ptt`, `voice`)


### Requirements
- Python 3.8+
- Packages: `cryptography`, `requests`

Install dependencies:

```bash
pip install -r requirements.txt
```


### Quick start

```bash
python3 whatsapp_media_decrypt.py \
  --url "https://mmg.whatsapp.net/d/f/AbCd...xyz.enc" \
  --media-key "BASE64_MEDIA_KEY_FROM_MESSAGE==" \
  --media-type audio \
  --out output.ogg
```

This will download the encrypted payload, verify the MAC, decrypt it, and save the plaintext media to `output.ogg`.


### CLI usage

```bash
python3 whatsapp_media_decrypt.py \
  --url <DIRECT_MEDIA_URL> \
  --media-key <BASE64_MEDIA_KEY> \
  --media-type <audio|image|video|document|sticker|ptt|voice> \
  --out <OUTPUT_FILE> \
  [--file-sha256 <B64_SHA256_OF_DECRYPTED>] \
  [--file-enc-sha256 <B64_SHA256_OF_ENCRYPTED>] \
  [--insecure-skip-mac]
```

- **--url**: Direct CDN URL to the encrypted media (typically ends with `.enc`).
- **--media-key**: Base64 `mediaKey` from the WhatsApp message (32 raw bytes, base64-encoded).
- **--media-type**: One of `audio`, `image`, `video`, `document`, `sticker` (aliases: `ptt`, `voice`). Determines HKDF info string.
- **--out**: Path to write the decrypted media file.
- **--file-sha256**: Optional expected base64 SHA256 of the decrypted file. Prints a warning if it does not match.
- **--file-enc-sha256**: Optional expected base64 SHA256 of the encrypted payload. Prints a warning if it does not match.
- **--insecure-skip-mac**: Decrypts without verifying the MAC (not recommended). Useful for debugging only.


### Examples

- **Decrypt an audio note (OGG/OPUS)**

```bash
python3 whatsapp_media_decrypt.py \
  --url "https://mmg.whatsapp.net/d/f/AbCdEfGh...enc" \
  --media-key "m0Qn9t3Ck0yC1n4Q1kS8T6jJYyT1c8m0u8V7w9X1y2A=" \
  --media-type audio \
  --out output.ogg
```

- **With integrity checks** (both encrypted and decrypted):

```bash
python3 whatsapp_media_decrypt.py \
  --url "https://mmg.whatsapp.net/d/f/AbCdEfGh...enc" \
  --media-key "BASE64_MEDIA_KEY==" \
  --media-type image \
  --out photo.jpg \
  --file-enc-sha256 "encrPayloadSha256Base64==" \
  --file-sha256 "plainFileSha256Base64=="
```


### Programmatic usage (optional)

You can reuse the key-derivation and decryption helpers from Python. Ensure the script is on your `PYTHONPATH` or run from this directory.

```python
from whatsapp_media_decrypt import hkdf_derive_keys, decrypt_media
import base64

# Inputs from your message
media_key_b64 = "BASE64_MEDIA_KEY=="
media_type = "image"  # or audio/video/document/sticker
enc_bytes = open("payload.enc", "rb").read()  # or download yourself

iv, cipher_key, mac_key = hkdf_derive_keys(base64.b64decode(media_key_b64), media_type)
plain = decrypt_media(enc_bytes, iv, cipher_key, mac_key)
open("output.bin", "wb").write(plain)
```


### Notes and troubleshooting
- **403/404 when downloading**: Make sure you use the direct URL from the message and that it has not expired.
- **MAC verification failed**: The mediaKey, media type, or payload may be incorrect or truncated. Double-check the `mediaKey` and the `media-type`. As a last resort for debugging, try `--insecure-skip-mac` to see if padding/decryption would otherwise succeed.
- **Unsupported media type**: See the supported list above; stickers use the same key info as `image`.


### Disclaimer
This tool is for educational and interoperability purposes only. Only decrypt media you have a legal right to access.