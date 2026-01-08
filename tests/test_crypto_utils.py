import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidTag

from tls.utils.crypto_utils import encrypt_message, decrypt_message, to_b64, from_b64, public_key_to_bytes

# Test encryption and decryption roundtrip
def test_encrypt_decrypt_roundtrip():
    session_key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    plaintext = "I love cats"

    ciphertext = encrypt_message(session_key, plaintext, nonce)
    decrypted = decrypt_message(session_key, ciphertext, nonce)

    assert decrypted == plaintext

# Test encryption and decryption determinsim
def test_encrypt_decrypt_determinism():
    session_key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    plaintext = "I love cats"

    ciphertext_1 = encrypt_message(session_key, plaintext, nonce)
    ciphertext_2 = encrypt_message(session_key, plaintext, nonce)

    plaintext_1 = decrypt_message(session_key, ciphertext_1, nonce)
    plaintext_2 = decrypt_message(session_key, ciphertext_2, nonce)

    assert ciphertext_1 == ciphertext_2
    assert plaintext_1 == plaintext_2 == plaintext

# Test decryption fails with wrong key
def test_encrypt_decrypt_key_faik():
    session_key_1 = AESGCM.generate_key(bit_length=128)
    session_key_2 = AESGCM.generate_key(bit_length=128)

    while session_key_1 == session_key_2:
        session_key_2 = AESGCM.generate_key(bit_length=128)
    

    nonce = os.urandom(12)
    plaintext = "I love cats"

    ciphertext = encrypt_message(session_key_1, plaintext, nonce)

    with pytest.raises(InvalidTag):
        decrypt_message(session_key_2, ciphertext, nonce)

# Test decryption fails with wrong nonce
def test_encrypt_decrypt_nonce_fail():
    session_key = AESGCM.generate_key(bit_length=128)

    nonce_1 = os.urandom(12)
    nonce_2 = os.urandom(12)

    while nonce_1 == nonce_2:
        nonce_2 = os.urandom(12)

    plaintext = "I love cats"

    ciphertext = encrypt_message(session_key, plaintext, nonce_1)

    with pytest.raises(InvalidTag):
        decrypt_message(session_key, ciphertext, nonce_2)

# Test base 64 encoding and decoding
def test_base64_encode_decode():
    original_bytes = os.urandom(32)
    b64_str= to_b64(original_bytes)
    decoded_bytes = from_b64(b64_str)

    assert decoded_bytes == original_bytes

# Test public key to bytes conversion
def test_public_key_to_bytes():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_raw_bytes = public_key_to_bytes(public_key)
    assert isinstance(public_raw_bytes, bytes)



