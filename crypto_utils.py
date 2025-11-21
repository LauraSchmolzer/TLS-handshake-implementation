from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
"""
    This means ChaCha20 is used for encryption, 
    it is a stream cipher that is fast and secure

    Poly1205 is a message authentication code (MAC),
    ensuring message authenticity and integrity

    Together is is an AEAD cipher (Authenticated Encryption with Associated Data)
"""

def encrypt_message(session_key: bytes, plaintext: str, nonce: bytes) -> bytes:
    """
    Encrypt a plaintext message using ChaCha20-Poly1305.
    
    Args:
        session_key: symmetric key derived from HKDF
        plaintext: message to encrypt
        nonce: 12-byte unique nonce for this message
    Returns:
        ciphertext: encrypted bytes
    """
    aead = ChaCha20Poly1305(session_key)
    return aead.encrypt(nonce, plaintext.encode(), None)

def decrypt_message(session_key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    """
    Decrypt a ciphertext message using ChaCha20-Poly1305.
    
    Args:
        session_key: symmetric key derived from HKDF
        ciphertext: encrypted bytes
        nonce: same nonce used for encryption
    Returns:
        plaintext: decrypted string
    """
    aead = ChaCha20Poly1305(session_key)
    return aead.decrypt(nonce, ciphertext, None).decode()
