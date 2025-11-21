from cryptography.hazmat.primitives.ciphers.aead import AESGCM

"""
    AES-GCM is an AEAD cipher (Authenticated Encryption with Associated Data).
    
    AES (Advanced Encryption Standard) provides the encryption,
    GCM (Galois/Counter Mode) provides message integrity and authentication (MAC)
    
    Together, this ensures both confidentiality and authenticity of messages.

    I have added a detailed description of AESGCM in the documentation.
"""

def encrypt_message(session_key: bytes, plaintext: str, nonce: bytes) -> bytes:
    """
    Encrypt a plaintext message using AES-GCM.
    
    Args:
        session_key: symmetric key derived from HKDF
        plaintext: message to encrypt
        nonce: 12-byte unique nonce for this message
    Returns:
        ciphertext: encrypted bytes
    """
    aead = AESGCM(session_key)
    return aead.encrypt(nonce, plaintext.encode(), None)

def decrypt_message(session_key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    """
    Decrypt a ciphertext message using AES-GCM.
    
    Args:
        session_key: symmetric key derived from HKDF
        ciphertext: encrypted bytes
        nonce: same nonce used for encryption
    Returns:
        plaintext: decrypted string
    """
    aead = AESGCM(session_key)
    return (aead.decrypt(nonce, ciphertext, None)).decode()
