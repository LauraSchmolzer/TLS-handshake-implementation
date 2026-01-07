from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from  crypto_utils import to_b64, from_b64, public_key_to_bytes

class CertificateAuthority:
    """
        Represents a trusted third-party Certificate Authority (CA).

        Purpose:
        Responsible for binding an identity to a public key. 
        It does this by signing the public key, forming a 
        certificate. Any client who trusts the CA's public key can verify 
        certificates issued by it.

        Responsibilities:
        - Sign identity public keys to create certificates
        - Verify certificates it previously issued
        - Act as a trust anchor in TLS system
    """
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate() # This will essentially sign the subject’s public key
        self.public = self.private.public_key() # This can be distributed to all clients

    def issue_certificate(self, public_key_bytes: bytes, identity: str) -> "Certificate" :
        # Generate the signature: CA's private key over certificate public key
        signature = self.private.sign(public_key_bytes)
        # Initialize the Certificate
        return Certificate(identity, public_key_bytes, signature)
    
    def verify(self, certificate: "Certificate") -> bool :
        self.public.verify(certificate.signature, certificate.public_key)
        return True
    
    # Return raw 32-byte public key bytes for certificates or network use
    def to_bytes(self) -> bytes :
        return public_key_to_bytes(self.public)

class Certificate:
    """
        Object of the Certificate

        Args:
            identity (str): identity of the Certificate
            public key (bytes): The Ed25519 public key of the certificate owner. 
                                This is the key the CA is certifying
            signature (bytes): A signature produced by the CA's private key over `public_key`.
    """
    def __init__(self, identity: str, public_key: bytes , signature: bytes):
        self.identity = identity
        self.public_key = public_key
        self.signature = signature
     
    def to_dict(self) -> dict:
        """
            Serialize the certificate to a dictionary ready for network transmission
        """
        return {
            "identity": self.identity,
            "public_key": to_b64(self.public_key),
            "signature": to_b64(self.signature)
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        """Reconstruct a certificate from JSON-safe dict."""
        pub_bytes = from_b64(d["public_key"])
        sig_bytes = from_b64(d["signature"])
        identity = d["identity"]
        return cls(identity, pub_bytes, sig_bytes)

class IdentityKeypair:
    """
    Represents a long-term Ed25519 identity keypair, which 
    represents the cryptographic identity of an endpoint

    Purpose:
      - Signing handshake transcripts (authenticating the endpoint)
      - Proving ownership of a certificate
      - Verifying signatures from the remote peer

    """
    def __init__(self):
        # Generate a long-term Ed25519 identity keypair
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    # Sign the message using the private key
    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    # Verify the signature using the message and public key
    def verify(self, signature: bytes, message: bytes) -> bool:
        return self.public.verify(signature, message)
    
    # Return raw 32-byte public key bytes for certificates or network use
    def to_bytes(self) -> bytes:
        return public_key_to_bytes(self.public)


