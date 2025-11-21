from keys import generate_x25519_keypair
import os
from hellomessage_utils import *

def client():
    """
    This is the Client main function.
    Generates a ClientHello message for the TLS-like handshake
    and prepares the ephemeral key and client random for the next steps.
    
    Returns:
        hello_client (dict): JSON-serializable ClientHello message
        private_key (X25519PrivateKey): ephemeral private key for this session
        client_random (bytes): 32-byte random nonce used in handshake
    """

    print("Client: ClientHello is being initialized.")

    # Build the HelloMessage class for the client
    hello_obj = HelloMessage(role="client")

    # Get the network-ready dictionary
    hello_client = hello_obj.to_dict()

    print("ClientHello generated successfully.")
    print("ClientHello message:", hello_client)  # show message contents

    # Return values needed for handshake continuation
    return hello_client, hello_obj.private_key, hello_obj.random_bytes
  



    



    







