from keys import generate_x25519_keypair
import os
from hellomessage_utils import *

def server():
    """
    This is the Server main function.
    Generates a ServerHello message for the TLS-like handshake
    and prepares the ephemeral key and client random for the next steps.
    
    Returns:
        hello_server (dict): JSON-serializable ServerHello message
        private_key (X25519PrivateKey): ephemeral private key for this session
        server_random (bytes): 32-byte random nonce used in handshake
    """

    print("Server: ServerHello is being initialized.")

    # Build the HelloMessage class for the server
    hello_obj = HelloMessage(role="server")

    # Get the network-ready dictionary
    hello_server= hello_obj.to_dict()

    print("ServerHello generated successfully.")
    print("ServerHello message:", hello_server)  # show message contents

    # Return values needed for handshake continuation
    return hello_server, hello_obj.private_key, hello_obj.random_bytes
  
