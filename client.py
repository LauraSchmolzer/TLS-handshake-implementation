# This file simulates the Client
import socket
import json
from hellomessage_utils import *

HOST = "127.0.0.1"
PORT = 4444

"""
    As TLS 1.3 is Client-initated the HelloClient will be generated 
    before the Client will connect to the server and send the request
"""

print("Client: ClientHello is being initialized.")

# Build the HelloMessage class for the client
hello_obj = HelloMessage(role="client")

# Get the network-ready dictionary
hello_client = hello_obj.to_dict()

print("ClientHello generated successfully.")
print("ClientHello message:", hello_client)  # show message contents

# Now the Client connects to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Send ClientHello
    s.sendall(json.dumps(hello_client).encode())
    
    # Receive ServerHello
    data = s.recv(4096)
    hello_server = json.loads(data.decode())
    
    # Compute shared secret
    server_pub_bytes = base64.b64decode(hello_server["x25519_pub"])

    server_pub_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = hello_obj.private_key.exchange(server_pub_key)
    
    print("Client: Shared secret computed!")


  



    



    







