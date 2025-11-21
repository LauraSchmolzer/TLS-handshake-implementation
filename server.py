# This file simulates the Server
import socket
import json
from hellomessage_utils import *

HOST = "127.0.0.1"
PORT = 4444

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    """
        We open a socket for the server such that it can listen to incoming requests
    """
    s.bind((HOST, PORT))
    s.listen(1)
    print("Server: Listening for client...")

    # Here we accept the request and we start with TLS session
    conn, addr = s.accept()
    with conn:
        print("Server: Connected by", addr)
        
        # Receive ClientHello
        data = conn.recv(4096)
        hello_client = json.loads(data.decode())
        
        # Create ServerHello
        server_hello_obj = HelloMessage("server")
        hello_server = server_hello_obj.to_dict()
        
        # We send back the ServerHello to the Client
        conn.sendall(json.dumps(hello_server).encode())
        
        # Compute shared secret
        client_pub_bytes = base64.b64decode(hello_client["x25519_pub"])
        from cryptography.hazmat.primitives.asymmetric import x25519
        client_pub_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = server_hello_obj.private_key.exchange(client_pub_key)
        
        print("Server: Shared secret computed!")

    

  
