import threading
from tls.utils.crypto_utils import AESGCM_session_key, recreate_HelloMessage_public_key, from_b64
from tls.hellomessage import HelloMessage
from tls.utils.concurrency_utils import listen_thread, send_thread

HOST = "127.0.0.1"
PORT = 4444

class TLSContext:
    # TLS context for client and server communication
    def __init__(self, role, host=HOST, port=PORT):
        self.role = role
        self.peer = 'server' if role=='client' else 'client'

        self.host = host 
        self.port = port

        self.sock = None
        self.conn = None
        self.addr = None
        self.active_socket = None

        self.hello_obj = None
        self.hello_peer_obj = None
        self.hello_dict = None
        self.hello_peer_dict = None

        self.shared_secret = None
        self.session_key = None
        self.server_identity = None
        self.server_certificate = None
        self.ca_pub_b64 = None
        self.peer_pub_key = None
        self.peer_pub_bytes = None

        self.shutdown_event = threading.Event()

    # Shared cryptographic operations
    def generate_hello(self):

        self.hello_obj = HelloMessage( role=self.role, certificate=self.server_certificate or None)
        self.hello_dict = self.hello_obj.to_dict()

        if self.role == "server":
            # Add the public key to the message to send over the network 
            self.hello_dict["ca_pub"] = self.ca_pub_b64


    def compute_keys(self):
        # From the PeerHello message, retrieve the public bytes and public key
        peer_pub_bytes = from_b64(self.hello_peer_dict["public_bytes"])
        peer_pub_key = recreate_HelloMessage_public_key(peer_pub_bytes)
        self.shared_secret = self.hello_obj.private_key.exchange(peer_pub_key)

        # Generate the Session keys from AESGCM
        # Both sides
        client_random = from_b64(self.hello_peer_dict["client_random"]) if self.role == "server" else self.hello_obj.random_bytes
        server_random = from_b64(self.hello_peer_dict["server_random"]) if self.role == "client" else self.hello_obj.random_bytes

        self.session_key = AESGCM_session_key(client_random, server_random, self.shared_secret)


    def start_communication(self):
        threading.Thread(target=listen_thread, args=(self.active_socket, self.session_key, self.shutdown_event, self.peer), daemon=True).start()
        send_thread(self.active_socket, self.session_key, self.shutdown_event)
