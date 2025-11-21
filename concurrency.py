import threading
import socket
from crypto_utils import *

"""
    As I wish the server to be able to send and listen/receive a message at the
    same time I have implemented threading. 

    In this way we have one thread listening and one thread sending.
"""

def listen_thread(conn, session_key, non_self):
    while True:
        try:
            data = conn.recv(4096)  # or implement length-prefixed reading
            if not data:
                print("Connection closed by " + non_self)
                break
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = decrypt_message(session_key, ciphertext, nonce)
            print("\nReceived message:", plaintext)
        except OSError as e:
            print("Socket error in listen_thread:", e)
            break
        except Exception as e:
            print("Decryption failed:", e)



def send_thread(conn, session_key):
    counter = 0 # Nonce must be unique for each message, therefor the counter
    while True:
        msg = input("Send a Message: ")
        nonce = counter.to_bytes(12, "big")
        ciphertext = encrypt_message(session_key, msg, nonce)
        conn.sendall(nonce + ciphertext)
        counter += 1


