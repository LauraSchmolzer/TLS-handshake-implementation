import threading
import socket
from crypto_utils import *

"""
    As I wish the server to be able to send and listen/receive a message at the
    same time I have implemented threading. 

    In this way we have one thread listening and one thread sending.
"""


import threading
import socket
from crypto_utils import *

def listen_thread(conn, session_key, shutdown_event,non_self):
    counter = 0
    try:
        while not shutdown_event.is_set():
            try:
                data = conn.recv(4096)
            except OSError:
                break

            if not data:
                print(f"Connection closed by {non_self}")
                break

            nonce = data[:12]
            ciphertext = data[12:]

            try:
                plaintext = decrypt_message(session_key, ciphertext, nonce)
            except Exception:
                # Ignore decryption failures if connection is closing
                break

            if plaintext.lower() == "exit":
                print(f"{non_self} closed the connection.")
                shutdown_event.set()
                break
            else:
                print(f"\nReceived message: {plaintext}")
            counter += 1
    finally:
        shutdown_event.set()
        try: conn.shutdown(socket.SHUT_RDWR)
        except: pass
        try: conn.close()
        except: pass

def send_thread(conn, session_key, shutdown_event):
    counter = 0
    try:
        while not shutdown_event.is_set():
            msg = input(" ")
            nonce = counter.to_bytes(12, "big")
            if msg.lower() == "exit":
                try:
                    ciphertext = encrypt_message(session_key, msg, nonce)
                    conn.sendall(nonce + ciphertext)
                except:
                    pass
                print("Closing connection…")
                shutdown_event.set()
                break
            else:
                ciphertext = encrypt_message(session_key, msg, nonce)
                try:
                    conn.sendall(nonce + ciphertext)
                except:
                    shutdown_event.set()
                    break
            counter += 1
    finally:
        shutdown_event.set()
        try: conn.shutdown(socket.SHUT_RDWR)
        except: pass
        try: conn.close()
        except: pass



def send_thread(conn, session_key, shutdown_event):
    counter = 0
    try:
        while not shutdown_event.is_set():
            msg = input(" ")
            nonce = counter.to_bytes(12, "big")
            if msg.lower() == "exit":
                try:
                    ciphertext = encrypt_message(session_key, msg, nonce)
                    conn.sendall(nonce + ciphertext)
                except:
                    pass
                print("Closing connection…")
                shutdown_event.set()
                break
            else:
                ciphertext = encrypt_message(session_key, msg, nonce)
                try:
                    conn.sendall(nonce + ciphertext)
                except:
                    shutdown_event.set()
                    break
            counter += 1
    finally:
        shutdown_event.set()
        try: conn.shutdown(socket.SHUT_RDWR)
        except: pass
        try: conn.close()
        except: pass


