
import threading
import socket
import json
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sqlite3
from pyt import conn

# Store user prekey bundles
prekey_store = {}
message_store = {}

SERVER_HOST = 'localhost'  # The hostname of the server that the client will connect to.
SERVER_PORT = 65432  # The port number on which the server is listening for incoming connections.

def handle_client(conn, addr):
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break
            request = json.loads(data)
            action = request.get("action")

            if action == "register":
                user = request["user"]
                prekey_store[user] = request["prekey_bundle"]
                conn.send(json.dumps({"status": "registered"}).encode())

            elif action == "fetch_prekey":
                user = request["user"]
                bundle = prekey_store.get(user)
                conn.send(json.dumps({"prekey_bundle": bundle}).encode())

            elif action == "send_message":
                recipient = request["recipient"]
                message = request["message"]
                if recipient in message_store:
                    message_store[recipient].append(message)
                else:
                    message_store[recipient] = [message]
                conn.send(json.dumps({"status": "message_sent"}).encode())

            elif action == "retrieve_messages":
                user = request["user"]
                messages = message_store.get(user, [])
                message_store[user] = []
                conn.send(json.dumps({"messages": messages}).encode())

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()

# Startet einen TCP-Server, der auf eingehende Verbindungen wartet.
def start_server(host='localhost', port=65432):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"Server listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()




def generate_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# Serializes a public key into a hexadecimal string format.
def serialize_key(key):
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()

# Deserializes a public key from its hexadecimal string representation.
def deserialize_key(hex_key):
        return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))

# Registers a user with their prekey bundle on the server.
def register_user(user, prekey_bundle):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            request = {
                "action": "register",
                "user": user,
                "prekey_bundle": prekey_bundle
            }
            s.send(json.dumps(request).encode())
            response = json.loads(s.recv(4096).decode())
            print(response)

# Fetches the prekey bundle of a specified user from the server.
#     Parameters:
#     user (str): The username of the user whose prekey bundle is to be fetched.
#     Returns:
#     dict: The prekey bundle of the user, containing public keys (ik, spk, opk).
def fetch_prekey(user):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            request = {
                "action": "fetch_prekey",
                "user": user
            }
            s.send(json.dumps(request).encode())
            response = json.loads(s.recv(4096).decode())
            return response.get("prekey_bundle")

# Sends an encrypted message from a sender to a recipient.
#     Parameters:
#     sender (str): The username of the sender.
#     recipient (str): The username of the recipient.
#     message (dict): The message content, which should be encrypted.
def send_message(sender, recipient, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        request = {
                "action": "send_message",
                "recipient": recipient,
                "message": {
                    "sender": sender,
                    "content": message  # This should be encrypted
                }
            }
        s.send(json.dumps(request).encode())
        response = json.loads(s.recv(4096).decode())
        print(response)

# Retrieves messages for a specified user from the server.
def retrieve_messages(user):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            request = {
                "action": "retrieve_messages",
                "user": user
            }
            s.send(json.dumps(request).encode())
            response = json.loads(s.recv(4096).decode())
            return response.get("messages")


#  Usage
if __name__ == "__main__":
        # Generate keys for Alice
        alice_ik, alice_ik_pub = generate_key_pair()
        alice_spk, alice_spk_pub = generate_key_pair()
        alice_opk, alice_opk_pub = generate_key_pair()

alice_bundle = {
            "ik": serialize_key(alice_ik_pub),
            "spk": serialize_key(alice_spk_pub),
            "opk": serialize_key(alice_opk_pub)
        }

# Register Alice
register_user("Alice", alice_bundle)

# Similarly, generate and register Bob's keys
bob_ik, bob_ik_pub = generate_key_pair()
bob_spk, bob_spk_pub = generate_key_pair()
bob_opk, bob_opk_pub = generate_key_pair()

bob_bundle = {
            "ik": serialize_key(bob_ik_pub),
            "spk": serialize_key(bob_spk_pub),
            "opk": serialize_key(bob_opk_pub)
        }

# Register Bob
register_user("Bob", bob_bundle)

# Alice wants to send a message to Bob
bob_prekey = fetch_prekey("Bob")
if bob_prekey:
            # Deserialize Bob's keys
            bob_ik_pub = deserialize_key(bob_prekey["ik"])
            bob_spk_pub = deserialize_key(bob_prekey["spk"])
            bob_opk_pub = deserialize_key(bob_prekey["opk"])

# X3DH Key Agreement Steps
# DH1: Alice's IK * Bob's SPK
dh1 = alice_ik.exchange(bob_spk_pub)

# DH2: Alice's EK * Bob's IK
# Assuming Alice has an ephemeral key
alice_ek, alice_ek_pub = generate_key_pair()
dh2 = alice_ek.exchange(bob_ik_pub)

# DH3: Alice's EK * Bob's SPK
dh3 = alice_ek.exchange(bob_spk_pub)

# DH4: Alice's OPK * Bob's SPK
dh4 = alice_opk.exchange(bob_spk_pub)

# Combine shared secrets
shared_secret = dh1 + dh2 + dh3 + dh4

# Derive a session key
salt = os.urandom(16)  # Salt generieren
session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'X3DH Key Agreement',
            ).derive(shared_secret)

# Encrypt the message
nonce = os.urandom(12)
cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"Hello Bob!") + encryptor.finalize()
tag = encryptor.tag

encrypted_message = {
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex()  }

# Send the encrypted message
send_message("Alice", "Bob", encrypted_message)

# Bob retrieves the message
messages = retrieve_messages("Bob")
for msg in messages:
        sender = msg["sender"]
        encrypted = msg["content"]
        if sender == "Alice":
                # Reconstruct session key
                # Normally, Bob would perform his own version of X3DH to derive the same session key
                # For demonstration, assuming the session key is known
                # Decrypt the message
                nonce = bytes.fromhex(encrypted["nonce"])
                ciphertext = bytes.fromhex(encrypted["ciphertext"])
                tag = bytes.fromhex(encrypted["tag"])

                cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                print(f"Bob received: {plaintext.decode()}")

# ------------------------------------------------------------------------------------------------------
 # Bonus: Allowing Recipient to Be Offline
 # Continuing from the previous server code...


# Initialize SQLite database
conn_db = sqlite3.connect('server.db', check_same_thread=False)
cursor = conn_db.cursor()
cursor.execute('''
     CREATE TABLE IF NOT EXISTS users (
         username TEXT PRIMARY KEY,
         ik TEXT, spk TEXT, opk TEXT ) '''
               )
try:
 cursor.execute('''
     CREATE TABLE IF NOT EXISTS messages (   recipient TEXT,
         sender TEXT,
         nonce TEXT,
         ciphertext TEXT,
         tag TEXT ) ''')
 conn_db.commit()
except Exception as e:
    print(f"Database error: {e}")
    conn.send(json.dumps({"error": "Database operation failed"}).encode())

# Manages communication with a connected client.
#  This function processes incoming requests from the client, handling actions such as user registration,
#     fetching prekey bundles, sending messages, and retrieving messages. It operates in a loop until the
#     connection is closed or an error occurs.
#     Parameters:
#     conn (socket.socket): The socket connection to the client.
#     addr (tuple): The address of the connected client (host, port).
#     Actions:
#     - register: Registers a user with their prekey bundle.
#     - etch_prekey: Retrieves the prekey bundle for a specified user.
#     - send_message: Stores a message sent from one user to another.
#     - retrieve_messages: Retrieves messages for a specified user and clears them from storage.
def handle_client(conn, addr):
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break
            request = json.loads(data)
            action = request.get("action")

            if action == "register":
                user = request["user"]
                prekey = request["prekey_bundle"]
                cursor.execute('REPLACE INTO users (username, ik, spk, opk) VALUES (?, ?, ?, ?)',
                               (user, prekey["ik"], prekey["spk"], prekey["opk"]))
                conn_db.commit()
                conn.send(json.dumps({"status": "registered"}).encode())

            elif action == "fetch_prekey":
                user = request["user"]
                cursor.execute('SELECT ik, spk, opk FROM users WHERE username=?', (user,))
                row = cursor.fetchone()
                if row:
                    bundle = {"ik": row[0], "spk": row[1], "opk": row[2]}
                    conn.send(json.dumps({"prekey_bundle": bundle}).encode())
                else:
                    conn.send(json.dumps({"error": "User not found"}).encode())

            elif action == "send_message":
                recipient = request["recipient"]
                message = request["message"]
                cursor.execute(
                    'INSERT INTO messages (recipient, sender, nonce, ciphertext, tag) VALUES (?, ?, ?, ?, ?)',
                    (recipient, message["sender"], message["content"]["nonce"],
                     message["content"]["ciphertext"], message["content"]["tag"]))
                conn_db.commit()
                conn.send(json.dumps({"status": "message_stored"}).encode())

            elif action == "retrieve_messages":
                user = request["user"]
                cursor.execute('SELECT sender, nonce, ciphertext, tag FROM messages WHERE recipient=?', (user,))
                rows = cursor.fetchall()
                messages = [{"sender": row[0],
                             "content": {"nonce": row[1],
                                         "ciphertext": row[2],
                                         "tag": row[3]}} for row in rows]
                cursor.execute('DELETE FROM messages WHERE recipient=?', (user,))
                conn_db.commit()
                conn.send(json.dumps({"messages": messages}).encode())

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()

