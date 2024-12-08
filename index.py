# Name: Jan Smith  
# EUID: js2019
# Student ID: 11536897
# Course: CSCE 3550

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends  import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import datetime
import sqlite3
import base64
import json
import uuid
import jwt
import os

hostName = "localhost"
serverPort = 8080

# Database file
db_file = "totally_not_my_privateKeys.db"

# Connect to DB 
db = sqlite3.connect(db_file)

# Create 'keys' table
db.execute(
    '''CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL)''')

# Create 'users' table
db.execute(
    '''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP)''')

# Create 'auth_logs' table
db.execute(
    '''CREATE TABLE IF NOT EXISTS auth_logs(   
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        request_ip TEXT NOT NULL, 
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER, 
        FOREIGN KEY(user_id) REFERENCES users(id)    
    );''')

# Get environment variable
def get_AES_key():
    key = os.getenv("NOT_MY_KEY")
    if not key:
        raise ValueError("Environment variabel 'NOT_MY_KEY' is not set")
    return bytes.fromhex(key)    

# AES encrypting function
def encrypt_AES(data: bytes) -> dict:
    NOT_MY_KEY = get_AES_key()     # NOT_MY_KEY
    iv = os.urandom(16)     # Initialization Vector (16-byte) 
    cipher = Cipher(algorithms.AES(NOT_MY_KEY), modes.CBC(iv), backend=default_backend())
    
    # Pad data
    padder = PKCS7(128).padder() # 128-bit block size for AES
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()   
    
    return {"ciphertext": ciphertext, "iv": iv}

# AES decrypting function
def decrypt_AES(data: dict) -> bytes:
    NOT_MY_KEY = get_AES_key()         # NOT_MY_KEY
    iv = data["iv"]             # Initialization Vector (16-byte)
    ciphertext = data["ciphertext"]         # Encrypted Data
    
    cipher = Cipher(algorithms.AES(NOT_MY_KEY), modes.CBC(iv), backend=default_backend)
    
    # Decrypt ciphertext
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove Padding
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

# Re-using code for integer conversion to Base64URL
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Serialize key to PEM format
def serialize_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )
    
# Deserialize key from PEM format    
def deserialize_pem(pem):
    return serialization.load_pem_private_key(pem, password=None) 
   
# Save the keys to DB
def store_key(k_pem, exp):
    with db:
        db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (k_pem, exp))
        
# Function to get a key from the database (expired or valid)
def get_key(expired=False):
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp)
    
    with db:
        if expired:
            result = db.execute("SELECT key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
        else:
            result = db.execute("SELECT key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
        row = result.fetchone()
        
    if row:             # Return kid with the corresponding private key 
        return row[0], deserialize_pem(decrypt_AES(row[1]))      
    return None, None
    
# Re-using given code for key generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serialize keys
private_pem = serialize_key(private_key)
expired_pem = serialize_key(expired_key)
   
# Encrypt serialized keys, and respective IVs
encrypted_private_key, IV_V = encrypt_AES(private_pem.encode('utf-8'))
encrypted_expired_key, IV_E = encrypt_AES(expired_pem.encode('utf-8'))   

current_time = int(datetime.datetime.now(datetime.UTC))
   
# Store valid key (expiration 1 hour from now)
store_key(encrypted_private_key.decode(), current_time + datetime.timedelta(hours=1).timestamp())  

# Store expired key (expired by 5 hours)
store_key(encrypted_expired_key.decode(), current_time - datetime.timedelta(hours=5).timestamp())    

db.commit()

# HTTP Server logic remains unchanged
class MyServer(BaseHTTPRequestHandler):
    # For unsupported methods --> Key Not Found 
    def not_supported_methods(self):
        self.send_response(404)
        self.end_headers()
    
    # Simplificaiton for unused methods          
    do_PUT = do_DELETE = do_HEAD = do_PATCH = not_supported_methods

    # POST Request (/auth)
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            exp = 'expired' in params
            row = get_key(exp)            
            
            # For each 'auth' request, log the following into the 'auth_logs' table:
                # Request IP Address
                # Timestamp of the request
                # User ID of the username

            if row:
                k_pem = row[0]      # Index 0 is pem, Index 1 is exp
                headers = {"kid": "expiredKID" if exp else "goodKID"}

                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.UTC) + (datetime.timedelta(hours=-2) if exp else datetime.timedelta(hours=2))
                }

                encoded_jwt = jwt.encode(
                    token_payload, 
                    k_pem.encode(), 
                    algorithm = "RS256", 
                    headers = headers)
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.not_supported_methods() # Key not found
        #elif parsed_path.path == "/register":
        return

    #GET Request (/.well-known/jwks.json)
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Get valid key 
            valid_key = get_key(False)              
            jwks = {"keys": []}  #Key Set

            if valid_key:
                k_pem = valid_key[0]
                key = serialization.load_pem_private_key(k_pem.encode(), password = None)

                numbers = key.private_numbers()
                
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                
                jwks["keys"].append(jwk)

            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
        else:
            self.not_supported_methods() # Not found
            
        return

print("Starting server on port 8080!")

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        #db.execute("""DROP TABLE IF EXISTS keys""") # Only for debugging purposes
        db.close()
        pass

    webServer.server_close()


    
