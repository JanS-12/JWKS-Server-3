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
from collections import defaultdict
from argon2 import PasswordHasher
from uuid import uuid4
import datetime
import sqlite3
import base64
import time
import json
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
            iv BLOB NOT NULL,
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
    key = os.getenv('NOT_MY_KEY', 'default_key').encode().ljust(32)[:32]
    if not key:
        raise ValueError("Environment variable 'NOT_MY_KEY' is not set")
    return key    

# AES encrypting function (encrypts serialized data)
def encrypt_AES(data):
    NOT_MY_KEY = get_AES_key()     # NOT_MY_KEY
    iv = os.urandom(16)     # Initialization Vector (16-byte) 
    cipher = Cipher(algorithms.AES(NOT_MY_KEY), modes.CBC(iv), backend=default_backend())
    
    # Pad data
    padder = PKCS7(128).padder() # 128-bit block size for AES
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()   
    
    return ciphertext, iv

# AES decrypting function (decrypts data, returns serialized data)
def decrypt_AES(ciphertext, iv):
    NOT_MY_KEY = get_AES_key()         # NOT_MY_KEY
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
    return serialization.load_pem_private_key(pem.encode(), password=None) 
   
# Save the keys to DB
def store_key(encrypted_key, iv, exp):
    with db:
        db.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)", 
            (sqlite3.Binary(encrypted_key), sqlite3.Binary(iv), exp))
        
def get_kid(expired=False):
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    with db:
        if expired:
            result = db.execute("SELECT kid FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
        else:
            result = db.execute("SELECT kid FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
        row = result.fetchone()
    if row:     
        return row[0]
    else:
        print("No kid found")  
    
    return None    
               
# Function to get a key from the database (expired or valid)
def get_key(expired=False):
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    with db:
        if expired:
            result = db.execute("SELECT key, iv FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
        else:
            result = db.execute("SELECT key, iv FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
        row = result.fetchone()
        
    if row:             # Return kid with the corresponding private key 
        encrypted_key, iv = row
        return decrypt_AES(encrypted_key, iv) 
    else:
        print("Key is None")
         
    return None, None

# User registration
def register_user(username, email):
    pwd = str(uuid4())
    pwd_h = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32,salt_len=16)
    hashed_pwd = pwd_h.hash(pwd)
    
    with db:
        db.execute('''
            INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)''',
            (username, hashed_pwd, email))
        
    return pwd    

# Log Auth Requests
def auth_request_log(user_id, request_ip, request_timestamp):
    with db:
        db.execute('''
            INSERT INTO auth_logs (user_id, request_ip, request_timestamp) VALUES (?, ?, ?)''', 
            (user_id, request_ip, request_timestamp))
        
def get_user_id(username):
    with db:
        cursor = db.execute('''SELECT id FROM users WHERE username = ?''', (username,))
        user = cursor.fetchone()
    
    if user:
        return user[0]
    else:
        print("User ID not found")
        
    return None    
    
# Re-using given code for key generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serialize keys to PEM format
private_pem = serialize_key(private_key)
expired_pem = serialize_key(expired_key)
   
# Encrypt serialized keys, and respective IVs
encrypted_private_key_PEM, IV_V = encrypt_AES(private_pem.decode('utf-8'))
encrypted_expired_key_PEM, IV_E = encrypt_AES(expired_pem.decode('utf-8'))   
   
# Store valid key (expiration 1 hour from now)
store_key(encrypted_private_key_PEM, IV_V, int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp()))  

# Store expired key (expired by 5 hours)
store_key(encrypted_expired_key_PEM, IV_E, int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=5)).timestamp()))    

# Commit Changes to DB
db.commit()

# Rate Limiter
def rate_limiter(ip_address, request_count, limit=10):
    current_time = time.time()
    request_times = request_count[ip_address]
    request_times =  [t for t in request_times if current_time - t <= 1] # Filter out past timestamps
    request_count[ip_address] = request_times
    if len(request_times) >= limit:
        return False
    
    request_count[ip_address].append(current_time)
    return True

# HTTP Server logic remains unchanged
class MyServer(BaseHTTPRequestHandler):
    # For unsupported methods --> Key Not Found 
    def not_supported_methods(self):
        self.send_response(404)
        self.end_headers()
    
    request_counts = defaultdict(list)
    
    # Simplificaiton for unused methods          
    do_PUT = do_DELETE = do_HEAD = do_PATCH = not_supported_methods

    # POST Request (/auth)
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            ip = self.client_address[0]         # Get IP address
            
             # Rate Limiter
            if not rate_limiter(ip, MyServer.request_counts):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"The maximum of requests have been reached")
                return
            
            exp = 'expired' in params
            content_length = int(self.headers['Content-Length'])
            post_data =  json.loads(self.rfile.read(content_length))
            username = post_data.get("username")
            
            kid = get_kid(exp)              # Retrieves key ID
            key_pem = get_key(exp)          # Retrieves key PEM
            decrypted_key = deserialize_pem(key_pem)        # Deserialize key PEM

            if decrypted_key:
                headers = {"kid": str(kid) }
                token_payload = {
                    "user": username,
                    "exp": datetime.datetime.now(datetime.UTC) + (datetime.timedelta(hours=-2) if exp else datetime.timedelta(hours=2))
                }

                encoded_jwt = jwt.encode(
                    token_payload, 
                    key_pem.encode(), 
                    algorithm = "RS256", 
                    headers = headers)
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))

                # Log auth request
                user_id = get_user_id(username)
                request_ip = self.client_address[0]
                request_timestamp = datetime.datetime.now(datetime.UTC)
                auth_request_log(user_id, request_ip, request_timestamp)                
            else:
                self.not_supported_methods() # Key not found
                print("No decrypted key")
              
        # "./register endpoint"   
        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length))

            username = post_data.get("username")
            email = post_data.get("email")
            
            if username is not None and email is not None:
                password = register_user(username, email)   # Register user and get pwd
                self.send_response(201)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"password": password}), 'utf-8'))
            else: 
                print("No username nor email")
        
        else: 
            self.send_response(405)
            self.end_headers()
            print("Not valid path")    
        return

    #GET Request (/.well-known/jwks.json)
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Get decrypted key 
            key_pem = get_key(False)              
            jwks = {"keys": []}  #Key Set

            if key_pem:
             #   k_pem = valid_key[0]
                key = deserialize_pem(key_pem)
                numbers = key.private_numbers()
                
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "0",
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
       # db.execute("""DROP TABLE IF EXISTS keys""") # Only for debugging purposes
        db.close()
        pass

    webServer.server_close()


    
