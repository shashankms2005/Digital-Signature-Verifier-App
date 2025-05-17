from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from uuid import uuid4
from datetime import datetime

app = Flask(__name__)

# Helper functions - moved to the top for proper reference
def pad_message(data):
    """PKCS#7 padding"""
    block_size = 16  # AES block size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad_message(data):
    """Remove PKCS#7 padding"""
    padding_length = data[-1]
    return data[:-padding_length]

def generate_fingerprint(message):
    """Generate a SHA-256 fingerprint of the message for integrity verification"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8') if isinstance(message, str) else message)
    return base64.b64encode(digest.finalize()).decode('utf-8')

def get_timestamp():
    """Generate a formatted timestamp string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Store session data
sessions = {}

# Generate RSA key pair for server
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

# Serialize the server keys to PEM format
server_private_pem = server_private_key.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
).decode('utf-8')

server_public_pem = server_public_key.public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

@app.route('/')
def index():
    # Create a new session for this client
    session_id = str(uuid4())
    sessions[session_id] = {
        'encryption_key': None,
        'client_public_key': None,
        'shared_secret': None
    }
    # In a real app, you would set this as a cookie
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign_message():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Sign the message
    try:
        signature = server_private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Convert binary signature to base64 for easier JSON transport
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        return jsonify({
            'message': message, 
            'signature': signature_b64
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.json
    message = data.get('message', '')
    signature_b64 = data.get('signature', '')
    
    if not message or not signature_b64:
        return jsonify({'error': 'Message and signature are required'}), 400
    
    try:
        # Convert base64 signature back to binary
        signature = base64.b64decode(signature_b64)
        
        # Verify the signature
        server_public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return jsonify({'status': 'valid', 'message': 'Valid Signature! Message integrity confirmed.'})
    
    except Exception as e:
        return jsonify({'status': 'invalid', 'message': 'Invalid Signature! Message may have been tampered with.'})

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    try:
        # Create a unique message ID for tracking
        message_id = str(uuid4())[:8]
        
        # For simplicity, we'll use a random symmetric key for each encryption
        # In production, this would come from a secure key exchange
        key = os.urandom(32)  # 256-bit key for AES
        iv = os.urandom(16)   # 128-bit IV for AES-CBC
        
        # Create and use cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad the message to be a multiple of block size (16 bytes for AES)
        padded_message = pad_message(message.encode('utf-8'))
        
        # Encrypt the message
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Calculate message fingerprint for integrity verification
        fingerprint = generate_fingerprint(message)
        
        # Prepare payload with all needed components
        payload = {
            'id': message_id,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'key': base64.b64encode(key).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'fingerprint': fingerprint,
            'timestamp': get_timestamp()
        }
        
        # In a real app, the key would be encrypted with the recipient's public key
        # For demo purposes, we're just storing it with the payload
        payload_json = json.dumps(payload)
        encrypted_payload = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
        
        # Store encryption details in the app's memory for logging purposes
        app.encryption_log = getattr(app, 'encryption_log', {})
        app.encryption_log[message_id] = {
            'original_length': len(message),
            'encrypted_length': len(encrypted_payload),
            'timestamp': get_timestamp(),
            'fingerprint': fingerprint
        }
        
        return jsonify({
            'encrypted': encrypted_payload,
            'message_id': message_id,
            'status': 'success',
            'details': f"Message encrypted using AES-256-CBC ({len(message)} chars → {len(encrypted_payload)} chars)"
        })
    
    except Exception as e:
        return jsonify({'error': f"Encryption failed: {str(e)}"}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted_payload_b64 = data.get('encrypted', '')
    
    if not encrypted_payload_b64:
        return jsonify({'error': 'Encrypted data is required'}), 400
    
    try:
        # Decode the payload
        payload_json = base64.b64decode(encrypted_payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Extract components
        message_id = payload.get('id', 'unknown')
        iv = base64.b64decode(payload['iv'])
        key = base64.b64decode(payload['key'])
        ciphertext = base64.b64decode(payload['ciphertext'])
        original_fingerprint = payload.get('fingerprint', '')
        timestamp = payload.get('timestamp', 'unknown')
        
        # Create and use cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = unpad_message(padded_plaintext)
        decrypted_message = plaintext.decode('utf-8')
        
        # Verify message integrity
        current_fingerprint = generate_fingerprint(decrypted_message)
        integrity_verified = current_fingerprint == original_fingerprint
        
        # Log decryption details
        app.decryption_log = getattr(app, 'decryption_log', {})
        app.decryption_log[message_id] = {
            'timestamp': get_timestamp(),
            'original_timestamp': timestamp,
            'integrity_verified': integrity_verified,
            'decrypted_length': len(decrypted_message)
        }
        
        result = {
            'decrypted': decrypted_message,
            'status': 'success',
            'details': "Message decrypted successfully"
        }
        
        if original_fingerprint:
            result['integrity_verified'] = integrity_verified
            if integrity_verified:
                result['details'] += " (integrity verified)"
            else:
                result['details'] += " (WARNING: message integrity check failed)"
        
        if timestamp != 'unknown':
            result['encrypted_at'] = timestamp
            
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f"Decryption failed: {str(e)}",
            'status': 'error',
            'details': "Unable to decrypt the message. The data may be corrupted or tampered with."
        }), 500

@app.route('/generate-client-key', methods=['GET'])
def generate_client_key():
    try:
        # In a real application, the client would generate their own key pair
        # For this demo, we're generating it server-side
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        client_public_key = client_private_key.public_key()
        
        # Serialize the client public key
        client_public_pem = client_public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Store the client keys (in a real app, the client would keep their private key)
        # For this demo, we're just returning the public key
        return jsonify({'client_public_key': client_public_pem})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/exchange-keys', methods=['POST'])
def exchange_keys():
    data = request.json
    client_public_key_pem = data.get('client_public_key', '')
    
    if not client_public_key_pem:
        return jsonify({'error': 'Client public key is required'}), 400
    
    try:
        # Generate a session key that would be used for symmetric encryption
        session_key = os.urandom(32)  # 256-bit key
        session_id = str(uuid4())
        
        # In a real application, we would encrypt the session key with the client's public key
        # and store relevant session information
        
        # Store the session information
        sessions[session_id] = {
            'client_public_key': client_public_key_pem,
            'session_key': base64.b64encode(session_key).decode('utf-8'),
            'created_at': get_timestamp(),
            'status': 'active'
        }
        
        # Return the server's public key
        return jsonify({
            'server_public_key': server_public_pem,
            'session_id': session_id,
            'status': 'success',
            'message': 'Key exchange successful! Secure channel established.',
            'details': f"Session established at {get_timestamp()} with 256-bit encryption"
        })
    
    except Exception as e:
        return jsonify({'error': f"Key exchange failed: {str(e)}"}), 500

@app.route('/terminate-session', methods=['POST'])
def terminate_session():
    # In a real app, you would get the session ID from a cookie
    # For this demo, we'll just acknowledge the request
    return jsonify({'message': 'Session terminated successfully'})

# Add these helper functions after the existing pad_message and unpad_message functions
def generate_fingerprint(message):
    """Generate a SHA-256 fingerprint of the message for integrity verification"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8') if isinstance(message, str) else message)
    return base64.b64encode(digest.finalize()).decode('utf-8')

def get_timestamp():
    """Generate a formatted timestamp string"""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)