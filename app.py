from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import base64

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize the keys to PEM format
private_pem = private_key.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign_message():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Sign the message
    try:
        signature = private_key.sign(
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
        public_key.verify(
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

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)