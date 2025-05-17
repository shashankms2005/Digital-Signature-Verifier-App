Digital Signature Verifier - Setup Instructions

Project Structure
digital_signature_verifier/
├── app.py                  # Flask backend application
├── templates/              # Frontend templates directory
│   └── index.html          # Main HTML/JS interface
└── requirements.txt        # Python dependencies

Installation Steps

1. Create a virtual environment (recommended):
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

2. Install the required packages:
   pip install -r requirements.txt

3. Run the application:
   python app.py

4. Open your browser and navigate to:
   http://localhost:5000

Dependencies
The application requires these Python packages:
- Flask
- cryptography

How to Use

1. Type a message in the text area
2. Click "Sign Message" to generate a digital signature
3. The signature will appear in the signature box
4. Click "Verify Signature" to check if the message is authentic
5. To test tampering detection, click "Tamper Message" then "Verify Signature"

How It Works

Backend
- Generates an RSA key pair (public and private keys)
- Uses the private key to sign messages
- Uses the public key to verify signatures

Frontend
- Sends message to backend for signing
- Displays the returned signature
- Allows verification of message integrity
- Features a "tamper" button to demonstrate signature validation

Security Notes
- In a production environment, keys should be securely stored and not generated on each app start
- The frontend should use HTTPS for secure communication with the backend
- This is a demonstration app and not meant for production use without further security enhancements