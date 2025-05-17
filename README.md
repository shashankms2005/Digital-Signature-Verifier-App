# Secure Communication Portal

A Flask-based web application demonstrating cryptographic principles including digital signatures, encryption/decryption, and key exchange. This application provides an interactive interface for understanding how these security mechanisms work in practice.

## Features

- **Digital Signatures**: Sign messages using RSA-PSS signatures and verify their authenticity.
- **Encryption/Decryption**: Encrypt messages using AES-256-CBC and decrypt them securely.
- **Key Exchange**: Simulate secure key exchange between client and server using RSA encryption.
- **Interactive UI**: User-friendly interface with visual feedback and activity logging.
- **Educational Diagrams**: Explanations of cryptographic processes for learning purposes.

## Technical Details

### Backend (Flask)

The application utilizes Python's Flask framework with the following cryptographic implementations:

- **RSA**: For asymmetric encryption and digital signatures.
- **AES-256-CBC**: For symmetric encryption with proper padding.
- **PBKDF2**: For secure key derivation.
- **SHA-256**: For message fingerprinting and integrity verification.

### Frontend

- Pure HTML/CSS/JavaScript implementation.
- Responsive design with a tabbed interface.
- Real-time activity logging.
- Educational diagrams explaining cryptographic concepts.

## Installation and Setup

### Prerequisites

- Python 3.7+
- Flask
- `cryptography` package

### Step 1: Clone the Repository

```bash
git clone https://github.com/shashankms2005/Digital-Signature-Verifier-App
cd Digital-Signature-Verifier-App
```
### Step 2: Create and Activate Virtual Environment (Recommended)

```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install flask cryptography
```

### Step 4: Run the Application

```bash
python app.py
```

The application will be available at http://127.0.0.1:5000/

## How to Use

### Digital Signatures

- Navigate to the "Digital Signatures" tab.
- Enter a message in the text area.
- Click "Sign Message" to create a digital signature.
- Click "Verify Signature" to validate the signature against the message.
- Try modifying the message to see how verification fails when content changes.

### Encryption/Decryption

- Navigate to the "Encryption/Decryption" tab.
- Enter a message in the text area.
- Click "Encrypt Message" to encrypt the content.
- The encrypted data will appear in the designated area.
- Click "Decrypt Message" to recover the original message.

### Key Exchange

- Navigate to the "Key Exchange" tab.
- Click "Generate Client Key" to create a client key pair.
- Click "Exchange with Server" to perform a key exchange operation.
- The server's public key will be displayed upon successful exchange.

## Security Considerations

This application is designed for educational purposes and demonstrates cryptographic principles in a simplified manner. For production applications, consider the following security enhancements:

- Implement proper session management.
- Use secure cookies with HTTPS.
- Add protection against CSRF attacks.
- Implement rate limiting to prevent brute force attacks.
- Use proper key management solutions.
- Consider adding perfect forward secrecy.

## Code Structure

- `app.py`: Main Flask application with cryptographic implementations.
- `templates/index.html`: Frontend interface with interactive components.
- `static/`: Contains CSS and client-side JavaScript (if separated from HTML).