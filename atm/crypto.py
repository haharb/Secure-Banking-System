# crypto.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from pymongo import HASHED

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_key_from_pem(pem_data, key_type):
    if key_type == 'private':
        return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    elif key_type == 'public':
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=utils.Algorithm.SHA256),
            algorithm=utils.Algorithm.SHA256,
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=utils.Algorithm.SHA256),
            algorithm=utils.Algorithm.SHA256,
            label=None
        )
    )
    return plaintext

def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(HASHED.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(utils.Algorithm.SHA256)
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(HASHED.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(utils.Algorithm.SHA256)
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False