# crypto.py
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import sys
from pymongo import HASHED
# Loads key from pem file
def loadKey(fileName):
    return RSA.import_key(open(fileName).read())
# Encrypts bytes using a given key
def encrypt_message(message, key):
    cipher_rsa_encrypt = PKCS1_OAEP.new(key, hashAlgo=None, mgfunc=None, randfunc=None)
    cipherBytes = cipher_rsa_encrypt.encrypt(message)
    return cipherBytes
#Sign message with RSA
def sign_messageRSA(message, key):
    h = SHA256.new(message)
    return pss.net(key).sign(h)

# Decrypts a bytes message using a given key
def decrypt_message(cipherBytes, key):
    cipher_rsa_decrypt = PKCS1_OAEP.new(key, hashAlgo=None, mgfunc=None, randfunc=None)
    decryptedBytes = cipher_rsa_decrypt.decrypt(cipherBytes)
    return decryptedBytes

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