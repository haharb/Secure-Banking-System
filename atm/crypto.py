# crypto.py
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
import sys
from pymongo import HASHED
#Create DSA key
# def createDSAkeypair(owner):
#     key = DSA.generate(2048)
#     f = open("public_key.pem", "w")
#     f.write(key.publickey().export_key())
#     f.close()

# Loads key for RSA from pem file, prefix denotes whose key it is, and if it private or public
def loadKeyRSA(fileNamePrefix):
    return RSA.import_key(open("%s_key_RSA.pem"%(fileNamePrefix)).read())
# Loads key for DSA from pem file, prefix denotes whose key it is, and if it private or public
def loadKeyDSA(fileNamePrefix):
    return ECC.import_key(open("%s_key_DSA.pem"%(fileNamePrefix)).read())
# Encrypts bytes using a given key
def encrypt_message(message, key):
    cipher_rsa_encrypt = PKCS1_OAEP.new(key, hashAlgo=None, mgfunc=None, randfunc=None)
    cipherBytes = cipher_rsa_encrypt.encrypt(message)
    return cipherBytes
#Sign message with RSA, key is a imported from a file, message is bytes representation of a string
def sign_messageRSA(message, key):
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)
#Sign message with DSA, key is a imported from a file, message is bytes representation of a string
def sign_messageDSA(message, key):
    h = SHA256.new(message)
    return pss.net(key).sign(h)
# Decrypts a bytes message using a given key
def decrypt_message(cipherBytes, key):
    cipher_rsa_decrypt = PKCS1_OAEP.new(key, hashAlgo=None, mgfunc=None, randfunc=None)
    decryptedBytes = cipher_rsa_decrypt.decrypt(cipherBytes)
    return decryptedBytes

def verify_signatureDSA(message, signature, public_key):
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