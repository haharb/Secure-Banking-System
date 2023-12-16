# crypto.py
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.PublicKey import DSA
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
import sys
#Create DSA key
# def createDSAkeypair(owner):
#     key = DSA.generate(2048)
#     f = open("public_key.pem", "w")
#     f.write(key.publickey().export_key())
#     f.close()

# Loads key for RSA from pem file, prefix denotes whose key it is, and if it private or public
def loadKeyRSA(fileNamePrefix):
    return RSA.import_key(open("%s_keyRSA.pem"%(fileNamePrefix)).read())
# Loads key for DSA from pem file, prefix denotes whose key it is, and if it private or public
def loadKeyDSA(fileNamePrefix):
    return DSA.import_key(open("%s_keyDSA.pem"%(fileNamePrefix)).read())
# Encrypts bytes using a given key (symmetric), returns the ciphertext as well as the nonce and tag for added authentication and integrity
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext,tag
# Decrypts a bytes ciphertext using a given key, tag, nonce (symmetric)
def decrypt_message(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message
#Sign message with RSA, key is a imported from a file, message is bytes representation of a string
def sign_messageRSA(message, key):
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)
#Sign message with DSA, key is a imported from a file, message is bytes representation of a string
def sign_messageDSA(message, key):
    h = SHA256.new(message)
    signer = DSS.new(key, 'fips-186-3')
    return signer.sign(h)
# Verifies RSA signature, message is bytes, returns bool
def verify_signatureRSA(message, signature, key):
    try: 
        h = SHA256.new(message)
        pkcs1_15.new(key).verify(h, signature)
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False
# Verifies RSA signature, message is bytes, returns bool
def verify_signatureDSA(message, signature, key):
    try: 
        h = SHA256.new(message)
        verifier = DSS.new(key, 'fips-186-3')
        verifier.verify(h, signature)
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False