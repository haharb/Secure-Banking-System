# bank_server/server.py
import base64
import json
from flask import Flask, request, jsonify
from crypto import hashPassword, verifyHash
from db import add_user_to_db, get_user_by_id, save_transaction
from crypto import decrypt_message, loadKeyDSA, loadKeyRSA, verify_signatureDSA, verify_signatureRSA
key = b"12345678912345678912345678912345"
app = Flask(__name__)
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json['data']
    print("THE REQUEST HEADER ITEMS ARE AS FOLLOWS")
    print(request.headers)
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(data)
    #Get the nonce for comparison
    nonce = base64.b64decode(request.headers["NONCE"])
    #Get the tag for comparison
    tag = base64.b64decode(request.headers["TAG"])
    #Decrypt the data and compare the nonce and tag for authentication
    decrypted_data = decrypt_message(nonce, decoded_encrypted_data, tag, key)
    #Decode the encoded data to get string representation
    decoded_data = decrypted_data.decode('utf-8')
    #Data is still in JSON string format at this point, return to dictionary
    dataJSON = json.loads(decoded_data)
    #Get signature from the header
    signature = base64.b64decode(request.headers["SIGNATURE"])
    signing_algorithm = request.headers["SIGNINGALGORITHM"]
    if signing_algorithm == 'RSA':
        #Load the atm's public key
        atm_public_key = loadKeyRSA("atm_public")
        # Verify the signature using the atm's public key with RSA
        is_valid_signature = verify_signatureRSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    if not is_valid_signature:
        print("Signature does not match")
        return jsonify({'created': False,'isValidSignature': False})
    #Get user_id
    user_id = dataJSON['user_id']
    #Get password as bytes to hash
    password = bytes(dataJSON['password'], 'utf-8')
    # Check user id from the database
    user = get_user_by_id(user_id)
    if user:
        print("User already exists.")
        return jsonify({'created': False})
    else:
        add_user_to_db(user_id, hashPassword(password))
        print("User " + user_id)
        return jsonify({'created':True})
@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    data = request.json['data']
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(data)
    #Get the nonce for comparison
    nonce = base64.b64decode(request.headers["NONCE"])
    #Get the tag for comparison
    tag = base64.b64decode(request.headers["TAG"])
    #Decrypt the data and compare the nonce and tag for authentication
    decrypted_data = decrypt_message(nonce, decoded_encrypted_data, tag, key)
    #Decode the encoded data to get string representation
    decoded_data = decrypted_data.decode('utf-8')
    #Data is still in JSON string format at this point, return to dictionary
    dataJSON = json.loads(decoded_data)
    #Get user_id
    user_id = dataJSON['user_id']
    #Get signature from the header
    signature = base64.b64decode(request.headers["SIGNATURE"])
    signing_algorithm = request.headers["SIGNINGALGORITHM"]
    if signing_algorithm == 'RSA':
        #Load the atm's public key
        atm_public_key = loadKeyRSA("atm_public")
        # Verify the signature using the atm's public key with RSA
        is_valid_signature = verify_signatureRSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    if is_valid_signature:
        # Check user credentials in the database
        user = get_user_by_id(user_id)
        if user:
            #Get password as bytes to hash
            password = bytes(dataJSON['password'], 'utf-8')
            if verifyHash(password, user['password']):
                return jsonify({'authenticated': True})
    return jsonify({'authenticated': False})

@app.route('/perform_transaction', methods=['POST'])
def perform_transaction():
    data = request.json['data']
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(data)
    #Get the nonce for comparison
    nonce = base64.b64decode(request.headers["NONCE"])
    #Get the tag for comparison
    tag = base64.b64decode(request.headers["TAG"])
    #Decrypt the data and compare the nonce and tag for authentication
    decrypted_data = decrypt_message(nonce, decoded_encrypted_data, tag, key)
    #Data is still in JSON string format at this point, return to tuple format
    dataJSON = json.loads(decrypted_data)
    #Get signature from the header
    signature = base64.b64decode(request.headers["SIGNATURE"])
    signing_algorithm = request.headers["SIGNINGALGORITHM"]
    user_id = dataJSON.get('user_id')
    action = dataJSON.get('action')
    amount = dataJSON.get('amount')
    user = get_user_by_id(user_id)
    balance = user['balance']
    # Validate the user's identity and perform the transaction
    user = get_user_by_id(user_id)
    if signing_algorithm == 'RSA':
            #Load the atm's public key
            atm_public_key = loadKeyRSA("atm_public")
            # Verify the signature using the atm's public key with RSA
            is_valid_signature = verify_signatureRSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(bytes(json.dumps(dataJSON), 'utf-8'), signature, atm_public_key)
    if is_valid_signature:
        if user:
            if action == 'deposit':
                balance += amount
            elif action == 'withdrawl':
                if balance >= amount:
                    balance =- amount
                else:
                    return jsonify({'status':'insufficient balance'})
            # Example: Perform transaction logic and save the transaction in the database
            save_transaction(user_id, action, amount,signing_algorithm )
            return jsonify({'status': 'success', 'balance':balance})
    else:
        return jsonify({'authenticated': False, 'status' : 'error'})

if __name__ == '__main__':
    app.run(debug=True)