# bank_server/server.py
import base64
import json
from flask import Flask, request, jsonify
from crypto import hashPassword, verifyHash
from db import create_user, get_user_by_id, save_transaction
from crypto import decrypt_message, loadKeyDSA, loadKeyRSA, verify_signatureDSA, verify_signatureRSA
key = b"12345678912345678912345678912345"
app = Flask(__name__)
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json['data']
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(data).decode('utf-8')
    #Get the nonce for comparison
    nonce = request.headers['Nonce']
    #Get the tag for comparison
    tag = request.headers['Tag']
    #Decrypt the data and compare the nonce and tag for authentication
    decrypted_data = decrypt_message(nonce, decoded_encrypted_data, tag, key)
    #Decode the encoded data to get string representation
    decoded_data = decrypted_data.decode('utf-8')
    #Data is still in JSON string format at this point, return to dictionary
    dataJSON = json.loads(decoded_data)
    
    #Get userinfo from dataJSON
    userInfo = dataJSON['user_id']
    #Get signature from the header
    signature = base64.b64decode(request.headers['Signature']).decode('utf-8')
    signing_algorithm = request.headers['Signing_algorithm']
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
    user_id = userInfo.get('user_id')
    
    # Check user id from the database
    user = get_user_by_id(user_id)
    if user:
        return jsonify({'created': False})
    else:
        create_user(user_id, hashPassword(userInfo['password']))
        print("User " + user_id)
        return jsonify({'created':True})
@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    data = request.json['data']
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(data).decode('utf-8')
    #Get the nonce for comparison
    nonce = base64.b64decode(request.headers['Nonce']).decode('utf-8')
    #Get the tag for comparison
    tag = base64.b64decode(request.headers['Tag']).decode('utf-8')
    #Decrypt the data and compare the nonce and tag for authentication
    decrypted_data = decrypt_message(nonce, decoded_encrypted_data, tag, key)
    #Data is still in JSON string format at this point, return to tuple format
    dataJSON = json.loads(decrypted_data)
    #Get userinfo from dataJSON
    userInfo = dataJSON['user_id']
    #Get signature from the header
    signature = base64.b64decode(request.headers['Signature']).decode('utf-8')
    signing_algorithm = request.headers['Signing_algorithm']
    if signing_algorithm == 'RSA':
        #Load the atm's public key
        atm_public_key = loadKeyRSA("atm_public")
        # Verify the signature using the atm's public key with RSA
        is_valid_signature = verify_signatureRSA(bytes(json.dumps(dataJSON), 'utf-8'), base64.b64decode(signature), atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(bytes(json.dumps(dataJSON), 'utf-8'), base64.b64decode(signature), atm_public_key)
    if is_valid_signature:
        # Check user credentials in the database
        user = get_user_by_id(userInfo)
        if user:
            if verifyHash(userInfo, user['password']):
                return jsonify({'authenticated': True})
    return jsonify({'authenticated': False})

@app.route('/perform_transaction', methods=['POST'])
def perform_transaction():
    data = request.json
    #Decode data before decryption
    decoded_encrypted_data = base64.b64decode(decoded_encrypted_data).decode('utf-8')
    #Decrypt the encrypted data with the symmetric key
    decrypted_data = decrypt_message(data, key)
    #Decode the encoded data to get string representation
    decoded_data = decrypted_data.decode('utf-8')
    #Data is still in JSON string format at this point, return to dictionary format
    dataJSON = json.loads(decoded_data)
    #Get signature from the header
    signature = base64.b64decode(request.headers['Signature']).decode('utf-8')
    signing_algorithm = request.headers['Signing_algorithm']
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
            is_valid_signature = verify_signatureRSA(bytes(json.dumps(dataJSON), 'utf-8'), base64.b64decode(signature), atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(bytes(json.dumps(dataJSON), 'utf-8'), base64.b64decode(signature), atm_public_key)
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
            save_transaction(user_id, action, amount)
            return jsonify({'status': 'success'})
    else:
        return jsonify({'authenticated': False, 'status' : 'error'})

if __name__ == '__main__':
    app.run(debug=True)