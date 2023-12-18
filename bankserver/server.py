# bank_server/server.py
import base64
import json
from flask import Flask, request, jsonify
from crypto import encrypt_message, hashPassword, sign_messageDSA, sign_messageRSA, verifyHash
from db import add_user_to_db, get_transactions_by_user, get_user_by_id, save_transaction
from crypto import decrypt_message, loadKeyDSA, loadKeyRSA, verify_signatureDSA, verify_signatureRSA
key = b"12345678912345678912345678912345"
app = Flask(__name__)
@app.route('/create_user', methods=['POST'])
def create_user():
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
        return jsonify({'status': 'False','created': False,'isValidSignature': False})
    #Get user_id
    user_id = dataJSON['user_id']
    #Get password to hash
    password =dataJSON['password']
    # Check user id from the database
    user = get_user_by_id(user_id)
    if user:
        print("User already exists.")
        return jsonify({'status': 'duplicate','created': False,'authenticated' : False})
    else:
        add_user_to_db(user_id, hashPassword(password))
        print("User " + user_id)
        return jsonify({'status':'new' ,'created':True, 'authenticated' : True})
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
            #Get password to hash
            password = dataJSON['password']
            if verifyHash(password, user['password']):
                return jsonify({'status':'complete','authenticated': True})
    return jsonify({'status':'completed','authenticated': False})

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
    #Cast to integer to be able to do arithmetic operations
    amount = dataJSON.get('amount')
    if amount:
        intamount = int(amount)
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
                balance += intamount
            elif action == 'withdrawal':
                if balance >= intamount:
                    balance -= intamount
                else:
                    return jsonify({'status':'insufficient balance'})
            # Example: Perform transaction logic and save the transaction in the database
            save_transaction(user_id, action, amount, balance )
            return jsonify({'status': 'success', 'balance':balance})
        elif action == 'account_activities':
            return       
    else:
        return jsonify({'authenticated': False, 'status' : 'error'})
@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    user_id = request.args.get('user_id')
    signing_algorithm = request.args.get('signature_algorithm')
    if user_id:
        #Encode to bytes the json string form of the message
        transactions = bytes(json.dumps(get_transactions_by_user(user_id)), 'utf-8')
        #Encrypt the message using symmetric key encryption, the result is a triple of nonce ciphertext and tag
        triple = encrypt_message(transactions, key)
        #Get the ciphertext from the triple
        encrypted_transactions = triple[1]
        #Get the nonce from the triple
        nonce = triple[0]
        #Get the tag from the triple
        tag = triple[2]
        #Encode to be able to send across the net
        encoded_encrypted_transactions = base64.b64encode(encrypted_transactions).decode('utf-8')
        encoded_nonce = base64.b64encode(nonce).decode('utf-8')
        encoded_tag = base64.b64encode(tag).decode('utf-8')
        if signing_algorithm == 'RSA':
            bank_private_key = loadKeyRSA("bank_private")
            signature = sign_messageRSA(transactions, bank_private_key)
        else:
            bank_private_key = loadKeyDSA("bank_private")
            signature = sign_messageDSA(transactions, bank_private_key)
        signature = base64.b64encode(signature).decode('utf-8')
        return {'data':encoded_encrypted_transactions, 'nonce': encoded_nonce, 'tag' : encoded_tag, 'signature' : signature}
    else:
        return jsonify({'error': 'User ID is missing'}), 400  # Return a 400 Bad Request status if user_id is missing
if __name__ == '__main__':
    app.run(debug=True)