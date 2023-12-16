# bank_server/server.py
from flask import Flask, request, jsonify
from db import create_user, get_user_by_id, save_transaction
from crypto import decrypt_message, loadKeyDSA, loadKeyRSA, verify_signatureDSA, verify_signatureRSA
key = b"Qp5LsKMC0Pdkh1TDdFUAwiGJjVZMU2yEYi3LKDGfT/8="
app = Flask(__name__)
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json
    user_id = data.get('user_id')
    encrypted_credentials = data.get('credentials')
    signature = data.get('signature')
    isRSA = data.get('isRSA')
    # Decrypt the user's credentials using the bank's private key
    decrypted_credentials = decrypt_message(encrypted_credentials, key)
    if isRSA:
        #Load the atm's public key
        atm_public_key = loadKeyRSA("atm_public")
        # Verify the signature using the atm's public key with RSA
        is_valid_signature = verify_signatureRSA(decrypted_credentials, signature, atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(decrypted_credentials, signature, atm_public_key)
    if is_valid_signature:
        # Check user credentials in the database
        user = get_user_by_id(user_id)
        if user:
            return jsonify({'created': False})
        else:
            create_user(user_id, decrypted_credentials['password'])
            print("User " + user_id)
            return jsonify({'created':True})
    return jsonify({'created': False,'isValidSignature': False})
@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    data = request.json
    user_id = data.get('user_id')
    encrypted_credentials = data.get('credentials')
    signature = data.get('signature')
    isRSA = data.get('isRSA')
    # Decrypt the user's credentials using the bank's private key
    decrypted_credentials = decrypt_message(encrypted_credentials, key)
    if isRSA:
        #Load the atm's public key
        atm_public_key = loadKeyRSA("atm_public")
        # Verify the signature using the atm's public key with RSA
        is_valid_signature = verify_signatureRSA(decrypted_credentials, signature, atm_public_key)
    else:
        #Load the atm's public key
        atm_public_key = loadKeyDSA("atm_public")
        # Verify the signature using the atm's public key with DSA
        is_valid_signature = verify_signatureDSA(decrypted_credentials, signature, atm_public_key)
    if is_valid_signature:
        # Check user credentials in the database
        user = get_user_by_id(user_id)
        if user and user['password'] == decrypted_credentials['password']:
            return jsonify({'authenticated': True})
    
    return jsonify({'authenticated': False})

@app.route('/perform_transaction', methods=['POST'])
def perform_transaction():
    data = request.json
    user_id = data.get('user_id')
    action = data.get('action')
    amount = data.get('amount')
    user = get_user_by_id(user_id)
    balance = user['balance']
    # Validate the user's identity and perform the transaction
    user = get_user_by_id(user_id)

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

    return jsonify({'status': 'error'})

if __name__ == '__main__':
    app.run(debug=True)