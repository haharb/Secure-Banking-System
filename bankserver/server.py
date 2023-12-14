# bank_server/server.py
from flask import Flask, request, jsonify
from db import get_user_by_id, save_transaction
from crypto import decrypt_message, sign_message, generate_key_pair, verify_signature

app = Flask(__name__)

# Bank's private and public keys
BANK_PRIVATE_KEY, BANK_PUBLIC_KEY = generate_key_pair()

@app.route('/verify_credentials', methods=['POST'])
def verify_credentials():
    data = request.json
    user_id = data.get('user_id')
    encrypted_credentials = data.get('credentials')
    signature = data.get('signature')

    # Decrypt the user's credentials using the bank's private key
    decrypted_credentials = decrypt_message(encrypted_credentials, BANK_PRIVATE_KEY)

    # Verify the signature using the user's public key
    is_valid_signature = verify_signature(decrypted_credentials, signature, user_id)

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

    # Validate the user's identity and perform the transaction
    user = get_user_by_id(user_id)

    if user:
        # Example: Perform transaction logic and save the transaction in the database
        save_transaction(user_id, action, amount)
        return jsonify({'status': 'success'})

    return jsonify({'status': 'error'})

if __name__ == '__main__':
    app.run(debug=True)