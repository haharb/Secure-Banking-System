import maskpass
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto import encrypt_message, decrypt_message, sign_message, verify_signature

class ATM:
    def __init__(self, user_id, password, bank_public_key, atm_private_key):
        self.user_id = user_id
        self.password = password
        self.bank_public_key = bank_public_key
        self.atm_private_key = atm_private_key
    def getUserInfo():
        id = input("ID:")
        pwd = maskpass.askpass(prompt="Password:", mask="*")
        return (id, pwd)
    def selectAction():
        choice = input("1. Check balance \n2. Make deposit\n3. Withdrawl\n4. View Account Activities\n5. Quit")
        if choice == "1":
            return 'display_balance'
        elif choice == "2":
            return 'deposit'
        elif choice == "3":
            return 'withdrawl'
        elif choice == "4":
            return 'account_activities'
        elif choice == "5":
            return 'quit'
        else:
            return 'Invalid'

    def verify_credentials(self):
        # Encrypt user credentials with the bank's public key
        encrypted_credentials = encrypt_message(f"{self.user_id}:{self.password}", self.bank_public_key)

        # Sign the encrypted credentials with the ATM's private key
        signature = sign_message(encrypted_credentials, self.atm_private_key)

        # Send encrypted credentials and signature to the bank server for verification
        response = requests.post(
            'http://bank-server/verify_credentials',
            json={'user_id': self.user_id, 'credentials': encrypted_credentials, 'signature': signature}
        )

        # Check if the user is authenticated
        return response.json().get('authenticated', False)

    def perform_transaction(self, action, amount=None):
        # Sign the transaction details with the ATM's private key
        transaction_details = f"{self.user_id}:{action}:{amount}" if amount else f"{self.user_id}:{action}"
        signature = sign_message(transaction_details, self.atm_private_key)

        # Send transaction details and signature to the bank server for processing
        response = requests.post(
            'http://bank-server/perform_transaction',
            json={'user_id': self.user_id, 'action': action, 'amount': amount, 'signature': signature}
        )
        # Check the status of the transaction
        return response.json().get('status', 'error')

if __name__ == '__main__':
    # Example usage
    cred = ATM.getUserInfo()
    user_id = cred[0]
    password = cred[1]
    bank_public_key = open('../keys/bank_public_key.pem', 'rb').read()
    atm_private_key = open('../keys/atm_private_key.pem', 'rb').read()

    atm = ATM(user_id, password, bank_public_key, atm_private_key)

    if atm.verify_credentials():
        choice = ATM.selectAction()
        while choice == 'Invalid':
            choice = ATM.selectAction()
        # Perform transactions
        result = atm.perform_transaction(choice)
        print(f"Transaction Status: {result}")
    else:
        print("Authentication failed.")