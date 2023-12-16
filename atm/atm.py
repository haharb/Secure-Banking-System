import sys
import maskpass
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto import encrypt_message, loadKeyDSA, loadKeyRSA, sign_messageDSA, sign_messageRSA
key = b"Qp5LsKMC0Pdkh1TDdFUAwiGJjVZMU2yEYi3LKDGfT/8="
isRSA = False
class ATM:
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password
    def getUserInfo():
        id = input("ID:")
        pwd = maskpass.askpass(prompt="Password:", mask="*")
        return (id, pwd)
    def greetingScreen():
        choice = input("ATM At the Moment\n\n\n\n1. Login \n2. Create User\n")
        if choice =="1":
            return True
        else:
            return False 
    def selectAction():
        choice = input("1. Check balance \n2. Make deposit\n3. Withdrawl\n4. View Account Activities\n5. Quit\n")
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
    def isRSA():
        choice = input("Select an option for digital signature:\n1. RSA\n2. DSA\n")
        if choice == "1":
            isRSA= True
        elif choice == "2":
            isRSA = False
        else:
            print("Invalid choice, defaulting to DSA.\n")
            isRSA = False
    def process_credentials(self, isUser):
        message = bytes(f"{self.user_id}:{self.password}", encoding = "utf-8")
        # Encrypt user credentials with symmetric key
        encrypted_credentials = encrypt_message(message, key)
        self.isRSA()
        if isRSA:
            # Sign the encrypted credentials with the ATM's private key
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(encrypted_credentials, atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(encrypted_credentials, atm_private_key)
        if isUser:
            # Send encrypted credentials and signature to the bank server for verification
            response = requests.post(
                'http://bank-server/verify_credentials',
                json={'user_id': self.user_id, 'credentials': encrypted_credentials, 'signature': signature, 'isRSA':isRSA}
            )
            # Check if the user is authenticated.
            return response.json().get('authenticated', False)
        else:
            response = requests.post(
                'http://bank-server/create_user',
                json={'user_id': self.user_id, 'credentials': encrypted_credentials, 'signature': signature}
            )
            # Check if the user was created successfully.
            return response.json().get('created', False)

    def perform_transaction(self, action, amount=None):
        # Sign the transaction details with the ATM's private key
        transaction_details = encrypt_message(bytes(f"{self.user_id}:{action}:{amount}", encoding = "utf-8") if amount else bytes(f"{self.user_id}:{action}", encoding = "utf-8"), key)
        if isRSA:
            # Sign the encrypted credentials with the ATM's private key
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(transaction_details, atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(transaction_details, atm_private_key)

        # Send transaction details and signature to the bank server for processing
        response = requests.post(
            'http://bank-server/perform_transaction',
            json={'user_id': self.user_id, 'action': action, 'amount': amount, 'signature': signature}
        )
        # Check the status of the transaction
        return response.json().get('status', 'error')

if __name__ == '__main__':
    isUser = ATM.greetingScreen()
    cred = ATM.getUserInfo()
    user_id = cred[0]
    password = cred[1]
    atm = ATM(user_id, password)
    if atm.process_credentials(isUser):
        action = ATM.selectAction()
        while action == 'Invalid':
            action = ATM.selectAction()
        if action == 'quit':
            print("Exiting the program.")
            sys.exit()
        elif action == 'deposit' or action == 'withdrawl':
            amount = input("Enter amount:")
            result = atm.perform_transaction(user_id, action, amount)
            print(f"Transaction Status: {result}")
    else:
        print("Authentication failed.")