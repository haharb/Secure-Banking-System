import sys
import maskpass
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto import encrypt_message, loadKeyDSA, loadKeyRSA, sign_messageDSA, sign_messageRSA
key = b"12345678912345678912345678912345"

class ATM:
    isRSA = False
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
    def checkSignatureType(self):
        choice = input("Select an option for digital signature:\n1. RSA\n2. DSA\n")
        if choice == "1":
            self.isRSA= True
        elif choice == "2":
            self.isRSA = False
        else:
            print("Invalid choice, defaulting to DSA.\n")
            self.isRSA = False
    def process_credentials(self, isUser):
        #JSON dictionary with user data
        json={'user_id': self.user_id, 'password': self.password, 'isRSA':self.isRSA}
        self.checkSignatureType()
        if self.isRSA:
            # Sign the encrypted credentials with the ATM's private key using RSA
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json.dumps(json), 'utf-8'), atm_private_key)
        else:
            # Sign the encrypted credentials with the ATM's private key using DSA
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json.dumps(json), 'utf-8'), atm_private_key)
        #Includes data and its signature to be encrypted
        dataAndSig = (json,signature)
        # Serializing the tuple into a JSON formatted string
        json_string =json.dumps(dataAndSig)
        #message = bytes(f"{self.user_id}:{self.password}", encoding = "utf-8")
        # Encode the JSON string into bytes
        message = json_string.encode('utf-8')
        # Encrypt message with symmetric key
        encrypted_message = encrypt_message(message, key)
        if isUser:
            # Send encrypted message and signature to the bank server for verification
            response = requests.post(
                'http://bank-server/verify_credentials',
                encrypted_message
            )
            # Check if the user is authenticated.
            return response.json().get('authenticated', False)
        else:
            response = requests.post(
                'http://bank-server/create_user',
                encrypted_message            )
            # Check if the user was created successfully.
            return response.json().get('created', False)

    def perform_transaction(self, action, amount=None):
        #JSON dictionary to be sent
        json={'user_id': self.user_id, 'action': action,'amount':amount}
        # Sign the transaction details with the ATM's private key
        if self.isRSA:
            # Sign the encrypted credentials with the ATM's private key
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json.dumps(json), 'utf-8'), atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json.dumps(json), 'utf-8'), atm_private_key)
        #Includes the data to be sent and signature in a tuple
        dataAndSig = (json,signature)
        # Serializing the tuple into a JSON formatted string
        json_string =json.dumps(json)
        # Encode the JSON string into bytes
        message = json_string.encode('utf-8')
        #transaction_details = encrypt_message(bytes(f"{self.user_id}:{action}:{amount}", encoding = "utf-8") if amount else bytes(f"{self.user_id}:{action}", encoding = "utf-8"), key)
        # Encrypt message with symmetric key
        encrypted_message = encrypt_message(message, key)
        # Send transaction details and signature to the bank server for processing
        response = requests.post(
            'http://bank-server/perform_transaction',
            encrypted_message
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