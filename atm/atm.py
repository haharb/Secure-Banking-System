import base64
import json
import sys
import maskpass
import requests
from crypto import encrypt_message, loadKeyDSA, loadKeyRSA, sign_messageDSA, sign_messageRSA
key = b"12345678912345678912345678912345"

class ATM:
    signing_algorithm = 'DSA'
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password
    def getUserInfo(self):
        id = input("ID:")
        pwd = maskpass.askpass(prompt="Password:", mask="*")
        return (id, pwd)
    def greetingScreen(self):
        choice = input("ATM At the Moment\n\n\n\n1. Login \n2. Create User\n")
        if choice =="1":
            return True
        else:
            return False 
    def selectAction(self):
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
            self.signing_algorithm= 'RSA'
        elif choice == "2":
            self.signing_algorithm = 'DSA'
        else:
            print("Invalid choice, defaulting to DSA.\n")
            self.signing_algorithm = 'DSA'
    def process_credentials(self, isUser):
        #JSON dictionary with user data
        json_data={'user_id': self.user_id, 'password': self.password}
        self.checkSignatureType()
        # Serializing the dictionary into a JSON formatted string
        json_string =json.dumps(json_data)
        if self.signing_algorithm == 'RSA':
            # Sign the encrypted credentials with the ATM's private key using RSA
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json_string, 'utf-8'), atm_private_key)
        else:
            # Sign the encrypted credentials with the ATM's private key using DSA
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json_string, 'utf-8'), atm_private_key)
        # Base64 encode the signature
        encoded_signature = base64.b64encode(signature).decode('utf-8')

        #message = bytes(f"{self.user_id}:{self.password}", encoding = "utf-8")
        # Encode the JSON string into bytes
        message = json_string.encode('utf-8')
        # Encrypt message with symmetric key, and receive the triple that contains the nonce, ciphertext and tag
        triple = encrypt_message(message, key)
        #Retrieve the ciphertext
        encrypted_message = triple[1]
        #Retrieve the nonce
        nonce = base64.b64encode(triple[0]).decode('utf-8')
        #Retrieve the tag
        tag = base64.b64encode(triple[2]).decode('utf-8')
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')
        if isUser:
            # Send encrypted message and signature to the bank server for verification
            response = requests.post(
                'http://bank-server/verify_credentials',
                json = {'data':encoded_encrypted_message},
                headers={"Signature": encoded_signature, 'Signing_algorithm':self.signing_algorithm, 'Nonce':nonce, 'Tag': tag},
                verify= False#Only for non production
            )
            if response:
                # Check if the user is authenticated.
                return response.json().get('authenticated', False)
        else:
            response = requests.post(
                'http://bank-server/create_user',
                json = {'data':encoded_encrypted_message},
                headers={"Signature": encoded_signature, 'Signing_algorithm':self.signing_algorithm, 'Nonce':nonce, 'Tag': tag},
                verify= False#Only for non production
            )
        if response:
            # Check if the user was created successfully.
            return response.json().get('created', False)
        return response.json().get('created', True)
    def perform_transaction(self, action, amount=None):
        #JSON dictionary to be sent
        json_data={'user_id': self.user_id, 'action': action,'amount':amount}
        # Serializing the dictionary into a JSON formatted string
        json_string =json.dumps(json_data)
        # Sign the transaction details with the ATM's private key
        if self.signing_algorithm:
            # Sign the encrypted credentials with the ATM's private key
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json_string, 'utf-8'), atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json_string, 'utf-8'), atm_private_key)
        # Base64 encode the signature
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        # Encode the JSON string into bytes
        message = json_string.encode('utf-8')
        #transaction_details = encrypt_message(bytes(f"{self.user_id}:{action}:{amount}", encoding = "utf-8") if amount else bytes(f"{self.user_id}:{action}", encoding = "utf-8"), key)
        # Encrypt message with symmetric key, and receive the triple that contains the nonce, ciphertext and tag
        triple = encrypt_message(message, key)
        #Retrieve the ciphertext
        encrypted_message = triple[1]
        #Retrieve the nonce
        nonce = triple[0]
        #Retrieve the tag
        tag = triple[2]
        #Encode message to be able to sent
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')
        # Send transaction details and signature to the bank server for processing
        response = requests.post(
            'http://bank-server/perform_transaction',
            json = {'data':encoded_encrypted_message},
                headers={"Signature": encoded_signature, 'Signing_algorithm':self.signing_algorithm, 'Nonce':nonce, 'Tag': tag},
                verify= False#Only for non production
        )
        # Check the status of the transaction
        return response.json().get('status', 'error')

if __name__ == '__main__':
    # Create an instance of the ATM class with dummy values
    atm_instance = ATM("", "") 
    isUser = atm_instance.greetingScreen()
    cred = atm_instance.getUserInfo()
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