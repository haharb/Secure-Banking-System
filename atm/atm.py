import base64
import json
import sys
import maskpass
import requests
from flask import jsonify
from crypto import decrypt_message, encrypt_message, loadKeyDSA, loadKeyRSA, sign_messageDSA, sign_messageRSA, verify_signatureDSA, verify_signatureRSA
#TEMP KEY ##REMOVE## or change
key = b"12345678912345678912345678912345"

class ATM:
    #Default Signing algorithm
    signing_algorithm = 'DSA'

    def __init__(self, user_id, password, isUser):
        self.user_id = user_id
        self.password = password
        self.isUser = isUser

    def getUserInfo(self):
        while True:
            #Remove leading/trailing whitespaces
            id = input("ID: ").strip()  
            if not id:
                print("ID cannot be empty. Please try again.")
                continue

            pwd = maskpass.askpass(prompt="Password: ", mask="*")
            if not pwd:
                print("Password cannot be empty. Please try again.")
                continue

            # If both ID and password are non-empty, return the values
            return (id, pwd)
        
    #Has the bank name and prompts user to login if returning user, or create an account otherwise.
    def greetingScreen(self):
        print("\n\n\n\n\n At the Moment\n\n\n      ATM")
        while True:
            choice = input("\n\n\n\n1. Login \n2. Create User\n")
            if choice == "1":
                return True
            elif choice == "2":
                return False
            else:
                print("Invalid choice. Please enter 1 or 2.")

    #Prompts user to select an action to perform, choices are view balance, make a deposit, withrdrawl money, and check account activites.
    def selectAction(self):
        while True:
            choice = input("1. Check balance \n2. Make deposit\n3. Withdrawal\n4. View Account Activities\n5. Quit\n")
            if choice == "1":
                return 'display_balance'
            elif choice == "2":
                return 'deposit'
            elif choice == "3":
                return 'withdrawal'
            elif choice == "4":
                return 'account_activities'
            elif choice == "5":
                return 'quit'
            else:
                print("Invalid choice. Please enter a number between 1 and 5.")
    #Prompts user to choose a digital signature algorithm, the choices are RSA and DSA
    def checkSignatureType(self):
        choice = input("Select an option for digital signature:\n1. RSA\n2. DSA\n")
        if choice == "1":
            self.signing_algorithm = 'RSA'
        elif choice == "2":
            self.signing_algorithm = 'DSA'
        else:
            print("Invalid choice, defaulting to DSA.\n")
            self.signing_algorithm = 'DSA'

    def process_credentials(self):
        #Data to be encrypted and sent
        json_data = {'user_id': self.user_id, 'password': self.password}
        #Serializing the dictionary into a JSON string before sending
        json_string = json.dumps(json_data)
        # Signing algorithm check for RSA
        self.checkSignatureType()
        if self.signing_algorithm == 'RSA':
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json_string, 'utf-8'), atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json_string, 'utf-8'), atm_private_key)
        #Encode with base64 to be able to send bytes objects over network
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        message = json_string.encode('utf-8')
        #Encrypt the encoded message to receive the tuple including nonce, ciphertext, and tag
        triple = encrypt_message(message, key)
        #Retrieve the ciphertext from the tuple
        encrypted_message = triple[1]
        #Encode with base64 to be able to send bytes objects over network
        nonce = base64.b64encode(triple[0]).decode('utf-8')
        tag = base64.b64encode(triple[2]).decode('utf-8')
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')
        #Check if creating a new user or logging in to post to the respective route
        if self.isUser:
            #The data in the JSON file is the encoded and encrypted message
            #The headers include the encoded signature, the user's signing algorithm choice (RSA or DSA), the nonce and tag for decryption 
            #Verify is set to false since this is a non-production environmnet, we can create a self signed certificate and have it set here, we might revisit and fix.
            response = requests.post(
                'http://localhost:5000/verify_credentials',
                json={'data': encoded_encrypted_message},
                headers={"SIGNATURE": encoded_signature, "SIGNINGALGORITHM": self.signing_algorithm, "NONCE": nonce, "TAG": tag},
                verify=False  # Only for non-production
            )
        else:
            response = requests.post(
                'http://localhost:5000/create_user',
                json={'data': encoded_encrypted_message},
                headers={"SIGNATURE": encoded_signature, "SIGNINGALGORITHM": self.signing_algorithm, "NONCE": nonce, "TAG": tag},
                verify=False  # Only for non-production
            )
            if response.json()['status'] == 'duplicate':
                print("User already exists!")
                print("\nExiting.")
                sys.exit()
        #Make sure the response exists first
        if response.text:

            try:
                response_data = response.json()
            except json.decoder.JSONDecodeError:
                print("Invalid JSON in response.")
                return False
            if response_data['authenticated']:
                print("Welcome!")
            if 'authenticated' in response_data:
                return response_data['authenticated']
            elif 'created' in response_data:
                return response_data['created']
            else:
                print("Unexpected response format.")
                return False
        else:
            print("Empty response received.")
            return False
    #Performs the requested transaction or action, from the list within the selectAction function
    def perform_transaction(self, action, amount=None):
        json_data = {'user_id': self.user_id, 'action': action, 'amount': amount}
        json_string = json.dumps(json_data)
        #The chosen digital signature algorithm
        if self.signing_algorithm == 'RSA':
            atm_private_key = loadKeyRSA("atm_private")
            signature = sign_messageRSA(bytes(json_string, 'utf-8'), atm_private_key)
        else:
            atm_private_key = loadKeyDSA("atm_private")
            signature = sign_messageDSA(bytes(json_string, 'utf-8'), atm_private_key)

        encoded_signature = base64.b64encode(signature).decode('utf-8')
        message = json_string.encode('utf-8')
        triple = encrypt_message(message, key)
        encrypted_message = triple[1]
        nonce = base64.b64encode(triple[0]).decode('utf-8')
        tag = base64.b64encode(triple[2]).decode('utf-8')
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')

        response = requests.post(
            'http://localhost:5000/perform_transaction',
            json={'data': encoded_encrypted_message},
            headers={"SIGNATURE": encoded_signature, "SIGNINGALGORITHM": self.signing_algorithm, "NONCE": nonce, "TAG": tag},
            verify=False  # Only for non-production
        )
        print("Response Content:", response.text)
        if response.text:
            try:
                response_data = response.json()
            except json.decoder.JSONDecodeError:
                print("Invalid JSON in response.")
                return "error"
            return response_data
        else:
            print("Empty response received.")
            return "error"
    #Get list of transactions to be shown 
    def get_transactions(self):
        response = requests.get(
            'http://localhost:5000/get_transactions',
            params={'user_id': self.user_id, 'signature_algorithm': self.signing_algorithm},
            verify=False  # Only for non-production
        )
        # Retrieve the data only if the GET request was succesful
        if response.ok:
                try:
                    response_data = response.json()
                    # Decode the encoded encrypted transactions
                    encoded_encrypted_transactions = response_data['data']
                    # Decode the nonce and tag
                    nonce = base64.b64decode(response_data['nonce'])
                    tag = base64.b64decode(response_data['tag'])
                    signature = base64.b64decode(response_data['signature'])
                    # Decrypt the transactions, and check the nonce and tags to protect against replays and assure authenticity
                    transactions = json.loads(decrypt_message(nonce, base64.b64decode(encoded_encrypted_transactions), tag, key).decode('utf-8'))
                    if self.signing_algorithm == 'RSA':
                        #Load the atm's public key
                        atm_public_key = loadKeyRSA("bank_public")
                        # Verify the signature using the atm's public key with RSA
                        is_valid_signature = verify_signatureRSA(bytes(json.dumps(transactions), 'utf-8'), signature, atm_public_key)
                    else:
                        #Load the atm's public key
                        atm_public_key = loadKeyDSA("bank_public")
                        # Verify the signature using the atm's public key with DSA
                        is_valid_signature = verify_signatureDSA(bytes(json.dumps(transactions), 'utf-8'), signature, atm_public_key)
                    if not is_valid_signature:
                        print("Authentication failed. Signature did not match.")
                    else:
                        print("Your account activities:")
                        if len(transactions) == 0:
                            print("You have made no transactions yet.")
                        else:
                            # Some transactions didn't have a specific amount
                            for transaction in transactions:
                                if transaction['amount'] is not None:
                                    print(f"Action: {transaction['action']}, Amount: {transaction['amount']} on {transaction['date_time']}")
                                else:
                                    print(f"Action: {transaction['action']} on {transaction['date_time']}")
                except json.decoder.JSONDecodeError:
                    print("Invalid JSON in response.")
        else:
            print("Error in the request. HTTP Status Code:", response.status_code)   

if __name__ == '__main__':
    atm_instance = ATM("", "", False)
    isUser = atm_instance.greetingScreen()
    cred = atm_instance.getUserInfo()
    user_id = cred[0]
    password = cred[1]
    atm = ATM(user_id, password, isUser)
    if atm.process_credentials():
        while True:
            action = atm.selectAction()
            if action == 'quit':
                print("Exiting the program.")
                sys.exit()
            elif action == 'deposit' or action == 'withdrawal':
                amount = input("Enter amount:")
                result = atm.perform_transaction(action, amount)
                print(f"Transaction Status: {result}")
            elif action == 'display_balance':
                result = atm.perform_transaction(action)
                print("Your balance is\n\n")
                print(str(result['balance'])+ "\n\n")
            elif action == 'account_activities':
                transactions = atm.get_transactions()

                
    else:
        print("Authentication failed.\nBye bye!")