import base64
import json
import sys
import maskpass
import requests
from crypto import encrypt_message, loadKeyDSA, loadKeyRSA, sign_messageDSA, sign_messageRSA
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
        id = input("ID:")
        pwd = maskpass.askpass(prompt="Password:", mask="*")
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
        #Printing for debugging purposeses ##REMOVE##
        print("Response Content:", response.text)
        #Make sure the response exists first
        if response.text:
            try:
                response_data = response.json()
            except json.decoder.JSONDecodeError:
                print("Invalid JSON in response.")
                return False

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
            elif action == 'deposit' or action == 'withdrawl':
                amount = input("Enter amount:")
                result = atm.perform_transaction(action, amount)
                print(f"Transaction Status: {result}")
            elif action == 'display_balance':
                result = atm.perform_transaction(action)
                print("Your balance is\n")
                print(result['balance'])
    else:
        print("Authentication failed.")