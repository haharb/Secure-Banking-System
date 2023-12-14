# bank_server/db.py
from pymongo import MongoClient

# Connect to the MongoDB server
client = MongoClient('mongodb://localhost:27017/')
db = client['bank_database']
def create_user(user_id, password):
    # Create a new user document
    user = {
        'user_id': user_id,
        'password': password,
        # Add other user details as needed
    }

    # Insert the user document into the users collection
    db.users.insert_one(user)
def get_user_by_id(user_id):
    # Retrieve user information from the database based on user_id
    user = db.users.find_one({'user_id': user_id})
    return user

def save_transaction(user_id, action, amount):
    # Save the transaction in the database
    db.transactions.insert_one({
        'user_id': user_id,
        'action': action,
        'amount': amount
    })