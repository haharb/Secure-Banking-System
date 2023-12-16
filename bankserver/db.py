# bank_server/db.py
from pymongo import MongoClient

# Connect to the MongoDB server
client = MongoClient('mongodb://localhost:27017/')
db = client['bank_database']
def create_user(user_id, password, balance = 0):
    # Create a new user document
    user = {
        'user_id': user_id,
        'password': password,
        'balance': balance
    }
    # Insert the user document into the users collection
    db.users.insert_one(user)
def get_user_by_id(user_id):
    # Retrieve user information from the database based on user_id
    user = db.users.find_one({'user_id': user_id})
    return user
def get_transactions_by_user(user_id):
    #Retrieve previous transactions by user id
    transactions = db.transactions.find({'user_id': user_id})
    return list(transactions)
def save_transaction(user_id, action, amount, isRSA):
    # Save the transaction in the database
    db.transactions.insert_one({
        'user_id': user_id,
        'action': action,
        'amount': amount,
        'isRSA': isRSA
    })