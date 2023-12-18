# bank_server/db.py
from datetime import datetime
from pymongo import MongoClient

# Connect to the MongoDB server
client = MongoClient('mongodb://localhost:27017/')
db = client['bank_database']
def add_user_to_db(user_id, password, balance = 0):
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
    # Convert ObjectId to string
    transactions_list = [
        {**transaction, '_id': str(transaction['_id'])} 
        for transaction in transactions
    ]
    return transactions_list
def save_transaction(user_id, action, amount, balance):
    # Save the updated user document back to the database
    db.users.update_one({'user_id': user_id}, {'$set': {'balance': balance}})
    # Save the transaction in the database
    db.transactions.insert_one({
        'user_id': user_id,
        'action': action,
        'amount': amount,
        #Format date time as a string for a cleaner look
        'date_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })