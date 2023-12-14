# constants.py

# Configuration settings
DATABASE_URL = "mongodb://localhost:27017/"
BANK_SERVER_URL = "http://bank-server/"

# Cryptographic keys and parameters
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 256

# User-related constants
MIN_PASSWORD_LENGTH = 8
MAX_USERNAME_LENGTH = 20

# Transaction types
DISPLAY_BALANCE = "display_balance"
DEPOSIT = "deposit"
WITHDRAWAL = "withdrawal"
ACCOUNT_ACTIVITIES = "account_activities"
QUIT = "quit"