from Crypto.PublicKey import ECC

# Generate an ECC key pair
key = ECC.generate(curve='P-256')

# Save the private key
with open('atm_private_keyDSA.pem', 'wb') as f:
    f.write(bytes(key.export_key(format='PEM', use_pkcs8=True), encoding = "utf-8")))

# Save the public key
with open('atm_public_keyDSA.pem', 'wb') as f:
    f.write(bytes(key.public_key().export_key(format='PEM'), encoding = "utf-8"))
    # Save the private key
with open('bank_private_keyDSA.pem', 'wb') as f:
    f.write(bytes(key.export_key(format='PEM', use_pkcs8=True), encoding = "utf-8"))

# Save the public key
with open('bank_public_keyDSA.pem', 'wb') as f:
    f.write(bytes(key.public_key().export_key(format='PEM'), encoding = "utf-8"))