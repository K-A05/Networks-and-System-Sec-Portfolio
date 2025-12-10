import bcrypt
import re
import math
import os
import hashlib
import pyotp
import qrcode

string = input("Enter a password to analyze: ")

def password_meter(password, file):
    score  = 0
    pool_size = 0
    password = password.strip()

    with open(file, 'r') as f:
        common_passwords = f.read().splitlines()
        if password in common_passwords:
                print("Password is too common.")
                exit()

    length = len(password) 
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
            score += 0

    if re.search(r'[a-z]', password): # lowercase
            score += 1
            pool_size += 26
    if re.search(r'[A-Z]', password): #Uppercase
        score += 1
        pool_size += 26
    if re.search(r'[0-9]', password): # Numbers
        score += 1
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): # Special characters
            score += 1
            pool_size += 32

    entropy = length * math.log2(pool_size)
    if entropy < 28:
        score += 0
        print("Very Weak password")
    elif entropy < 36:
        score += 1  
        print("Weak password")
    elif entropy < 60:
        score += 2  
        print("Reasonable password")
    elif entropy < 128:
        score += 3  
        print("Strong password")

    return score, entropy
    
file_path = os.path.join(os.path.dirname(__file__), "passwds.txt")
result = password_meter(string, file_path)
print(f"Password Score: {result[0]}, Entropy: {result[1]:.2f} bits")


def hash_password(password):
    bytes = password.encode('utf-8')
    md5_hash = hashlib.md5(bytes).hexdigest()
    sha256_hash = hashlib.sha256(bytes).hexdigest()
    print(f"MD5: {md5_hash}")
    print(f"SHA-256: {sha256_hash}")

    salt = bcrypt.gensalt()
    bcrypt_hash = bcrypt.hashpw(bytes, salt)
    print(f"bcrypt: {bcrypt_hash.decode()}")

hash_password(string)

def generate_totp():
    secret = pyotp.random_base32() # generate a random base32 secret
    otp = pyotp.TOTP(secret)


    uri = otp.provisioning_uri(
        name="user@example.com", 
        issuer_name="password-meter"
    )

    qr_img = qrcode.make(uri)
    qr_img.save("totp_qr.png")

    print("\n===== MFA INIT ======")
    print("Scan the QR code saved with google authenticator / Authy")
    print(f"Secret Key (store this safely!): {secret}")

    current  = otp.now()
    print(f"Current OTP: {current}")

    is_valid = otp.verify(current)
    print(f"Is the OTP valid? {is_valid}")

