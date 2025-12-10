import bcrypt
import hashlib

def hashing_sequence(password):    
    #hash the password without salt
    hashed1 = hashlib.md5(password.encode('utf-8')).hexdigest()
    print(f"MD5 Hash without salt: {hashed1}")
    hashed2 = hashlib.md5(password.encode('utf-8')).hexdigest()
    print(f"MD5 Hash without salt (2nd time): {hashed2}")
    # #hash the password with salt
    salt1 = bcrypt.gensalt()
    hashed3 = bcrypt.hashpw(password.encode('utf-8'), salt1)
    print(f"Hash 3 with salt: {hashed3.decode()}")

    salt2 = bcrypt.gensalt()
    hashed4 = bcrypt.hashpw(password.encode('utf-8'), salt2)
    print(f"Hash 4 with salt: {hashed4.decode()}")

    pepper1 = b'secret_pepper_value'
    #hash the password with salt and pepper
    hashed5 = bcrypt.hashpw(password.encode('utf-8') + pepper1, salt1)
    print(f"Hash 5 with salt and pepper: {hashed5.decode()}")

    pepper2 = b'another_secret_pepper'
    hashed6 = bcrypt.hashpw(password.encode('utf-8') + pepper2, salt1)
    print(f"Hash 6 with salt and pepper: {hashed6.decode()}")   

password = input("Enter a password to hash: ")
hashing_sequence(password)