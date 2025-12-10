import hashlib
import time

#===== Output from running salt and pepper.py =====
# Enter a password to hash: 1q2w3e4r (from brute_dict.txt)
# MD5 Hash without salt: 5416d7cd6ef195a0f7622a9c56b55e84 (Value being used for simulation)
# MD5 Hash without salt (2nd time): 5416d7cd6ef195a0f7622a9c56b55e84
# Hash 3 with salt: $2b$12$VzVbL1JYXjSPxBOqY9IsveqY3yWrgOGl0tCCM5vqybAggDO9VWhN2
# Hash 4 with salt: $2b$12$DRfn2nwMXMduV2iBpZgxN.2KVJSvRrmBJjy7kKYpnYPdIS.COt/v2
# Hash 5 with salt and pepper: $2b$12$VzVbL1JYXjSPxBOqY9IsveJBQEtYklLAodl8/94YO1g9V5.EQTmVm
# Hash 6 with salt and pepper: $2b$12$VzVbL1JYXjSPxBOqY9IsvePzlnXaTZ6nBkyUkk0QwUUvfM/WlYES2

def brute_force_attack(hash_to_crack, charset=None, hash_type='md5', dict_path='brute_dict.txt'):
    start_time = time.time()

    # choose hash function once
    if hash_type == 'md5':
        hash_func = lambda s: hashlib.md5(s).hexdigest()
    elif hash_type == 'sha256':
        hash_func = lambda s: hashlib.sha256(s).hexdigest()
    else:
        print("Unsupported hash type.")
        return None

    # open the wordlist once
    try:
        with open(dict_path, 'r', encoding='utf-8') as f:
            for line in f:
                password = line.rstrip('\n')
                hashed = hash_func(password.encode('utf-8'))
                if hashed == hash_to_crack:
                    end_time = time.time()
                    print(f"Password found: {password}")
                    print(f"Time taken: {end_time - start_time:.2f} seconds")
                    return password
    except FileNotFoundError:
        print(f"Dictionary file not found: {dict_path}")
        return None

    return None

# Example usage:
if __name__ == "__main__":
    target_hash = input("Enter the hash to crack: ")
    hash_algorithm = input("Enter the hash type (md5/sha256): ").lower()
    brute_force_attack(target_hash, hash_type=hash_algorithm)

#     python brute.py
# Enter the hash to crack: 5416d7cd6ef195a0f7622a9c56b55e84
# Enter the hash type (md5/sha256): md5
# Password found: 1q2w3e4r
# Time taken: 0.00 seconds
