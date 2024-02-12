import hashlib
import base64
import os
from tqdm import tqdm

class PasswordEncryptor:
    def __init__(self, hash_algorithm="SHA", pbkdf2_iterations=10000):
        """
        Initialize the PasswordEncryptor object with a hash algorithm and PBKDF2 iterations.

        :param hash_algorithm: The hash algorithm to use (default is SHA).
        :param pbkdf2_iterations: The number of iterations for PBKDF2 (default is 10000).
        """
        self.hash_algorithm = hash_algorithm
        self.pbkdf2_iterations = pbkdf2_iterations

    def encrypt_password(self, salt, value):
        """
        Encrypt a password using the specified hash algorithm and salt.

        :param salt: The salt used in the encryption.
        :param value: The password value to be encrypted.
        :return: The encrypted password string.
        """
        if not salt:
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        hash_obj = hashlib.new(self.hash_algorithm)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        result = f"${self.hash_algorithm}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
        return result

    def get_encrypted_bytes(self, salt, value):
        """
        Get the encrypted bytes for a password.

        :param salt: The salt used in the encryption.
        :param value: The password value to get encrypted bytes for.
        :return: The encrypted bytes as a string.
        """
        hash_obj = hashlib.new(self.hash_algorithm)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')

# Example usage:
chosen_algorithm = "SHA1"
salt = "d"
search_hash = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist_path = '/usr/share/wordlists/rockyou.txt'

# Create an instance of the PasswordEncryptor class
encryptor = PasswordEncryptor(chosen_algorithm)

# Get the number of lines in the wordlist for the loading bar
with open(wordlist_path, 'r', encoding='latin-1') as wordlist_file:
    total_lines = sum(1 for _ in wordlist_file)

# Iterate through the wordlist with a loading bar and check for a matching password
with open(wordlist_path, 'r', encoding='latin-1') as wordlist_file:
    for password in tqdm(wordlist_file, total=total_lines, desc="Processing"):
        password_value = password.strip()
        
        # Get the encrypted password
        hashed_password = encryptor.encrypt_password(salt, password_value.encode('utf-8'))
        
        # Compare with the search hash
        if hashed_password == search_hash:
            print(f'CyberiumX Found the Password: {password_value}, hash: {hashed_password}')
            break  # Stop the loop if a match is found
