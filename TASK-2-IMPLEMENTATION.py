from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import os

#The logic and structure of combining Blowfish and RSA for hybrid encryption is my customized implementation

#cryptography.hazmat.primitives.ciphers: Provides symmetric encryption tools
#cryptography.hazmat.primitives: Contains cryptographic primitives like hashes and padding.
#cryptography.hazmat.primitives.asymmetric.rsa: Provides functionality to generate and use RSA keys for encryption, decryption, and signing.
#cryptography.hazmat.primitives.asymmetric.padding: Provides padding schemes for asymmetric algorithms like RSA.
#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC: Implements the PBKDF2 (Password-Based Key Derivation Function 2) with HMAC (Hash-Based Message Authentication Code).
#cryptography.hazmat.primitives.serialization: Provides methods to serialize and deserialize cryptographic keys.
#os: Used to generate random keys and initialization vectors (IVs).

# Utility functions for key management
def generate_blowfish_key():
    """Generate a 128-bit Blowfish key."""
    # Generates a random 16-byte key suitable for Blowfish encryption
    return os.urandom(16)

def generate_rsa_keys():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_blowfish(key, plaintext):
    """Encrypt data using Blowfish."""
    # Generate a random IV (Initialization Vector) for Blowfish encryption
    iv = os.urandom(8)  # Blowfish block size is 8 bytes
    cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv)) # Using Blowfish with CFB mode
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize() # Encrypt the plaintext
    return iv, ciphertext

def decrypt_blowfish(key, iv, ciphertext):
    """Decrypt data using Blowfish."""
    cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_rsa(public_key, data):
    """Encrypt data using RSA."""
        # Using RSA with OAEP padding and SHA-512 for secure encryption
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

def decrypt_rsa(private_key, ciphertext):
    """Decrypt data using RSA."""
        # Decrypt the ciphertext using RSA private key with OAEP padding
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

def sign_data(private_key, data):
    """Sign data with RSA private key."""
        # Compute the SHA-256 hash of the data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hashed_data = digest.finalize()
    signature = private_key.sign(
        hashed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, data, signature):
    """Verify signature with RSA public key."""
        # Compute the SHA-256 hash of the data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hashed_data = digest.finalize()
    try: # Verify the signature against the hashed data
        public_key.verify(
            signature,
            hashed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False

# Example workflow
if __name__ == "__main__":
    # Generate Blowfish keys for two users
    blowfish_key_user1 = generate_blowfish_key()
    blowfish_key_user2 = generate_blowfish_key()

    # Generate RSA key pairs for key management
    private_key_user1, public_key_user1 = generate_rsa_keys()
    private_key_user2, public_key_user2 = generate_rsa_keys()

    # File to encrypt
    input_file = "message.txt"

    encrypted_file = "encrypted_file.bin"

    decrypted_file = "decrypted_file.txt"

    # Read file content
    with open(input_file, "rb") as file:
        data = file.read()

    # User 1 encrypts file with Blowfish
    iv, ciphertext = encrypt_blowfish(blowfish_key_user1, data)

    # Save encrypted data and iv to a file
    with open(encrypted_file, "wb") as file:
        file.write(iv + ciphertext)

    # Encrypt Blowfish key with RSA public key for sharing
    encrypted_blowfish_key = encrypt_rsa(public_key_user2, blowfish_key_user1)

    # User 2 decrypts Blowfish key with RSA private key
    decrypted_blowfish_key = decrypt_rsa(private_key_user2, encrypted_blowfish_key)

    # Read encrypted data from file
    with open(encrypted_file, "rb") as file:
        file_data = file.read()
        iv = file_data[:8]  # Blowfish IV size
        ciphertext = file_data[8:]

    # User 2 decrypts file with Blowfish
    decrypted_data = decrypt_blowfish(decrypted_blowfish_key, iv, ciphertext)

    # Save decrypted data to a file
    with open(decrypted_file, "wb") as file:
        file.write(decrypted_data)

    # Verify data integrity
    assert decrypted_data == data, "Decryption failed!"

    # Digital signature
    signature = sign_data(private_key_user1, data)

    # Verify signature
    is_verified = verify_signature(public_key_user1, data, signature)
    assert is_verified, "Signature verification failed!"

    # Print completion message
    print("Encryption, decryption, and digital signature completed successfully.")
