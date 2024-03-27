from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Example usage:
if __name__ == "__main__":
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Original string
    original_string = "Hello, RSA encryption!"

    # Encrypt the string
    encrypted_data = rsa_encrypt(public_key, original_string)
    print("Encrypted data:", encrypted_data.hex())

    # Decrypt the encrypted data
    decrypted_string = rsa_decrypt(private_key, encrypted_data)
    print("Decrypted string:", decrypted_string)
