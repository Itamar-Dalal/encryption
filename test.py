from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serialize the public key in PEM format
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print or save the public key
print(public_key_pem.decode())
print(public_key_pem)
# If you want to save the public key to a file
# with open("public_key.pem", "wb") as f:
#     f.write(public_key_pem)

#def encrypt(message, key):
#    cipher = AES.new(key, AES.MODE_CBC)
#    ciphertext = cipher.encrypt(pad(message, AES.block_size))
#    iv = cipher.iv
#    return iv + ciphertext
#
#def decrypt(encrypted_message, key):
#    iv = encrypted_message[:AES.block_size]
#    ciphertext = encrypted_message[AES.block_size:]
#    cipher = AES.new(key, AES.MODE_CBC, iv)
#    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
#    return decrypted.decode('utf-8')
#
## Example usage:
#secret_key = b'\xd7O;\x93\xa8Xj\xb6\xa2\xc9\x1bB\xefCc\xce'  # Generating a random 16-byte key
#message = "Hello, World!".encode()
#encrypted_message = encrypt(message, secret_key)
#print("Encrypted:", encrypted_message)
#decrypted_message = decrypt(encrypted_message, secret_key)
#print("Decrypted:", decrypted_message)
#