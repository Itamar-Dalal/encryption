from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    iv = cipher.iv
    return iv + ciphertext

def decrypt(encrypted_message, key):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

# Example usage:
secret_key = b'\xd7O;\x93\xa8Xj\xb6\xa2\xc9\x1bB\xefCc\xce'  # Generating a random 16-byte key
message = "Hello, World!".encode()
encrypted_message = encrypt(message, secret_key)
print("Encrypted:", encrypted_message)
decrypted_message = decrypt(encrypted_message, secret_key)
print("Decrypted:", decrypted_message)
