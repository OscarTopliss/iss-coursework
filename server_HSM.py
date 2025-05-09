######################### SERVER HSM METHODS ###################################
# Methods for interacting with the server's "HSM". These methods are used by
# both the main server script and the server database script, so I'm putting
# these methods here so they can be imported by both.

## Imports
# Cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
# Misc
import json


def write_secret_to_hsm(key: str, value: str):
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        secrets[key] = value
        with open("./HSM-server/secrets.json", "w+") as new_secrets_file:
            json.dump(secrets, new_secrets_file)


def get_pepper() -> bytes:
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        return bytes.fromhex(secrets["pepper"])

def generate_aes_key():
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        aes_keys = secrets["aes-keys"]
        new_key = AESGCM.generate_key(256)
        aes_keys.append(new_key.hex())
        secrets["aes-keys"] = aes_keys

    with open("./HSM-server/secrets.json", "w") as new_secrets_file:
        json.dump(secrets, new_secrets_file)

# Encrypt the given value with the most recent AES key in the "HSM".
# Returns the index of the key used, the nonce, the encrypted data, and the HMAC
# as one bytes object in the form INDEX:NONCE:DATA:MAC, with the index stored
# in 2 bytes.
# Note, the ciphertext library AES_GCM implementation pre-appends the tag, so
# I don't need to handle it directly.
def encrypt_aes(plaintext: bytes) -> bytes:
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        aes_keys = secrets["aes-keys"]
        key_index = len(aes_keys) - 1
        key = bytes.fromhex(aes_keys[-1])

    ciphertext = bytes()
    # https://www.geeksforgeeks.org/how-to-convert-int-to-bytes-in-python/
    ciphertext += key_index.to_bytes(2, "big")
    nonce = os.urandom(12)
    ciphertext += nonce
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=None)
    ciphertext += encrypted_data
    return ciphertext

# Decrypts and verifies a value.
def decrypt_and_verify_aes(ciphertext: bytes) -> bytes:
    key_index = int.from_bytes(ciphertext[:2], "big")
    print(f"key_index_bytes: {ciphertext[:2]}")
    print(f"key_index {key_index}")
    nonce = ciphertext[2:14]
    data_with_tag = ciphertext[14:]
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        aes_keys = secrets["aes-keys"]
        key = bytes.fromhex(aes_keys[key_index])

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(
            nonce = nonce,
            data = data_with_tag,
            associated_data = None
        )
    except InvalidTag:
        return b''
    else:
        return plaintext

# Decyrpts a value, verifies it, and re-encrypts it with the most recent AES
# key.
def re_encrypt_aes(ciphertext: bytes) -> bytes:
    plaintext = decrypt_and_verify_aes(ciphertext)
    new_ciphertext = encrypt_aes(plaintext)
    return new_ciphertext

def test_encryption_methods():
    generate_aes_key()
    data = b"test"
    print(f"original data: {data!r}")
    encrypted_data = encrypt_aes(data)
    print(f"Encrypted data: {str(encrypted_data.hex())}")
    decrypted_data = decrypt_and_verify_aes(encrypted_data)
    print(f"Decrypted data: {decrypted_data!r}")
    generate_aes_key()
    decrypted_data = decrypt_and_verify_aes(encrypted_data)
    print(f"Decrypting data with old key after key rotation:{decrypted_data!r}")
    re_encrypted_data = re_encrypt_aes(encrypted_data)
    print(f"re-encrypted data:{str(re_encrypted_data.hex())}")
    decrypted_data = decrypt_and_verify_aes(re_encrypted_data)
    print(f"Final decrypted data:{decrypted_data!r}")


if __name__ == "__main__":
    test_encryption_methods()
