######################### SERVER HSM METHODS ###################################
# Methods for interacting with the server's "HSM". These methods are used by
# both the main server script and the server database script, so I'm putting
# these methods here so they can be imported by both.

## Imports
# Cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

if __name__ == "__main__":
    generate_aes_key()
