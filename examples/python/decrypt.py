#!/usr/bin/env python3
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import yaml
import base64
import binascii

with open("../../cipher.yaml", "rb") as yaml_file:
    cipher_yaml=yaml.load(yaml_file, Loader=yaml.SafeLoader)

with open("/tmp/id_rsa", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

# decrypt and break up plain text into password and hash + salt
passin, hash_salt = private_key.decrypt(
    base64.b64decode(cipher_yaml["hash"]),
    asymmetric.padding.OAEP(
        mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
).decode("utf-8").split("|")

# get hash and salt
hash_salt = binascii.hexlify(base64.b64decode(hash_salt)).decode()
known_hash = hash_salt[:64]
salt = hash_salt[64:]

# verify cipher YAML against SHA256 hash
data_to_verify =  "\n".join([
    passin,
    salt,
    cipher_yaml["openssl_aes_args"],
    cipher_yaml["openssl_rsa_args"],
    str(cipher_yaml["pbkdf2_salt_length"]),
    str(cipher_yaml["pbkdf2_password_length"]),
    cipher_yaml["data"]
]) + "\n"
digest = hashes.Hash(hashes.SHA256())
digest.update(data_to_verify.encode("utf-8"))
calculated_hash = binascii.hexlify(digest.finalize()).decode()
if calculated_hash != known_hash:
    raise AssertionError('Checksum verification failed.  Refusing to decrypt.')

# derive key and iv with pbkdf2 hmac sha256
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=48, # key(32) + iv(16) size
    salt=binascii.unhexlify(salt),
    iterations=600000,
)
key_iv = kdf.derive(passin.encode('utf-8'))
key, iv = key_iv[:32], key_iv[32:]

# decrypt data with AES
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(base64.b64decode(cipher_yaml["data"].replace("\n", ""))) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(plaintext) + unpadder.finalize()

# print to stdout the decrypted txt
print(plaintext.decode(), end='')
