#!/usr/bin/env python3
# Copyright (c) 2015-2024 Sam Gleske - https://github.com/samrocketman/repository-secrets
# MIT Licensed
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import binascii
import os
import random
import re
import string
import sys
import yaml

# optional KMS
try:
    import boto3
    import botocore
except ModuleNotFoundError:
    pass


class RepositorySecrets:
    private_key = None
    public_key = None
    kms_client = None
    openssl_aes_args = "-aes-256-cbc -pbkdf2 -iter 600000"
    openssl_rsa_args = "-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256"
    pbkdf2_password_length = 389
    pbkdf2_salt_length = 8

    def __init__(self):
        self.pbkdf2_password_length = int(
            os.getenv("pbkdf2_password_length", self.pbkdf2_password_length)
        )
        self.set_pbkdf2_salt_length(
            int(os.getenv("pbkdf2_salt_length", self.pbkdf2_salt_length))
        )
        self.openssl_aes_args = os.getenv("openssl_aes_args", self.openssl_aes_args)
        self.openssl_rsa_args = os.getenv("openssl_rsa_args", self.openssl_rsa_args)
        self.load_private_pem(os.getenv("PRIVATE_KEY", "/tmp/id_rsa"))
        self.load_public_pem(os.getenv("PUBLIC_KEY", "/tmp/id_rsa.pub"))

    def set_pbkdf2_salt_length(self, saltlen):
        saltlen = int(saltlen)
        if saltlen < 1:
            raise AssertionError("pbkdf2_salt_length must be greater than 0.")
        elif saltlen > 16:
            raise AssertionError("pbkdf2_salt_length must be less than or equal to 16.")
        self.pbkdf2_salt_length = int(saltlen)
        if isinstance(self.public_key, rsa.RSAPublicKey):
            calculated_max_pword = self.public_key.key_size / 8 - (
                115 + self.pbkdf2_salt_length
            )
            if calculated_max_pword < self.pbkdf2_password_length:
                self.pbkdf2_password_length = calculated_max_pword

    def set_pbkdf2_iterations(self, iterations):
        self.openssl_aes_args = "-aes-256-cbc -pbkdf2 -iter %d" % int(iterations)

    def load_kms_client(self, kms_client):
        if not isinstance(kms_client, botocore.client.BaseClient):
            raise AssertionError("Not a valid KMS client.")
        self.kms_client = kms_client

    def load_public_pem(self, public_pem):
        if isinstance(public_pem, str) and "-----BEGIN PUBLIC KEY-----" in public_pem:
            self.public_key = serialization.load_pem_public_key(
                public_pem.encode("utf-8")
            )
            return
        elif not os.path.exists(public_pem):
            self.public_key = public_pem
            return
        with open(public_pem, "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(key_file.read())
        self.pbkdf2_password_length = int(
            os.getenv(
                "pbkdf2_password_length",
                self.public_key.key_size / 8 - (115 + self.pbkdf2_salt_length),
            )
        )

    def load_private_pem(self, private_pem):
        if (
            isinstance(private_pem, str)
            and ":kms:" in private_pem
            and self.kms_client is None
        ):
            self.load_kms_client(boto3.client("kms"))
        elif (
            isinstance(private_pem, str)
            and "-----BEGIN PRIVATE KEY-----" in private_pem
        ):
            self.private_key = serialization.load_pem_private_key(
                private_pem.encode("utf-8"),
                password=None,
            )
            return
        elif not os.path.exists(private_pem):
            self.private_key = private_pem
            return
        with open(private_pem, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

    def encrypt(self, plain_text):
        cipher_yaml = self.__get_initial_cipher_yaml()
        passin = self.__randompass(self.pbkdf2_password_length)
        salt = self.__randomsalt(self.pbkdf2_salt_length)
        cipher_yaml["data"] = self.__encrypt_with_aes(
            plain_text, passin, salt, cipher_yaml
        )
        known_hash = self.__calculate_hash(passin, salt, cipher_yaml)
        plain_hash = self.__encode_plain_hash(known_hash, passin, salt)
        cipher_yaml["hash"] = self.__pem_encrypt_hash(plain_hash)
        return self.__render_cipher_yaml(cipher_yaml)

    def decrypt(self, cipher_yaml):
        parsed_cipher_yaml = self.__parse_cipher_yaml(cipher_yaml)
        known_hash, passin, salt = self.__decrypt_with_client(parsed_cipher_yaml)
        self.__verify(known_hash, passin, salt, parsed_cipher_yaml)
        return self.__decrypt_with_aes(passin, salt, parsed_cipher_yaml)

    def rotate(self, cipher_yaml):
        parsed_cipher_yaml = self.__parse_cipher_yaml(cipher_yaml)
        known_hash, passin, salt = self.__decrypt_with_client(parsed_cipher_yaml)
        self.__verify(known_hash, passin, salt, parsed_cipher_yaml)
        new_cipher_yaml = self.__get_initial_cipher_yaml()
        new_cipher_yaml["data"] = parsed_cipher_yaml["data"]
        new_hash = self.__calculate_hash(passin, salt, new_cipher_yaml)
        plain_hash = self.__encode_plain_hash(new_hash, passin, salt)
        new_cipher_yaml["hash"] = self.__pem_encrypt_hash(plain_hash)
        return self.__render_cipher_yaml(new_cipher_yaml)

    def __get_initial_cipher_yaml(self):
        if self.pbkdf2_password_length < 125:
            raise AssertionError(
                "pbkdf2_password_length must not be less than 125 characters."
            )
        cipher_yaml = dict(
            openssl_aes_args=self.openssl_aes_args,
            openssl_rsa_args=self.openssl_rsa_args,
            pbkdf2_password_length=self.pbkdf2_password_length,
            pbkdf2_salt_length=self.pbkdf2_salt_length,
        )
        return cipher_yaml

    def __parse_cipher_yaml(self, cipher_yaml):
        if isinstance(cipher_yaml, str) and os.path.exists(cipher_yaml):
            with open(cipher_yaml, "rb") as yaml_file:
                parsed_cipher_yaml = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        else:
            parsed_cipher_yaml = yaml.load(cipher_yaml, Loader=yaml.SafeLoader)
        return parsed_cipher_yaml

    def __decrypt_with_client(self, parsed_cipher_yaml):
        if self.kms_client is not None:
            known_hash, passin, salt = self.__kms_decrypt_hash(parsed_cipher_yaml)
        elif isinstance(self.private_key, rsa.RSAPrivateKey):
            known_hash, passin, salt = self.__pem_decrypt_hash(parsed_cipher_yaml)
        else:
            raise AssertionError("No private key available for decryption.")
        return known_hash, passin, salt

    def __randompass(self, pass_length):
        # symbols is string.punctuation without "|" character
        characters = "".join(
            [string.ascii_letters, string.digits, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{}~"]
        )
        passin = "".join(random.choice(characters) for i in range(pass_length))
        return passin

    def __randomsalt(self, salt_length_bytes):
        return binascii.hexlify(os.urandom(salt_length_bytes)).decode()

    def __encode_plain_hash(self, known_hash, passin, salt):
        hash_salt = base64.b64encode(binascii.unhexlify(known_hash + salt)).decode()
        return "|".join([passin, hash_salt])

    def __decode_plain_hash(self, plain_hash):
        passin, hash_salt = plain_hash.decode("utf-8").split("|")
        hash_salt = binascii.hexlify(base64.b64decode(hash_salt)).decode()
        known_hash = hash_salt[:64]
        salt = hash_salt[64:]
        return known_hash, passin, salt

    def __base64_oneline_to_base64_multiline(self, encoded_data):
        # Add newlines every 64 characters
        multiline_data = encoded_data.decode("utf-8")
        multiline_data = "\n".join(
            multiline_data[i : i + 64] for i in range(0, len(multiline_data), 64)
        )
        return multiline_data

    def __pem_encrypt_hash(self, plain_hash):
        cipher_hash = self.public_key.encrypt(
            plain_hash.encode("utf-8"),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return self.__base64_oneline_to_base64_multiline(base64.b64encode(cipher_hash))

    def __kms_decrypt_hash(self, cipher_yaml):
        plain_hash = self.kms_client.decrypt(
            KeyId=self.private_key,
            CiphertextBlob=base64.b64decode(cipher_yaml["hash"]),
            EncryptionAlgorithm="RSAES_OAEP_SHA_256",
        )["Plaintext"]
        return self.__decode_plain_hash(plain_hash)

    def __pem_decrypt_hash(self, cipher_yaml):
        plain_hash = self.private_key.decrypt(
            base64.b64decode(cipher_yaml["hash"]),
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return self.__decode_plain_hash(plain_hash)

    def __calculate_hash(self, passin, salt, cipher_yaml):
        # verify cipher YAML against SHA256 hash
        data_to_verify = "\n".join(
            [
                passin,
                salt,
                cipher_yaml["openssl_aes_args"],
                cipher_yaml["openssl_rsa_args"],
                str(cipher_yaml["pbkdf2_salt_length"]),
                str(cipher_yaml["pbkdf2_password_length"]),
                cipher_yaml["data"],
            ]
        )
        data_to_verify += "\n"
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data_to_verify.encode("utf-8"))
        return binascii.hexlify(digest.finalize()).decode()

    def __verify(self, known_hash, passin, salt, cipher_yaml):
        calculated_hash = self.__calculate_hash(passin, salt, cipher_yaml)
        if calculated_hash != known_hash:
            raise AssertionError("Checksum verification failed.  Refusing to decrypt.")

    def __derive_with_pbkdf2(self, passin, salt, cipher_yaml):
        match = re.search(r"-iter ([0-9]+)", cipher_yaml["openssl_aes_args"])
        if match:
            iterations = int(match.group(1))
        else:
            raise AssertionError(
                "Could not determine PBKDF2 iterations from openssl_aes_args."
            )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,  # key(32) + iv(16) size
            salt=binascii.unhexlify(salt),
            iterations=iterations,
        )
        key_iv = kdf.derive(passin.encode("utf-8"))
        key, iv = key_iv[:32], key_iv[32:]
        return key, iv

    def __encrypt_with_aes(self, plaintext, passin, salt, cipher_yaml):
        key, iv = self.__derive_with_pbkdf2(passin, salt, cipher_yaml)
        # pad with pkcs7 for 16-byte block size (128 bits)
        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()
        # encrypt data with AES
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = encryptor.update(plaintext)
        data += encryptor.finalize()
        return self.__base64_oneline_to_base64_multiline(base64.b64encode(data))

    def __decrypt_with_aes(self, passin, salt, cipher_yaml):
        key, iv = self.__derive_with_pbkdf2(passin, salt, cipher_yaml)
        # decrypt data with AES
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(
            base64.b64decode(cipher_yaml["data"].replace("\n", ""))
        )
        plaintext += decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        return plaintext

    def __indent_two_spaces(self, multiline_string):
        multiline_string = "  " + multiline_string
        multiline_string = "\n  ".join(multiline_string.split("\n"))
        return multiline_string

    def __render_cipher_yaml(self, cipher_yaml):
        cipher_yaml_text = []
        cipher_yaml_text.append(
            "openssl_aes_args: %s" % cipher_yaml["openssl_aes_args"]
        )
        cipher_yaml_text.append(
            "openssl_rsa_args: %s" % cipher_yaml["openssl_rsa_args"]
        )
        cipher_yaml_text.append(
            "pbkdf2_password_length: %d" % cipher_yaml["pbkdf2_password_length"]
        )
        cipher_yaml_text.append(
            "pbkdf2_salt_length: %d" % cipher_yaml["pbkdf2_salt_length"]
        )
        cipher_yaml_text.append("data: |-")
        cipher_yaml_text.append(self.__indent_two_spaces(cipher_yaml["data"]))
        cipher_yaml_text.append("hash: |-")
        cipher_yaml_text.append(self.__indent_two_spaces(cipher_yaml["hash"]))
        return "\n".join(cipher_yaml_text) + "\n"


if __name__ == "__main__":
    rs = RepositorySecrets()
    # Alternate loading of pems directly rather than from a file.
    #    with open("/tmp/id_rsa", "rb") as f:
    #        rs.load_private_pem(f.read().decode())
    #    with open("/tmp/id_rsa.pub", "rb") as f:
    #        rs.load_public_pem(f.read().decode())
    print("Decrypt example", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(rs.decrypt("../../cipher.yaml").decode(), end="", file=sys.stderr)
    print("\nRotate key without changing encrypted data", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    new_cipher_yaml = rs.rotate("../../cipher.yaml")
    with open("../../new-cipher.yaml", "w") as f:
        f.write(new_cipher_yaml)
        f.write("\n")
    print("Run 'diff -u ../../cipher.yaml ../../new-cipher.yaml' to see differences.", file=sys.stderr)
    print("\nEncrypt example", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    print(rs.encrypt("This text was encrypted by Python!\n".encode("utf-8")), end="")
