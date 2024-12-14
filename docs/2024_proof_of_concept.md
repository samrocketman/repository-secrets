# 2024 proof of concept

Enable developers to use an RSA public key to encrypt data.  A backend system
would use the RSA private key to decrypt data.  The data can be plain text or
binary.  Usage and intent should be flexible.

### Goals

Improvements over the [original proof of concept](proof_of_concept.md).

* Use strong cryptography.
* Rely solely on openssl even for larger files.
* Keep dependencies as minimal as possible.

### Cryptography

Algorithms

- SHA-256 used for hashing and data integrity.
- RSA/ECB/PKCS1Padding for asymmetric encryption storage.  4096-bit or higher
  recommended.
- AES/CBC/PKCS5Padding for symmetric encryption storage.
- PBKDF2WithHmacSHA256 for key derivation; 600000 iterations with 16-byte salt.

# Encrypting

In general, the storage will be a YAML file; which will be called cipher YAML
referring to YAML containing keys with encrypted data.

- `openssl_args` YAML key will be plain text describing some of the arguments
  passed to openssl for encrypting and decrypting data with AES.
- Generate a random 128 character password (128 bytes).
- Generate a random 16-byte salt.
- RSA public key encrypts password to be stored in `passin` YAML key.
- RSA public key encrypts salt to be stored in `salt` YAML key.
- A key-derivation function will be used to create an AES key from the password.
- Encrypt the data with AES.  Encrypted data to be stored in `data` YAML key.
- The contents of YAML keys `openssl_args`, `salt`, `passin`, and `data` will be
  combined and a SHA-256 hash is calculated.  The resulting hash will be
  encrypted with the RSA public key and stored in `hash` YAML key.

The generic format of the cipher YAML is the following.

```yaml
openssl_args: <plain text args for symmetric encryption>
salt: <RSA encrypted via public key; 16 bytes of random data>
passin: <RSA encrypted via public key; 128-character password>
data: <AES encrypted with salt and passin>
hash: <RSA encrypted via public key; hash of openssl_args + salt + passin + data>
```

# Decryption

Decryption wil be roughly in reverse of encryption.

- Copy the cipher YAML to a location exclusive to the script.  All read and
  write operations occur within this location.
- Decrypt the `hash` with RSA private key.
- Combine YAML keys `openssl_args`, `salt`, `passin`, and `data` and checksum
  with SHA-256.  Compare the calculated checksum with the decrypted hash in
  previous step.
- Do not proceed if hashes don't match.  Tampering or corruption may have
  occurred so don't bother decrypting.
- Decrypt the `salt` with RSA private key.
- Decrypt the `passin` with RSA private key.
- Decrypt the `data` with AES using `salt`, `passin`, and `openssl_args`.

# Benefits

- Minimal requirements: some coreutils, bash, yq, and openssl.
- Because data is stored with AES, there's theoretically no limit to the amount
  of data you can encrypt.
- Unlike the previous proof of concept, binary data is allowed.
