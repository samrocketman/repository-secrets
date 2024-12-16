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
- RSA/ECB/OAEPWithSHA-256AndMGF1Padding for asymmetric encryption storage.
  4096-bit or higher recommended.
- AES/CBC/PKCS5Padding for symmetric encryption storage.
- PBKDF2WithHmacSHA256 for key derivation; 600000 iterations with 16-byte salt.

Optionally enable usage of older OpenSSL options and algorithms.

- AES/CBC/PKCS5Padding for symmetric encryption storage.
- PBKDF2WithHmacSHA256 for key derivation; 600000 iterations with 8-byte salt.

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
- Cloud storage backends can be utilized for private key storage; such AWS KMS.

# AWS KMS Usage

I revived and updated a project named [openssl-engine-kms][openssl-engine-kms].

Download the secrets engine.

    curl -sSfLO https://raw.githubusercontent.com/samrocketman/yml-install-files/refs/tags/v3.1/download-utilities.sh
    chmod 755 download-utilities.sh
    curl -sSfL https://github.com/samrocketman/openssl-engine-kms/releases/download/0.1.1/openssl-engine-kms.yaml | ./download-utilities.sh -

On Linux, copy the library as `kms.so` to `engines-3`

    find /usr/lib -type d -name engines-3 | xargs -n1 cp ./libopenssl_engine_kms.so

On MacOS, the binary is linked to homebrew openssl.  Copy to `kms.dylib`

    cp libopenssl_engine_kms.dylib /opt/homebrew/Cellar/openssl@3/3.4.0/lib/engines-3/kms.dylib

Generate an asymmetric KMS key with RSA 4096 to be used for Encryption and
Decryption.

Export the public key.  The intent is to allow develoeprs to encrypt using a
locally stored public key and so no AWS login is required for encryption.

    openssl pkey -engine kms -inform engine -in arn:aws:kms:us-east-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -pubout > kms.pub

Encrypting data with KMS

    export PUBLIC_KEY=/tmp/id_rsa.pub
    echo secret data | repository-secrets.sh encrypt -o cipher.yaml

Decrypting data with KMS.

    export openssl_rsa_args='-keyform engine -engine kms -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'
    export PRIVATE_KEY=arn:aws:kms:us-east-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef
    repository-secrets.sh decrypt -s openssl_rsa_args -i cipher.yaml

Any key management storage can be used as long as there's an openssl engine
available to utilize it for encryption or decryption.

# Other considerations

I considered generating the 32-byte key and 16-byte IV directly.  This would be
more secure than using a key derivation function.  However,
[openssl-enc][openssl-enc] `-K key` option and `-iv IV` option both require
specifying the random data as CLI arguments.  This leaks encryption information
to untrusted processes such as `ps` or `top` run by other users.  OpenSSL
supports passing arguments on stdin which would be more secure than specifying
CLI arguments, but a primary feature of this proof of concept is being able to
encrypt and decrypt data via stdin.  Because of arguments leaking sensitive
information I opted for using PBKDF2 with salt since password arguments can read
from a file.

[openssl-enc]: https://docs.openssl.org/3.4/man1/openssl-enc/
[openssl-engine-kms]: https://github.com/samrocketman/openssl-engine-kms
