# Securing repository secrets

This is a simple proof of concept around how to secure repository secrets.

The idea is you encrypt secrets with a public key that can be widely
distributed.  Then on a CI system or within a delivery pipeline you decrypt
those secrets with a private key.

* [Old Proof of concept](docs/proof_of_concept.md)
* [2024 proof of concept](docs/2024_proof_of_concept.md)

# repository-secrets.sh CLI utility

### Example

Generate a private and public key pair.

    openssl genrsa -out /tmp/id_rsa 4096
    openssl rsa -in /tmp/id_rsa -pubout -outform pem -out /tmp/id_rsa.pub

Encrypt some text

    echo supersecret | ./repository-secrets.sh encrypt -o cipher.yaml

### Help documentation

`repository-secrets.sh` was written based on the 2024 proof of concept document.

Help documentation: `./repository-secrets.sh help`

```
SYNOPSIS
  ./repository-secrets.sh [sub_command] [options]


DESCRIPTION
  A utility for performing one-way encryption or decryption on files using RSA
  key pairs.  The intent is to have a client encrypt data with an RSA public
  key and a backend system use this same script to decrypt the data with an RSA
  private key.


SUBCOMMANDS
  encrypt
      Performs encryption operations with an RSA public key and outputs an
      encrypted YAML file.  Binary data is allowed.

  decrypt
      Performs decryption operations with an RSA private key and outputs
      original plain text.  May output binary data if binary data was
      originally encrypted.

  rotate-key
      Performs private key rotation on enciphered YAML without changing
      symmetrically encrypted data.  This will not modify data or openssl_args
      keys in the enciphered YAML.


ENCRYPT SUBCOMMAND OPTIONS
  -p FILE
  --public-key FILE
    An RSA public key which will be used for encrypting data.
    Default: PUBLIC_KEY environment variable

  -i FILE
  --in-file FILE
    Plain input meant to be encrypted.  Can be plain text or binary data.
    Default: stdin

  -o FILE
  --output FILE
    Encrypted ciphertext in a plain-text friendly YAML format.  If the output
    file already exists as cipher YAML, then only the data and hash will be
    updated.
    Default: stdout


DECRYPT SUBCOMMAND OPTIONS
  -k FILE
  --private-key FILE
    An RSA private key which will be used for decrypting data.
    Default: PRIVATE_KEY environment variable

  -i FILE
  --in-file FILE
    Encrypted ciphertext in a plain-text friendly YAML format.
    Default: stdin

  -o FILE
  --output FILE
    Plain input meant to be which has been decrypted.
    Default: stdout

ROTATE-KEY SUBCOMMAND OPTIONS
  -k FILE
  --private-key FILE
    An RSA private key which will be used to decrypt keys salt, passin, and
    hash within a cipher YAML file.
    Default: PRIVATE_KEY environment variable

  -p FILE
  --public-key FILE
    An RSA public key which will be used to re-encrypt keys salt, passin, and
    hash within a cipher YAML file.
    Default: PUBLIC_KEY environment variable

  -f FILE
  --input-output-file FILE
    A cipher YAML file in which the salt, passin, and hash are updated with the
    new private key.  The data will not be modified.


EXAMPLES

  Generate RSA key pair for examples.

    openssl genrsa -out /tmp/id_rsa 4096
    openssl rsa -in /tmp/id_rsa -pubout -outform pem -out /tmp/id_rsa.pub

  Encrypt data

    echo plaintext | ./repository-secrets.sh encrypt -o /tmp/cipher.yaml
    ./repository-secrets.sh decrypt -i output.yaml

  Working with binary data is the same.

    echo plaintext | gzip -9 | ./repository-secrets.sh encrypt -o /tmp/cipher.yaml
    ./repository-secrets.sh decrypt -i /tmp/cipher.yaml | gunzip

  Rotate private/public key pair.

    ./repository-secrets.sh rotate-key -k old-private-key.pem -p new-public-key.pub -f /tmp/cipher.yaml

  Alternate example.

    export PRIVATE_KEY=old-private-key.pem
    export PUBLIC_KEY=new-public-key.pub
    ./repository-secrets.sh rotate-key -f /tmp/cipher.yaml


OLD OPENSSL NOTICE

  Old OpenSSL versions before OpenSSL 3.2 do not have -saltlen option
  available.  You must set a few environment variables in order for
  ./repository-secrets.sh to be compatible with older OpenSSL releases.

    openssl_saltlen=8
    openssl_args='-aes-256-cbc -pbkdf2 -iter 600000'
    export openssl_saltlen openssl_args
    echo plaintext | ./repository-secrets.sh encrypt -o /tmp/cipher.yaml

  You can upgrade the encryption if migrating to OpenSSL 3.2 or later.  Note
  the old and new file names must be different.  Also note that openssl_saltlen
  and openssl_args environment variables are prefixed on the first command and
  not exported to the second command.

    openssl_saltlen=8 openssl_args='-aes-256-cbc -pbkdf2 -iter 600000' \
      ./repository-secrets.sh decrypt -i cipher.yaml -k id_rsa | \
      ./repository-secrets.sh encrypt -p id_rsa.pub -o new-cipher.yaml
    mv new-cipher.yaml cipher.yaml


ALGORITHMS

  SHA-256 for data integrity verification.
  RSA/ECB/PKCS1Padding for asymmetric encryption storage.
  AES/CBC/PKCS5Padding for symmetric encryption storage.
  PBKDF2WithHmacSHA256 for key derivation; 600k iterations with 16-byte salt.
```
