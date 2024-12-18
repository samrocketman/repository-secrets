# Securing repository secrets

This is a simple proof of concept around how to secure repository secrets.

The idea is you encrypt secrets with a public key that can be widely
distributed.  Then on a CI system or within a delivery pipeline you decrypt
those secrets with a private key.

* [Old Proof of concept](docs/proof_of_concept.md)
* [2024 proof of concept](docs/2024_proof_of_concept.md)

# repository-secrets.sh CLI utility

### System Requirements

- GNU Bash
- GNU coreutils or similar providing `cat`, `cp`, `dd`, `mktemp`, `shasum` or
  `sha256sum`, and `tr`.
- OpenSSL 3 (OpenSSL 3.2 or later recommended).
- [yq](https://github.com/mikefarah/yq/) for YAML.
- GNU or BSD `awk`
- `xxd`

### Example

Generate a private and public key pair.

    openssl genrsa -out /tmp/id_rsa 4096
    openssl rsa -in /tmp/id_rsa -pubout -outform pem -out /tmp/id_rsa.pub

Encrypt some text.

    echo supersecret | ./repository-secrets.sh encrypt -o cipher.yaml

Results in cipher YAML like the following.

```yaml
openssl_aes_args: -aes-256-cbc -pbkdf2 -iter 600000
openssl_rsa_args: -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256
pbkdf2_password_length: 389
pbkdf2_salt_length: 8
data: |-
  sIk/SjszW6tJz3M7gaqkHQ==
hash: |-
  CUmTHeMGuJxwlxtgfpI9gP5Hu4q9ewluifadchPcDRExb/L4J1CoF9g7ssJ/T4zk
  96htHxZwRkLWqEekBktgN5SFmn1n905xYB8xvEXRrfysz/FDb92E4lmFxxAKOf+V
  A4YVCu36VskxhN15W+TNgiOfhJl0cTpyy9z3L9zwuIKfQG1fq4x8bb9E5t1N/RTy
  ZRmJByE4BcGWxPB0OIkaikkZnze71CV+Cg8F3Ovmn3fORN61aGeUhMAkbsMHB6Jp
  zU3JJ9yZS/UPwQgsv1VMHjNdMAkoxZWecdT0OCNU5d3G+Shn/TDBLYgtqT02aQiU
  74cBRVb2/xxjYnQqWBLbcE5xVjtuG0TODnHH7gWD/bjiEbRi+rxB8FF1dbopa26D
  8NfVeQh2T4SdVKJkbyAPlY0vPhcxAihf0HoryS8SPraLIYAFBnZWMruW9WSdGe2c
  oPvXaqAjZiR57UbZOps9ssxyjQzoZAtO46ynsTuYNTjwEt7y1rx5p9E+09KSJBsg
  r/cNNke3cGuRcAAh3lEHpJycyYjNWorzyIk/1F91dxJxQIrssA2ehXEN19lZCPT/
  Bs8ynGN8A7j3gRHwnEtpW8Vx1YeWsfa+zudO1PzEoOISj4PCu4I757D01zUm28jZ
  +MD08rkuEbHiWHITcran9VCbLNX9Hhpz4/tzJ32iOr4=
```

Which you can then decrypt.

```bash
./repository-secrets.sh decrypt -i cipher.yaml
# prints to stdout supersecret
```

Encryption and decryption can be handled in streams.

```bash
echo another secret | ./repository-secrets.sh encrypt | ./repository-secrets.sh decrypt
# 'another secret' is printed on stdout
```

### Docker example

Using a minimal alpine image to encrypt and decrypt secrets.

    docker build -t rs .
    echo plaintext | docker run -i rs encrypt | docker run -i rs decrypt

### Help documentation

`repository-secrets.sh` was written based on the 2024 proof of concept document.

Help documentation: `./repository-secrets.sh help`

```
SYNOPSIS
  ./repository-secrets.sh encrypt [options]
  ./repository-secrets.sh decrypt [options]
  ./repository-secrets.sh rotate-key [options]


DESCRIPTION
  A utility for performing one-way encryption or decryption on files using RSA
  key pairs.  The intent is to have a client encrypt data with an RSA public
  key and a backend system use this same script to decrypt the data with an RSA
  private key.


SUBCOMMANDS
  encrypt
      Performs encryption operations with an RSA public key and outputs an
      encrypted cipher YAML file.  Binary data is allowed.

  decrypt
      Performs decryption operations with an RSA private key and outputs
      original plain text.  May output binary data if binary data was
      originally encrypted.

  rotate-key
      Performs private key rotation on enciphered YAML without changing
      symmetrically encrypted data.  This will not modify data,
      openssl_aes_args, or openssl_rsa_args keys in the enciphered YAML.


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

  -s FIELD
  --skip-field FIELD
    Sometimes upon decryption you may want to override the AES or RSA
    decryption options.  This option allows you to set an environment variable
    of the same name while ignoring the value in the cipher YAML file.  FIELD
    may be one of the following values: openssl_aes_args or openssl_rsa_args.
    This option can be specified multiple times to skip multiple fields.
    Default: ''


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


ENVIRONMENT VARIABLES
  pbkdf2_salt_length
    The length of salt used by PBKDF2 during encryption or decryption.  Must be
    an integer between 1 and 16.
    Default: '8'

  openssl_aes_args
    Arguments used on openssl for AES encryption or decryption.
    Default: '-aes-256-cbc -pbkdf2 -iter 600000'

  openssl_rsa_args
    Arguments used on openssl for RSA encryption or decryption.
    Default: '-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'

  PRIVATE_KEY
    Path to RSA private key file used for decryption.  Used as -keyin argument
    for openssl pkeyutl.
    Default: '/tmp/id_rsa'

  PUBLIC_KEY
    Path to RSA public key file used for encryption.  Used as -keyin argument
    for openssl pkeyutl.
    Default: '/tmp/id_rsa.pub'

  pbkdf2_password_length
    Number of characters of the passphrased used to AES encrypt data.  This
    should be set to the largest number possible given the current design.  The
    current default assumes RSA 4096-bit keys.  If you require 2048-bit keys,
    then set the password length to 108.
    Default: 364


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

AWS KMS SECRETS ENGINE

  Install kms.so (on Linux) or kms.dylib (on Mac).

    curl -sSfLO https://raw.githubusercontent.com/samrocketman/yml-install-files/refs/tags/v3.1/download-utilities.sh
    chmod 755 download-utilities.sh
    curl -sSfL https://github.com/samrocketman/openssl-engine-kms/releases/download/0.1.1/openssl-engine-kms.yaml | ./download-utilities.sh -

  The above commands will download either ./libopenssl_engine_kms.so or
  libopenssl_engine_kms.dylib depending on your architecture and OS.  If
  nothing was downloaded, then your platform does not have a pre-compiled
  binary.  The binary must be copied to OpenSSL engines-3 directory.

  On Linux, install kms.so.

    find /usr/lib -type d -name engines-3 | xargs -I'{}' cp ./libopenssl_engine_kms.so '{}/kms.so'

  On arm64 MacOS, install kms.dylib

    cp libopenssl_engine_kms.dylib /opt/homebrew/Cellar/openssl@3/3.4.0/lib/engines-3/kms.dylib

  In AWS KMS, create an asymmetric key to be used for encryption and
  decryption.  The key spec should be RSA_4096.  Export the public key for
  local encryption which won't require an AWS login to encrypt.

    openssl pkey -engine kms -inform engine -in arn:aws:kms:... -pubout > kms.pub

  Encrypting a file, binary data, or plaintext data using the public key.

    export PUBLIC_KEY=kms.pub
    echo hello | ./repository-secrets.sh encrypt -o cipher.yaml

  On a backend system, use AWS KMS to decrypt the data with the private key.

    export openssl_rsa_args='-keyform engine -engine kms -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'
    export PRIVATE_KEY=arn:aws:kms:...
    ./repository-secrets.sh decrypt -i cipher.yaml

OLD OPENSSL NOTICE

  Old OpenSSL versions before OpenSSL 3.2 do not have -saltlen option available.
  The environment variable defaults are intended to reflect this.

  For even older OpenSSL, you might not want to use
  RSA/ECB/OAEPWithSHA-256AndMGF1Padding and instead use RSA/ECB/PKCS1Padding.
  You can accomplish this by overriding openssl_rsa_args with an empty space.
  Note the space is required so that the veriable is non-zero length.

    export openssl_rsa_args=' '
    echo hello | ./repository-secrets.sh encrypt


ALGORITHMS

  SHA-256 for data integrity verification.
  RSA/ECB/OAEPWithSHA-256AndMGF1Padding for asymmetric encryption storage.
  AES/CBC/PKCS5Padding for symmetric encryption storage.
  PBKDF2WithHmacSHA256 for key derivation; 600k iterations with 16-byte salt.

SOURCE
  Created by Sam Gleske
  https://github.com/samrocketman/yml-install-files
  https://github.com/samrocketman/openssl-engine-kms
  https://github.com/samrocketman/repository-secrets
```
