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

Encrypt some text.

    echo supersecret | ./repository-secrets.sh encrypt -o cipher.yaml

Results in encrypted YAML like the following.

```yaml
openssl_aes_args: -aes-256-cbc -pbkdf2 -iter 600000
openssl_rsa_args: -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256
salt: |-
  I51dA2unsNYb6dIHJ/oSS8BGXnQ0BxDD7/VLpAALlbKlobg156jVH+Hm17xwVD9y
  ZkI9YVivkLsohhKvMR/KKGCfXP4bq3fgjjbbw0fq9Tz/KUDj4HxYDGVUKkOeVVgh
  keOG6H3mWKIOs0HoOGcUCbse4bb4EZpYCTzYKxEfns6U5N8REMp6U11o81I4M21R
  ixAhgn47FB03DeNcwVv43PHgjjm3j6GssfWIt+gfCPgZwFvJKU8tyie0nr8TJD+A
  qsQ1ZK1ANQcrkOdB2P2454AWumW2I2kS33Wsv+ZWmI9FH42f1EQkO3jhk0qEpmMh
  pWfNPRZObS6tFr1kRPW2mIHN0he+evkB8JJeTy8Jw7Cz6I+wmcR9p9qrZa8jRVgL
  okTiigtl7UaIGf56+kbepnM1yp0kQBU18hM4KzTJRoOtpMUWP68Z/zASGmU32x44
  BZT51g70pCu/vyW453Ln7O1xEHW8QYGeb1+io5bWPenBSm4GrVNeMFXfZuUN9+8K
  PdNjjfq6EsSacutQaZ6fGRqbiaAG8qn9zP2kTUPYRiKFbBI+/y6X9ASUm5J4RDnZ
  kDvizRvagtDqtA3dq1XsjibplLOs1bzH1yAJxssuGgYnUln4jLBUtDWUuc2XwC40
  t0o8WNaCzeKu1B3FfQC9D20pZgZ+tZTjJq+hTTlbS8o=
passin: |-
  lju2hvVNdnYvw/cppqMaO+kD0RWFN34rdIF3V6ylSRZOsrX/CfK2T4ApICvAy06m
  RSlfpnHOpp1eWTwUvGPbg1LfHsN28I4S7UGWzybRrRp+SLQtSqA8rTpa1uz8ypx3
  GHKbrkGtvEOxCDBKMn5QPEayb261+9PhvLQPTvdkTQaY5k9Vv8P3d7qPAYUmaNIM
  rCnyx2lHqpPAriBA3/1lBSJ7KNpZqnj4kftxW6YPAhrDOGhAYdkUC/6Hqwyj2ck3
  0ZLOBinDvuZZjobpNYJQ/YvqEcbspFqFuRKkFM8GywJkyiUdNxLepgdm8/V/Q990
  FyT2ik5Q+4Xvswzqba3asLZ2Kh43BPK+oVJc+uNwoSveBapy9SvGCuI+AGB34tic
  gE/xf0FzQ3UOFmtUGx5wG9RApTDgGP1o2YVeMXLzLNcF30H8sZ2JLxOR8YFMuP5C
  kOGrYaK42/QC5FyKWX3a/R6umU+qt8ij3+nxy26MRkl665USfke9SVTMwdjB4+U7
  O9zi1XTqKQanN77td6Y2CCepxsWmHkaLJOuV0kNw4J2tlS8F0GjyZiTTq++cjrcA
  PvIDQaUUOrdHJqczG/EEEzg/swFfNJbhFqo3DZuZIQMGjQ7x/6d1q/CCB9swkjou
  MBIymns81TXiTIY4das0k7bp92tUCedwkSMaxismuDI=
data: |-
  TMq0QsWmyFQTr5IHWuHgtw==
hash: |-
  ECXdHwjCc1BDdTY6v8YIk+CNmnjCguOenHsHl4f8qISdHsVouxoA4mSsfg2Dw58p
  5IStOtfQ4ktMZiFSnkrAhWisCtIdJqaCWp2/yQA1KCtLdRAT4qjtVTZMf9bT+oS0
  aqbF9R7ODHXa8G90PqM0R4B7H7RHrRS4Bp0XhabJ+NAviTsmWneQf075WECfMqod
  HDZRQrihhs1hPR8efBqnR5LWkLopGNLr9dvQvw0BY1kqT2TMJ/CUmj2A/QkTpCB+
  ngqDfH9qepuI1VjMDrRMiz/Vy2h95sBkb4tbnjGznfo7TEpjb7G/W8OeJJ2pjIQm
  y5x4O7GMRmZePBjVUhkRIQSQdpOk0HrZOHc6NaobV7yaaQ3Q4DVShZ0Nyd2dnOU6
  XOCy6A/BoULX75VvWMWkAIFQ3CRh20QMlnceO80i+RXd3Bk+jGYaFiigFCULL+XY
  544wyUrkWZC7/dPSXC47FcsqAmhF2XeDePJavTwyk1HdP6G/h1iWWhM0yoDUTwCL
  64eP6dnqPHc3W5G+6bUTIlibVuryN4Lhw1V7KsDucadu3FAlV3hyuXLmuefVE3Xa
  2tzWNqFQAuCEGiGMJFLBjHmsfBPtFXuYNMyhB3B/6fGdFaAltqL2Urj+HdlkCasA
  4yhvtrEozkmhOVUdycLcGL9QWuOh7EoGgsnFvJkySNM=
```

Which you can then decrypt.

```bash
./repository-secrets.sh decrypt -i cipher.yaml
# prints to stdout supersecret
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
  openssl_saltlen
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
    Defult: '/tmp/id_rsa'

  PUBLIC_KEY
    Path to RSA public key file used for encryption.  Used as -keyin argument
    for openssl pkeyutl.
    Defult: '/tmp/id_rsa.pub'


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

  Advanced example using AWS KMS backend for private key.

    url="https://github.com/samrocketman/openssl-engine-kms/releases/download/0.1.1/$(arch)-$(uname)_libopenssl_engine_kms.so.gz"
    curl -sSfL "$url" | gunzip > libopenssl_engine_kms.so
    export openssl_rsa_args='-keyform engine -engine ./libopenssl_engine_kms.so -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'
    export PRIVATE_KEY=arn:aws:kms:us-east-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef
    export PUBLIC_KEY=arn:aws:kms:us-east-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef

    echo hello | ./repository-secrets.sh encrypt

  Advanced example using RSA public key to encrypt and AWS KMS to decrypt.

    export kms_openssl_rsa_args='-keyform engine -engine ./libopenssl_engine_kms.so -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'
    export PRIVATE_KEY=arn:aws:kms:us-east-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef
    export PUBLIC_KEY=/tmp/id_rsa.pub

    echo hello | ./repository-secrets.sh encrypt | \
      openssl_rsa_args="$kms_openssl_rsa_args" ./repository-secrets.sh decrypt -s openssl_rsa_args


OLD OPENSSL NOTICE

  Old OpenSSL versions before OpenSSL 3.2 do not have -saltlen option
  available.  You must set a few environment variables in order for
  ./repository-secrets.sh to be compatible with older OpenSSL releases.

    openssl_saltlen=8
    openssl_aes_args='-aes-256-cbc -pbkdf2 -iter 600000'
    export openssl_saltlen openssl_aes_args
    echo plaintext | ./repository-secrets.sh encrypt -o /tmp/cipher.yaml

  You can upgrade the encryption if migrating to OpenSSL 3.2 or later.  Note
  the old and new file names must be different.  Also note that openssl_saltlen
  and openssl_aes_args environment variables are prefixed on the first command
  and not exported to the second command.

    openssl_saltlen=8 openssl_aes_args='-aes-256-cbc -pbkdf2 -iter 600000' \
      ./repository-secrets.sh decrypt -i cipher.yaml -k id_rsa | \
      ./repository-secrets.sh encrypt -p id_rsa.pub -o new-cipher.yaml
    mv new-cipher.yaml cipher.yaml

  For even older OpenSSL, you might not want to use
  RSA/ECB/OAEPWithSHA-256AndMGF1Padding and instead use RSA/ECB/PKCS1Padding.
  You can accomplish this by overriding openssl_rsa_args with an empty space.
  Note the space is required so that the veriable is non-zero length.

    openssl_rsa_args=' '
    echo hello | ./repository-secrets.sh encrypt


ALGORITHMS

  SHA-256 for data integrity verification.
  RSA/ECB/OAEPWithSHA-256AndMGF1Padding for asymmetric encryption storage.
  AES/CBC/PKCS5Padding for symmetric encryption storage.
  PBKDF2WithHmacSHA256 for key derivation; 600k iterations with 16-byte salt.
```
