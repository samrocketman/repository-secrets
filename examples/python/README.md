# Python example of repository secrets

This Python 3 example is meant to be compatible with
[repository-secrets.sh](../../repository-secrets.sh).  It is encapsulated in a
single, easy to use, class named [`RepositorySecrets`](RepositorySecrets.py).

You can encrypt with `repository-secrets.sh` and decrypt with
`RepositorySecrets` or visa versa.

# Prerequisites

Set up python packages.

    python3 -m venv /tmp/venv
    source /tmp/venv/bin/activate
    pip install -r requirements.txt

If you want the latest dependencies, then

    pip install cryptography pyyaml boto3

`boto3` is optional since usage of KMS is not required.

# Code checking and formatting

Install code formatters.

    pip install flake8 black

Code auto formatter

    black RepositorySecrets.py

Lint code format

# Running Example

Set up

    openssl genrsa -out /tmp/id_rsa 4096
    openssl rsa -in /tmp/id_rsa -pubout -outform pem -out /tmp/id_rsa.pub
    echo 'This text was decrypted by Python!' | \
    ../../repository-secrets.sh encrypt -o ../../cipher.yaml

Show decrypt and encrypt with cipher text.

    ./RepositorySecrets.py


Pipe python-encrypted output into `repository-secrets.sh` to show compatibility.

    ./RepositorySecrets.py | ../../repository-secrets.sh decrypt
