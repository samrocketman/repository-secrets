#!/bin/bash
# Created by Sam Gleske (https://github.com/samrocketman/repository-secrets)
# Copyright (c) 2015-2024 Sam Gleske - https://github.com/samrocketman/repository-secrets
# MIT Licensed
# Fri Dec 13 21:29:09 EST 2024
# Pop!_OS 22.04 LTS
# Linux 6.9.3-76060903-generic x86_64
# GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)
# yq (https://github.com/mikefarah/yq/) version v4.44.2
# tr (GNU coreutils) 8.32
# OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
# DESCRIPTION
#   A script for encrypting and decrypting secret data.  The purpose of this
#   script is to provide developers a way to asymmetrically encrypt data on
#   client with an RSA public key.  A backend server will use this same script
#   to decrypt the data with an RSA private key.
# REQUIREMENTS
#   Some coreutils (tr, shasum or sha256sum)
#   yq 4.x

set -euo pipefail

#
# ENVIRONMENT AND DEFAULTS
#
openssl_saltlen="${openssl_saltlen:-16}"
openssl_args="${openssl_args:--aes-256-cbc -pbkdf2 -iter 600000 -saltlen ${openssl_saltlen}}"
PRIVATE_KEY="${PRIVATE_KEY:-/tmp/id_rsa}"
PUBLIC_KEY="${PUBLIC_KEY:-/tmp/id_rsa.pub}"

#
# PREREQUISITE UTILITIES
#
missing_util() {
  for x in "$@"; do
    if type -P "$x" &> /dev/null; then
      return 0
    fi
  done
  echo 'Missing utility: '"$@"
  return 1
}
needs_util=0
missing_util shasum sha256sum || needs_util=1
missing_util tr || needs_util=1
missing_util yq || needs_util=1
missing_util bash || needs_util=1
missing_util openssl || needs_util=1
if [ "${needs_util}" = 1 ]; then
  exit 1
fi

#
# PRE-RUN SETUP
#
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
export TMP_DIR
chmod 700 "${TMP_DIR}"
output_file='-'
input_file='-'
sub_command=''

#
# FUNCTIONS
#
helptext() {
cat <<EOF
SYNOPSIS
  $0 [sub_command] [options]


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

    echo plaintext | $0 encrypt -o /tmp/cipher.yaml
    $0 decrypt -i output.yaml

  Working with binary data is the same.

    echo plaintext | gzip -9 | $0 encrypt -o /tmp/cipher.yaml
    $0 decrypt -i /tmp/cipher.yaml | gunzip

  Rotate private/public key pair.

    $0 rotate-key -k old-private-key.pem -p new-public-key.pub -f /tmp/cipher.yaml

  Alternate example.

    export PRIVATE_KEY=old-private-key.pem
    export PUBLIC_KEY=new-public-key.pub
    $0 rotate-key -f /tmp/cipher.yaml


OLD OPENSSL NOTICE

  Old OpenSSL versions before OpenSSL 3.2 do not have -saltlen option
  available.  You must set a few environment variables in order for
  $0 to be compatible with older OpenSSL releases.

    openssl_saltlen=8
    openssl_args='-aes-256-cbc -pbkdf2 -iter 600000'
    export openssl_saltlen openssl_args
    echo plaintext | $0 encrypt -o /tmp/cipher.yaml

  You can upgrade the encryption if migrating to OpenSSL 3.2 or later.  Note
  the old and new file names must be different.  Also note that openssl_saltlen
  and openssl_args environment variables are prefixed on the first command and
  not exported to the second command.

    openssl_saltlen=8 openssl_args='-aes-256-cbc -pbkdf2 -iter 600000' \\
      $0 decrypt -i cipher.yaml -k id_rsa | \\
      $0 encrypt -p id_rsa.pub -o new-cipher.yaml
    mv new-cipher.yaml cipher.yaml


ALGORITHMS

  SHA-256 for data integrity verification.
  RSA/ECB/PKCS1Padding for asymmetric encryption storage.
  AES/CBC/PKCS5Padding for symmetric encryption storage.
  PBKDF2WithHmacSHA256 for key derivation; 600k iterations with 16-byte salt.
EOF
exit 1
}

process_arguments() {
  if [ "${1:-}" = help ]; then
    helptext
  fi
  if [ ! "${1:-}" = encrypt ] \
    && [ ! "${1:-}" = decrypt ] \
    && [ ! "${1:-}" = rotate-key ]; then
    echo 'Must use one of the following subcommands.' >&2
    echo '  - '"$0 encrypt [options]" >&2
    echo '  - '"$0 decrypt [options]" >&2
    echo '  - '"$0 rotate-key [options]" >&2
    echo >&2
    echo 'See also '"$0"' help.' >&2
    exit 1
  fi
  sub_command="$1"
  shift
  while [ "$#" -gt 0 ]; do
    case "${1}" in
      -o|--output)
        output_file="${2:-}"
        shift
        shift
        ;;
      -k|--private-key)
        PRIVATE_KEY="${2:-}"
        shift
        shift
        ;;
      -p|--public-key)
        PUBLIC_KEY="${2:-}"
        shift
        shift
        ;;
      -i|--in-file)
        input_file="${2:-}"
        shift
        shift
        ;;
      -f|--input-output-file)
        input_file="${2:-}"
        output_file="${2:-}"
        shift
        shift
        ;;
      *)
        echo 'Unknown option: '"$1" >&2
        echo >&2
        echo 'See also '"$0"' help.' >&2
        exit 1
    esac
  done
}

validate_arguments() {
  result=0
  if [ "$sub_command" = encrypt ]; then
    if [ ! -f "${PUBLIC_KEY:-}" ]; then
      echo 'RSA public key does not exist.' >&2
      result=1
    fi
  elif [ "$sub_command" = decrypt ]; then
    if [ ! -f "${PRIVATE_KEY:-}" ]; then
      echo 'RSA private key does not exist.' >&2
      result=1
    fi
    if ! yq '. | keys' "$input_file" &> /dev/null; then
      echo '-f FILE is expected to be YAML but it is not valid YAML.' >&2
      echo 'Invalid yaml: '"'$input_file'" >&2
      result=1
    fi
  elif [ "$sub_command" = 'rotate-key' ]; then
    if [ ! -f "${PUBLIC_KEY:-}" ]; then
      echo 'RSA public key does not exist.' >&2
      result=1
    fi
    if [ ! -f "${PRIVATE_KEY:-}" ]; then
      echo 'RSA private key does not exist.' >&2
      result=1
    fi
    if [ ! "x$input_file" = "x$output_file" ]; then
      echo 'Input-output mismatch.  Use -f FILE option.' >&2
      result=1
    fi
    if [ "x$input_file" = 'x-' ]; then
      echo 'No file selected for key rotation. Use -f FILE option.' >&2
      result=1
    fi
  fi
  if [ ! "x$input_file" = 'x-' ] && [ ! -f "$input_file" ]; then
    echo '-f FILE does not exist: '"'$input_file'" >&2
    result=1
  fi
  if [ ! "$result" = 0 ]; then
    echo >&2
    echo 'See also '"$0"' help.' >&2
  fi
  return "$result"
}

# functions
randompass() (
  set +o pipefail
  LC_ALL=C tr -dc -- "-'"'_!@#$%^&*(){}|[]\;:",./<>?0-9a-fA-F' < /dev/urandom | head -c128
)

randomsalt() (
  set +o pipefail
  local hexbytes="$(( $openssl_saltlen * 2 ))"
  LC_ALL=C tr -dc '0-9a-f' < /dev/urandom | head -c"$hexbytes"
)

stdin_aes_encrypt() {
  openssl enc \
    ${openssl_args} \
    -S "$(<"${TMP_DIR}"/salt)" \
    -pass file:"${TMP_DIR}"/passin \
    -a
}

stdin_aes_decrypt() {
  openssl enc \
    ${openssl_args} \
    -S "$(<"${TMP_DIR}"/salt)" \
    -pass file:"${TMP_DIR}"/passin \
    -a -d
}

stdin_rsa_encrypt() {
  openssl pkeyutl -encrypt -inkey "${PUBLIC_KEY}" -pubin | openssl enc -a
}

stdin_rsa_decrypt() {
  openssl enc -d -a | openssl pkeyutl -decrypt -inkey "${PRIVATE_KEY}"
}

data_or_file() {
  if [ "x${input_file:-}" = 'x-' ]; then
    cat
  else
    cat "${input_file}"
  fi
}

stdin_shasum() {
  (
    if type -P shasum &> /dev/null; then
      shasum -a 256 "$@"
    elif type -P sha256sum; then
      sha256sum "$@"
    else
      echo 'No sha256sum utility available' >&2
      exit 1
    fi
  )
}

read_yaml_for_hash() {
  yq e '.openssl_args, .salt, .passin, .data' "$1"
}

validate_hash() {
  local validate_file="${TMP_DIR}"/cipher_decrypt.yaml
  if [ -n "${1:-}" ]; then
    validate_file="$1"
  fi
  yq '.hash' "${validate_file}" \
    | stdin_rsa_decrypt > "${TMP_DIR}"/hash
  read_yaml_for_hash "${validate_file}" \
    | stdin_shasum -c "${TMP_DIR}"/hash
}

create_hash() {
  output="${1%.yaml}"_hash.yaml
cat > "$output" <<EOF
hash: |-
$(read_yaml_for_hash "$1" | stdin_shasum | stdin_rsa_encrypt | sed 's/^/  /')
EOF
}

write_to_output() {
  if [ "x${output_file:-}" = 'x-' ]; then
    cat
  else
    cat > "$output_file"
  fi
}

encrypt_file() {
  if [ -f "$output_file" ] && validate_hash "$output_file" &> /dev/null; then
    cp "$output_file" "${TMP_DIR}"/output.yaml
    yq '.salt' "${TMP_DIR}"/output.yaml | stdin_rsa_decrypt > "${TMP_DIR}/salt"
    yq '.passin' "${TMP_DIR}"/output.yaml | stdin_rsa_decrypt > "${TMP_DIR}/passin"
    yq -i 'del(.data)' "${TMP_DIR}"/output.yaml
    yq -i 'del(.hash)' "${TMP_DIR}"/output.yaml
cat > "${TMP_DIR}"/cipher_encrypt.yaml <<EOF
$(cat "${TMP_DIR}"/output.yaml)
data: |-
$(data_or_file | stdin_aes_encrypt | sed 's/^/  /')
EOF
  else
    randompass > "${TMP_DIR}/passin"
    randomsalt > "${TMP_DIR}/salt"
cat > "${TMP_DIR}"/cipher_encrypt.yaml <<EOF
openssl_args: ${openssl_args}
salt: |-
$(stdin_rsa_encrypt < "${TMP_DIR}/salt" | sed 's/^/  /')
passin: |-
$(stdin_rsa_encrypt < "${TMP_DIR}/passin" | sed 's/^/  /')
data: |-
$(data_or_file | stdin_aes_encrypt | sed 's/^/  /')
EOF
  fi

  create_hash "${TMP_DIR}"/cipher_encrypt.yaml
  yq eval-all '. as $item ireduce ({}; . *+ $item)' \
    "${TMP_DIR}"/cipher_encrypt.yaml \
    "${TMP_DIR}"/cipher_encrypt_hash.yaml \
    | write_to_output
}

decrypt_file() {
  data_or_file > "${TMP_DIR}"/cipher_decrypt.yaml
  if ! validate_hash &> /dev/null; then
    echo 'Checksum verification failed.  Refusing to decrypt.' >&2
    exit 1
  fi
  openssl_args="$(yq '.openssl_args' "${TMP_DIR}"/cipher_decrypt.yaml | head -n1)"
  yq '.salt' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_rsa_decrypt > "${TMP_DIR}/salt"
  yq '.passin' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_rsa_decrypt > "${TMP_DIR}/passin"
  yq '.data' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_aes_decrypt | write_to_output
}

rotate_key() {
  data_or_file > "${TMP_DIR}"/cipher_decrypt.yaml
  if ! validate_hash &> /dev/null; then
    echo 'Checksum verification failed.  Refusing to decrypt.' >&2
    exit 1
  fi
  openssl_args="$(yq '.openssl_args' "${TMP_DIR}"/cipher_decrypt.yaml | head -n1)"
  yq '.salt' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_rsa_decrypt > "${TMP_DIR}/salt"
  yq '.passin' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_rsa_decrypt > "${TMP_DIR}/passin"
  awk '$0 ~ /^data:/ { out="1"; print $0; next }; out == "1" && $0 ~ /^[^ ]/ { exit }; out == "1" { print $0 }' \
    < "${TMP_DIR}"/cipher_decrypt.yaml \
    > "${TMP_DIR}"/data.yaml
cat > "${TMP_DIR}"/cipher_encrypt.yaml <<EOF
openssl_args: ${openssl_args}
salt: |-
$(stdin_rsa_encrypt < "${TMP_DIR}/salt" | sed 's/^/  /')
passin: |-
$(stdin_rsa_encrypt < "${TMP_DIR}/passin" | sed 's/^/  /')
$(cat "${TMP_DIR}"/data.yaml)
EOF
  create_hash "${TMP_DIR}"/cipher_encrypt.yaml
  yq eval-all '. as $item ireduce ({}; . *+ $item)' \
    "${TMP_DIR}"/cipher_encrypt.yaml \
    "${TMP_DIR}"/cipher_encrypt_hash.yaml \
    | write_to_output
}

#
# MAIN
#
process_arguments "$@"
validate_arguments

if ! echo "$openssl_args" | grep '^[-a-z0-9 ]\+$' > /dev/null; then
  echo 'openssl_args contains invalid characters.' >&2
  exit 1
fi

if [ "${sub_command}" = encrypt ]; then
  encrypt_file
elif [ "${sub_command}" = decrypt ]; then
  decrypt_file
else
  rotate_key
fi
