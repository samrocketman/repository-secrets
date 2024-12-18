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
pbkdf2_password_length="${pbkdf2_password_length:-389}"
pbkdf2_salt_length="${pbkdf2_salt_length:-8}"
openssl_aes_args="${openssl_aes_args:--aes-256-cbc -pbkdf2 -iter 600000}"
openssl_rsa_args="${openssl_rsa_args:--pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256}"
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
missing_util mktemp || needs_util=1
missing_util cat || needs_util=1
missing_util cp || needs_util=1
missing_util awk || needs_util=1
missing_util xxd || needs_util=1
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
skip_fields=()

#
# FUNCTIONS
#
helptext() {
cat <<EOF
SYNOPSIS
  $0 encrypt [options]
  $0 decrypt [options]
  $0 rotate-key [options]


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
    Default: '${pbkdf2_salt_length:-}'

  openssl_aes_args
    Arguments used on openssl for AES encryption or decryption.
    Default: '${openssl_aes_args:-}'

  openssl_rsa_args
    Arguments used on openssl for RSA encryption or decryption.
    Default: '${openssl_rsa_args:-}'

  PRIVATE_KEY
    Path to RSA private key file used for decryption.  Used as -keyin argument
    for openssl pkeyutl.
    Default: '${PRIVATE_KEY:-}'

  PUBLIC_KEY
    Path to RSA public key file used for encryption.  Used as -keyin argument
    for openssl pkeyutl.
    Default: '${PUBLIC_KEY:-}'

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
    echo hello | $0 encrypt -o cipher.yaml

  On a backend system, use AWS KMS to decrypt the data with the private key.

    export openssl_rsa_args='-keyform engine -engine kms -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA256'
    export PRIVATE_KEY=arn:aws:kms:...
    $0 decrypt -i cipher.yaml

OLD OPENSSL NOTICE

  Old OpenSSL versions before OpenSSL 3.2 do not have -saltlen option available.
  The environment variable defaults are intended to reflect this.

  For even older OpenSSL, you might not want to use
  RSA/ECB/OAEPWithSHA-256AndMGF1Padding and instead use RSA/ECB/PKCS1Padding.
  You can accomplish this by overriding openssl_rsa_args with an empty space.
  Note the space is required so that the veriable is non-zero length.

    export openssl_rsa_args=' '
    echo hello | $0 encrypt


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
EOF
exit 1
}

process_arguments() {
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
      -s|--skip-field)
        skip_fields+=( "$2" )
        shift
        shift
        ;;
      -h|--help|help)
        helptext
        ;;
      *)
        if [ -z "${sub_command:-}" ]; then
          sub_command="$1"
          shift
        else
          echo 'Unknown option: '"$1" >&2
          echo >&2
          echo 'See also '"$0"' help.' >&2
          exit 1
        fi
    esac
  done
  case "${sub_command:-}" in
    encrypt|decrypt|rotate-key)
      ;;
    *)
      echo 'Must use one of the following subcommands.' >&2
      echo '  - '"$0 encrypt [options]" >&2
      echo '  - '"$0 decrypt [options]" >&2
      echo '  - '"$0 rotate-key [options]" >&2
      echo >&2
      echo 'See also '"$0"' help.' >&2
      exit 1
      ;;
  esac
}

validate_arguments() {
  result=0
  if [ "$sub_command" = encrypt ]; then
    if [ ! -f "${PUBLIC_KEY:-}" ] && ! grep -F :kms: <<< "${PUBLIC_KEY:-}" > /dev/null; then
      echo 'Warning: RSA public key does not exist.' >&2
    fi
  elif [ "$sub_command" = decrypt ]; then
    if [ ! -f "${PRIVATE_KEY:-}" ] && ! grep -F :kms: <<< "${PRIVATE_KEY:-}" > /dev/null; then
      echo 'Warning: RSA private key does not exist.' >&2
    fi
  elif [ "$sub_command" = 'rotate-key' ]; then
    if [ ! -f "${PUBLIC_KEY:-}" ] && ! grep -F :kms: <<< "${PUBLIC_KEY:-}" > /dev/null; then
      echo 'Warning: RSA public key does not exist.' >&2
    fi
    if [ ! -f "${PRIVATE_KEY:-}" ] && ! grep -F :kms: <<< "${PRIVATE_KEY:-}" > /dev/null; then
      echo 'Warning: RSA private key does not exist.' >&2
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
  [ "${pbkdf2_password_length:-0}" -gt 124 ] || {
    echo 'ERROR: pbkdf2_password_length must be 125 or higher.' >&2
    exit 1
  }
  # 92 possible characters
  # 30 special characters, 0-9, a-z, A-Z
  LC_ALL=C tr -dc -- "-'"'~=+_!@#$%^&*(){}[]\;:",./<>?0-9a-fA-F' < /dev/urandom | head -c"${pbkdf2_password_length}"
)

randomsalt() (
  set +o pipefail
  local hexbits="$(( $pbkdf2_salt_length * 2 ))"
  LC_ALL=C tr -dc '0-9a-f' < /dev/urandom | head -c"$hexbits"
)

stdin_aes_encrypt() {
  local result
  openssl enc \
    ${openssl_aes_args} \
    -S "$(<"${TMP_DIR}"/salt)" \
    -pass file:"${TMP_DIR}"/passin \
    -a || {
result=$?
cat >&2 <<'EOF'
AES encryption has failed.

This is typical for versions of OpenSSL less than 3.2.  You may be able to fix
this with the following environment variables.

    pbkdf2_salt_length=8
    openssl_aes_args='-aes-256-cbc -pbkdf2 -iter 600000'
    pbkdf2_password_length=389
    export pbkdf2_salt_length openssl_aes_args pbkdf2_password_length

EOF
  echo "See $0 help" >&2
  return "$result"
}
}

stdin_aes_decrypt() {
  openssl enc \
    ${openssl_aes_args} \
    -S "$(<"${TMP_DIR}"/salt)" \
    -pass file:"${TMP_DIR}"/passin \
    -a -d
}

get_rsa_key_size() {
  if [ -f "${PUBLIC_KEY:-}" ]; then
    openssl rsa -pubin -in "${PUBLIC_KEY}" -text -noout | \
      grep -o '[0-9]\+ bit' | \
      sed 's/ bit$//'
  fi
}

stdin_rsa_encrypt() {
  local result
  local rsa_key_size
  openssl pkeyutl ${openssl_rsa_args} -encrypt -inkey "${PUBLIC_KEY}" -pubin | \
    openssl enc -base64 || {
      result=$?
cat >&2 <<EOF
RSA encryption failed.  Possibly because of incorrect environment settings.

The equation for maximum data RSA keys can encrypt is:

    <RSA key size in bits>/8-66 = <data limit in bytes>

Current salt length: ${pbkdf2_salt_length}
Current pbkdf2 password length: ${pbkdf2_password_length}

Attempted to encrypt: $((49 + pbkdf2_salt_length + pbkdf2_password_length)) bytes

EOF
      rsa_key_size="$(get_rsa_key_size)"
      if [ -n "${rsa_key_size:-}" ]; then
cat >&2 <<EOF
Detected RSA ${rsa_key_size} key.  Update your environment variables:

    export pbkdf2_password_length=$(( rsa_key_size/8 - (115 + pbkdf2_salt_length) ))
EOF
      else
cat >&2 <<EOF
Could not detect RSA public key.  You should manually calculate
pbkdf2_password_length for the best security.  The lowest recommended value is
the following environment variable.

    export pbkdf2_password_length=125
EOF
      fi
      echo >&2
      echo "See $0 help" >&2
      return "$result"
    }
}

stdin_rsa_decrypt() {
  openssl enc -base64 -d | openssl pkeyutl ${openssl_rsa_args} -decrypt -inkey "${PRIVATE_KEY}"
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
    elif type -P sha256sum &> /dev/null; then
      sha256sum "$@"
    else
      echo 'No sha256sum utility available' >&2
      exit 1
    fi
  )
}

read_yaml_for_hash() {
  cat <<EOF
$(<"${TMP_DIR}/passin")
$(<"${TMP_DIR}/salt")
$(yq e '.openssl_aes_args, .openssl_rsa_args, .pbkdf2_salt_length, .pbkdf2_password_length, .data' "$1")
EOF
}

b64encode_hashsalt() {
  head -c64 "${TMP_DIR}"/hash > "${TMP_DIR}"/hashsalt
  cat "${TMP_DIR}"/salt >> "${TMP_DIR}"/hashsalt
  xxd -r -p < "${TMP_DIR}"/hashsalt | openssl enc -base64 -A
}

b64decode_hashsalt() {
  openssl enc -base64 -d -A | xxd -p | tr -d '\n' > "${TMP_DIR}"/hashsalt
  head -c64 "${TMP_DIR}"/hashsalt | sed 's/$/  -/' > "${TMP_DIR}"/hash
  dd if="${TMP_DIR}"/hashsalt bs=64 skip=1 status=none > "${TMP_DIR}"/salt
}

validate_hash() {
  yq '.hash' "$1" \
    | stdin_rsa_decrypt > "${TMP_DIR}"/scratch
  awk -F'|' '{print $1}' < "${TMP_DIR}"/scratch | tr -d '\n' > "${TMP_DIR}"/passin
  awk -F'|' '{print $2}' < "${TMP_DIR}"/scratch | tr -d '\n' | b64decode_hashsalt
  discovered_password_length="$(wc -c < "${TMP_DIR}"/passin)"

  if [ "$discovered_password_length" -lt 125 ]; then
    echo 'ERROR: the pbkdf2_password_length is less than 125 characters.' >&2
    echo 'Refusing to decrypt.' >&2
    exit 1
  fi
  read_yaml_for_hash "$1" | stdin_shasum -c "${TMP_DIR}"/hash
}

create_hash() {
  output="${1%.yaml}"_hash.yaml
  read_yaml_for_hash "$1" | stdin_shasum > "${TMP_DIR}/hash"
  echo 'hash: |-' > "$output"
(
cat <<EOF
$(<"${TMP_DIR}/passin")|$(b64encode_hashsalt)
EOF
) | tr -d '\n' | stdin_rsa_encrypt | sed 's/^/  /' >> "$output"
}

write_to_output() {
  if [ "x${output_file:-}" = 'x-' ]; then
    cat
  else
    cat > "$output_file"
  fi
}

create_cipher_encrypt_yaml() {
cat > "${TMP_DIR}"/cipher_encrypt.yaml <<EOF
openssl_aes_args: ${openssl_aes_args}
openssl_rsa_args: ${openssl_rsa_args}
pbkdf2_password_length: ${pbkdf2_password_length}
pbkdf2_salt_length: ${pbkdf2_salt_length}
data: |-
$(cat)
EOF
}

combine_yaml() {
  yq eval-all '. as $item ireduce ({}; . *+ $item)' "${@}"
}

encrypt_file() {
  randompass > "${TMP_DIR}/passin"
  randomsalt > "${TMP_DIR}/salt"
  data_or_file | stdin_aes_encrypt | sed 's/^/  /' | create_cipher_encrypt_yaml

  create_hash "${TMP_DIR}"/cipher_encrypt.yaml
  combine_yaml \
    "${TMP_DIR}"/cipher_encrypt.yaml \
    "${TMP_DIR}"/cipher_encrypt_hash.yaml \
    | write_to_output
}

should_not_skip() {
  local field="$1"
  if [ "${#skip_fields[@]}" = 0 ]; then
    return 0
  fi
  for x in "${skip_fields[@]}"; do
    if [ "${field}" = "${x}" ]; then
      return 1
    fi
  done
  return 0
}

decrypt_file() {
  data_or_file > "${TMP_DIR}"/cipher_decrypt.yaml
  if ! yq '. | keys' "${TMP_DIR}"/cipher_decrypt.yaml &> /dev/null; then
    echo '-f FILE is expected to be YAML but it is not valid YAML.' >&2
    echo 'Invalid yaml: '"'$input_file'" >&2
    exit 1
  fi
  if should_not_skip openssl_aes_args; then
    openssl_aes_args="$(yq '.openssl_aes_args' "${TMP_DIR}"/cipher_decrypt.yaml | head -n1)"
  fi
  if should_not_skip openssl_rsa_args; then
    openssl_rsa_args="$(yq '.openssl_rsa_args' "${TMP_DIR}"/cipher_decrypt.yaml | head -n1)"
  fi
  pbkdf2_password_length="$(yq '.pbkdf2_password_length' "${TMP_DIR}"/cipher_decrypt.yaml | head -n1)"
  if ! validate_hash "${TMP_DIR}"/cipher_decrypt.yaml > /dev/null; then
   echo 'Checksum verification failed.  Refusing to decrypt.' >&2
    exit 1
  fi
  yq '.data' "${TMP_DIR}"/cipher_decrypt.yaml | stdin_aes_decrypt | write_to_output
}

rotate_key() {
  data_or_file > "${TMP_DIR}"/cipher_decrypt.yaml
  if ! validate_hash "${TMP_DIR}"/cipher_decrypt.yaml > /dev/null; then
    echo 'Checksum verification failed.  Refusing to decrypt.' >&2
    exit 1
  fi
  openssl_aes_args="$(yq '.openssl_aes_args' "${TMP_DIR}"/cipher_decrypt.yaml)"
  openssl_rsa_args="$(yq '.openssl_rsa_args' "${TMP_DIR}"/cipher_decrypt.yaml)"
  awk '$0 ~ /^data:/ { out="1"; print $0; next }; out == "1" && $0 ~ /^[^ ]/ { exit }; out == "1" { print $0 }' \
    < "${TMP_DIR}"/cipher_decrypt.yaml \
    > "${TMP_DIR}"/data.yaml

  create_cipher_encrypt_yaml < "${TMP_DIR}"/data.yaml

  create_hash "${TMP_DIR}"/cipher_encrypt.yaml
  combine_yaml \
    "${TMP_DIR}"/cipher_encrypt.yaml \
    "${TMP_DIR}"/cipher_encrypt_hash.yaml \
    | write_to_output
}

#
# MAIN
#
process_arguments "$@"
validate_arguments

if [ "${sub_command}" = encrypt ]; then
  encrypt_file
elif [ "${sub_command}" = decrypt ]; then
  decrypt_file
else
  rotate_key
fi
