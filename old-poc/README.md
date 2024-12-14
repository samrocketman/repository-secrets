# Old proof of concept example

* [repository-secrets cli utility](#repository-secrets-cli-utility) (a user
  friendly utility)
  * [Command examples](#command-examples)
  * [Config file examples](#config-file-examples)

# repository-secrets cli utility

[`repository-secrets.rb`](repository-secrets.rb) was meant for both ends of this
equation.  It's meant to be used by developers to encrypt their secrets and by
the build system to decrypt the secrets.  Here's the command line documentation.

Features include:

* Friendly interface for generating fingerprinted key pairs.
* Friendly interface for developers to encrypt secrets.
* Key rotation by fingerprinting keys and encrypted secrets (see `--fingerprint`
  option).
* Loading a config file to override options to keep the options of the utility
  brief for both developers encrypting secrets and a build pipeline decrypting
  secrets.


```
Usage: repository-secrets.rb [options] [arguments]

This is a full featured command line utility for performing string interpolation
on encrypted secrets in plain text files in a repository.

There are two modes: Encrypt and Decrypt.  Encrypt mode is on by default.

Encryption options:
       Each argument that is passed without being associated with options, will
       be interpreted as an argument.  Each argument will be encrypted as a
       secure property.  Secure properties can be copied and pasted into a
       source file as a secret.

       If no arguments are passed in then stdin will be read for strings to be
       encrypted.

        --public-key FILE
                                     Path to a public key to use for encryption.
                                     This gets overridden if --fingerprint
                                     option is used.

Decryption options:
       Using any of these options will turn on Decrypt mode.

        --decrypt
                                     Force decrypt mode to be on.  Force mode to
                                     be on or off in the repository-secrets.yml.
        --private-key FILE
                                     Path to a private key to use for
                                     decryption.  This gets overridden if
                                      --fingerprint option is used.
    -s, --secrets-file FILE          Path to a secrets FILE; the contents
                                     contain one file per line.  It will do
                                     string interpolation on each file in the
                                     list replacing secrets with the decrypted
                                     text.  File paths are either full path or
                                     relative to the current working directory.
    -f, --file FILE                  Use string interpolation on the specified
                                     FILE to decrypt secrets.
    -i, --inplace [EXTENSION]        Perform string interpolation on files with
                                     in-place editing.  Otherwise print
                                     decrypted file to stdout.
                                       (make backup if EXTENSION supplied)

Common options:
       These options are common to both Encrypt and Decrypt modes.

    -c, --config FILE                Config file to override options.  If config
                                     file doesn't exist then will check current
                                     working directory for
                                     repository-secrets.yml.  The format is YAML
                                     and any long option with hyphens replaced
                                     with underscores can be used.  For example,
                                      --secrets-directory would be
                                     secrets_directory in the config file.
                                     Default: /etc/repository-secrets.yml
    -p, --fingerprint [FINGERPRINT]  Turn on fingerprint mode.  Optionally
                                     specify which fingerprinted key to use for
                                     encryption.  Decryption would automatically
                                     use the fingerprint attached to the secret.
    -d, --secrets-directory DIR      The directory to look for fingerprinted
                                     keys.  Generated key pairs will be placed
                                     here.
                                     Default: /etc/repository-secrets/
    -g, --generate-key-pair          Generate a fingerprinted key key pair in
                                     secrets_directory.
    -b, --bits BITS                  The number of bits that will be used in
                                     the generated key pair.  Default: 2048
        --secret-text-tag TAG        Change the unique text which defines the
                                     tag to be interpolated in files.
                                     Default: supersecret
    -v, --[no-]verbose               Run more verbosely.
                                       (more verbosity with -vv or -vvv)
                                       WARNING: -vvv displays plain text secrets
    -h, --help                       Show this message
        --version                    Show version
```

## Command examples

Enter interactive mode to generate secrets (from a user perspective).

    ./repository-secrets.rb

Decrypt secrets and output to `stdout`.

    ./repository-secrets.rb -f examples/myconfig.json

Decrypt secrets in a list of files and do inline replacement.

    ./repository-secrets.rb -s ./.supersecrets -i

Same example but creating a backup of the files being decrypted.

    ./repository-secrets.rb -s ./.supersecrets -i.bak

## Config file examples

Default options for the command line utility can be set in
`/etc/repository-secrets.yml`.  This path can be overridden with the `--config`
option.

YAML file with increased verbosity, forcing decrypt mode off, and specifying a
fingerprinted key to use.  *Hint: Increment `--verbose` with each `-v` option.*

```yaml
verbose: 2
decrypt: false
fingerprint: "0ae32bc1"
```

YAML file force decrypt mode on, enable fingerprinted decryption, and do inplace
editing.

```yaml
decrypt: true
fingerprint: true
inplace: true
```

Same as previous example but create a backup from the inplace editing and
customize the `--secret-text-tag`.

```yaml
decrypt: true
fingerprint: true
secret_text_tag: "encrypted"
inplace: ".bak"
```

