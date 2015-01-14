# Securing repository secrets

This is a simple proof of concept around how to secure repository secrets.

The idea is you encrypt secrets with a public key that can be widely
distributed.  Then on a CI system or within a delivery pipeline you decrypt
those secrets with a private key.

* [Drawbacks and alternative for files](#drawbacks-and-alternative-for-files)
* [A possible solution](#a-possible-solution)
  * [Asynchronous encryption](#asynchronous-encryption) (for strings)
  * [Asynchronous encrypting a synchronous session
    key](#asynchronous-encrypting-a-synchronous-session-key) (for files)
* [Supporting inline secrets](#supporting-inline-secrets) (for strings in files)

# Drawbacks and alternative for files

This uses asynchronous encryption (e.g. RSA key pair) which is best used on
small strings.  However, for large files this method is very inefficient.  It is
more efficient to use synchronous encryption (e.g. AES256) on large files.  One
way to go about it is to use a session key for the synchronous encryption and
then encrypt the session key using asynchronous encryption.

# A possible solution

For encrypting strings using asynchronous encryption, I am selecting RSA public
key encryption and using `openssl` tools.

For large files, rather than re-invent the wheel GPG does a great job at
encrypting session keys with asynchronous encryption and then
encrypting/decrypting files with synchronous encryption.  Also, by using GPG
there is a certain flexibility of being able to encrypt files for the CI system
or delivery pipeline but still allow a developer to easily decrypt the files as
well.  This is because files can be encrypted with multiple GPG keys able to
decrypt the same file.

## Asynchronous encryption

### Setting up key pair

Generate an RSA private and public key pair.

    openssl genrsa -out /tmp/id_rsa 1024
    openssl rsa -in /tmp/id_rsa -pubout -outform pem -out /tmp/id_rsa.pub

### Encrypting

Encrypt a plaintext string to be stored in a repository.  This encrypts using
the public key.

    echo -n 'plaintext' | openssl rsautl -encrypt -inkey secrets/id_rsa.pub -pubin | base64 -w0

### Decrypting

Decrypt a ciphertext string to be used by the CI system or delivery pipeline.
This decrypts using the private key.

    echo 'ciphertext' | base64 -d | openssl rsautl -decrypt -inkey secrets/id_rsa

## Asynchronous encrypting a synchronous session key

### Setting up GPG

Generate a GPG key for your build system.  There is helpful documentation on
completing the wizard prompts over at the [Fedora project wiki][fedora-wiki].

    gpg --gen-key

List your newly generate key so that you may get the Key ID.

    gpg --list-keys

Remove the password for the newly generated key (use the `passwd` command in the
`gpg>` prompt).  It is necessary to remove the password of the GPG key because
it is intended for automation.  There would be no human there to type in a
password during automated workflows unless you use something like the `expect`
command.

    gpg --edit-key <KEY ID>
    gpg> passwd
    gpg> save

When changing the password leave the password field blank.  You will be asked to
confirm if you *really* want to take away the password (you do).  `gpg> save`
will save your changes and exit GPG.

Create a backup of your key which is ASCII armored.  In the following replace
`<KEY ID>` with your GPG key id.

    gpg --export -a <KEY ID> > gpg_example_pub-sec.asc
    gpg --export-secret-keys -a <KEY ID> >> gpg_example_pub-sec.asc

From now on any GPG examples will be using the `secrets/gpg_example_pub-sec.asc`
key which has a key id of `DAB5AED9`.

### Encrypting

Before running any examples for GPG you might want to import the example GPG
key.

    gpg --import secrets/gpg_example_pub-sec.asc

Encrypt a single file to a single recipient.  In this case, use the example GPG
key to encrypt this README.  If you get a warning when encrypting its because of
the trust level of the recipient; ignore it because this is just an example.

    gpg  -e --recipient DAB5AED9 -- "README.md"

To add multiple recipients (like developers in addition to the CI system).

    gpg  -e --recipient DAB5AED9 --recipient <ANOTHER KEY ID> -- "README.md"

### Decrypting

Decrypt a file and have its contents output to `stdout`.

    gpg -d -- README.md.gpg | less

Decrypt a file and have it remove the extension and automatically output to the
same file name.

    echo "README.md.gpg" | gpg --multifile --decrypt --

Now that you're probably done with these examples go ahead and delete the
example key from your key chain.

    gpg --delete-secret-keys DAB5AED9
    gpg --delete-key DAB5AED9

# Supporting inline secrets

Inline secrets are just as important as encrypting strings or files.  Inline
secrets are what make encrypting strings useful in a configuration that might
need to only be partially secure.  An example of an inline secret would be
embedding a unique string in a config file that can be substituted with the
plain text equivalent of the secret string.  Another term for that is string
interpolation.  For example, see [`myconfig.json`](examples/myconfig.json) which
uses an inline secret, `${supersecret:ciphertext}`.  The inline secret can use
string interpolation with something like a regular expression from `sed` (e.g.
`${supersecret:[^}]*}`).

When the string interpolation is done on `myconfig.json` it would have the
plaintext contents of:

```json
{
  "somesetting": "another setting",
  "some_secure_setting": "super secret setting"
}
```

[fedora-wiki]: https://fedoraproject.org/wiki/Creating_GPG_Keys#Creating_GPG_Keys_Using_the_Command_Line
