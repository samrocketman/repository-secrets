#!/usr/bin/env ruby
#Created by Sam Gleske
#https://github.com/samrocketman/repository-secrets
#Wed Jan 14 22:04:55 EST 2015
#Ubuntu 14.04.1 LTS
#Linux 3.13.0-44-generic x86_64
#ruby 1.9.3p484 (2013-11-22 revision 43786) [x86_64-linux]

#DESCRIPTION
#  This is a full featured command line utility for performing string
#  interpolation on encrypted secrets in plain text files in a
#  repository.

#required for encryption/decryption
require 'openssl'
require 'base64'
#required for option parsing
require 'optparse'
require 'ostruct'
#pretty printing of ruby objects
require 'pp'

#The version of this program
Version = [0, 1, 0]

################################################################################
# Classes
################################################################################

class OptparseExample

  #
  # Return a structure describing the options.
  #
  # Option separator documentation is 80 chars wide.
  # Option description documentation is 43 chars wide.
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    options = OpenStruct.new
    options.private_key_file = "secrets/id_rsa"
    options.public_key_file = "secrets/id_rsa.pub"
    options.secret_text_tag = "supersecret"
    options.verbose = 0
    options.decrypt = false
    options.files = []
    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: repository-secrets.rb [options] [arguments]"

      opts.separator ""
      opts.separator "This is a full featured command line utility for performing string interpolation"
      opts.separator "on encrypted secrets in plain text files in a repository."
      opts.separator ""
      opts.separator "There are two modes: Encrypt and Decrypt.  Encrypt mode is on by default."

      #Encrypt mode options
      opts.separator ""
      opts.separator "Encryption options:"
      opts.separator "       Each argument that is passed without being associated with options, will"
      opts.separator "       be interpreted as an argument.  Each argument will be encrypted as a"
      opts.separator "       secure property.  Secure properties can be copied and pasted into a"
      opts.separator "       source file as a secret."
      opts.separator ""
      opts.separator "       If no arguments are passed in then stdin will be read for strings to be"
      opts.separator "       encrypted."
      opts.separator ""

      opts.on("--public-key FILE",
              "Path to a public key to use for encryption.") do |file|
        options.public_key_file = file
      end

      #Decrypt mode options
      opts.separator ""
      opts.separator "Decryption options:"
      opts.separator "       Using any of these options will turn on Decrypt mode."
      opts.separator ""

      opts.on_tail("-d", "--decrypt",
                   "Force Decrypt mode to be on.  Not really",
                   "necessary.") do
        options.decrypt = true
      end

      opts.on("--private-key FILE",
              "Path to a private key to use for",
              "decryption.") do |file|
        options.private_key_file = file
        options.decrypt = true
      end

      # Mandatory argument.
      opts.on("-s", "--secrets-file FILE",
              "Path to a secrets FILE; the contents",
              "contain one file per line.  It will do",
              "string interpolation on each file in the",
              "list replacing secrets with the decrypted",
              "text.  File paths are either full path or",
              "relative to the current working directory.") do |file|
        options.secrets_file = file
        options.decrypt = true
      end

      opts.on("-f", "--file FILE",
              "Use string interpolation on the specified",
              "FILE to decrypt secrets.") do |file|
        options.files << file
        options.decrypt = true
      end

      # Optional argument; multi-line description.
      opts.on("-i", "--inplace [EXTENSION]",
              "Perform string interpolation on files with",
              "in-place editing.  Otherwise print",
              "decrypted file to stdout.",
              "  (make backup if EXTENSION supplied)") do |ext|
        options.inplace = true
        options.extension = ext
        if options.extension
          options.extension.sub!(/\A\.?(?=.)/, ".")  # Ensure extension begins with dot.
        end
        options.decrypt = true
      end

      opts.separator ""
      opts.separator "Common options:"
      opts.separator "       These options are common to both Encrypt and Decrypt modes."
      opts.separator ""

      opts.on("--secret-text-tag TAG",
              "Change the unique text which defines the",
              "tag to be interpolated in files.  By",
              "default: supersecret") do |tag|
        options.secret_text_tag = tag
      end

      opts.on("-v", "--[no-]verbose",
              "Run more verbosely.",
              "  (more verbosity with -vv or -vvv)",
              "  WARNING: -vvv displays plain text secrets") do |v|
        #increment verbosity by 1 for each -v used
        if v
          options.verbose += 1
        end
      end

      # No argument, shows at tail.  This will print an options summary.
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      # Another typical switch to print the version.
      opts.on_tail("--version", "Show version") do
        puts ::Version.join('.')
        exit
      end
    end

    opt_parser.parse!(args)
    options
  end  # parse()

end  # class OptparseExample

################################################################################
# Function definitions
################################################################################

#print to stderr with a verbosity level
def verbose(level, text)
  if $options.verbose >= level
    $stderr.puts "v#{level}> #{text}".gsub(/^v0> /, "")
  end
end # verbose()

#First decodes base64 cipher text input and then decrypts; returns plain text
def decrypt(ciphertext)
  verbose 3, "decrypt(\"#{ciphertext}\")"
  private_key=OpenSSL::PKey::RSA.new(File.read($options.private_key_file))
  plaintext=private_key.private_decrypt(Base64.strict_decode64(ciphertext))
  verbose 3, "  returns \"#{plaintext}\""
  return plaintext
end # decrypt()

#First encrypts plain text input and then encodes in base64; returns cipher text
def encrypt(plaintext)
  verbose 3, "encrypt(\"#{plaintext}\")"
  public_key = OpenSSL::PKey::RSA.new(File.read($options.public_key_file))
  ciphertext = Base64.strict_encode64(public_key.public_encrypt(plaintext))
  verbose 3, "  returns \"#{ciphertext}\""
  return ciphertext
end # encrypt()

################################################################################
# Runtime
################################################################################

#make the options a global variable accessible to all functions everywhere
#this is lazy101 (how to be terrible)
$options = OptparseExample.parse(ARGV)

#print out the structures
verbose 2, "Arguments data structures (parsed and passed)"
verbose 2, PP.pp($options, "")
verbose 2, PP.pp(ARGV, "")

if (ARGV.length > 0) || $options.decrypt
  if $options.decrypt
    verbose 0, "Performing decryption with string interpolation on files."
    if $options.inplace
      verbose 0, "Inplace editing enabled for all files."
    end
    #read the secrets file
    if $options.secrets_file
      verbose 0, "Reading a secrets file for a list of files."
      f = File.open($options.secrets_file, "r")
      f.each_line do |line|
        #skip blank lines
        next if line.strip.length == 0
        #skip lines that start with a hash
        next if /^\s*#.*/.match(line.strip)
        $options.files << line.strip
      end
      f.close
    end
    $options.files.each do |file|
      verbose 0, "Performing string interpolation on: #{file}"
      filecontents = File.read(file)
      secrets = filecontents.scan(/\${#{Regexp.escape($options.secret_text_tag)}:[^}]*}/)
      secrets.each do |secret|
        #extract just the cipher text from the secret
        ciphertext=secret.gsub(/\${#{Regexp.escape($options.secret_text_tag)}:([^}]*)}/,'\1')
        #inline string replace the secret with the plain text
        filecontents.gsub!(secret,decrypt(ciphertext))
      end
      if $options.inplace
        if $options.extension
        else
          f = File.open(file,"w")
          f.write(filecontents)
          f.close()
        end
      else
        puts filecontents
      end
    end
  else
    ARGV.each do |plaintext|
      puts "${#{$options.secret_text_tag}:#{encrypt(plaintext.strip)}}"
    end
  end
else
  verbose 0, "Reading from stdin.  Use CTRL+D to finish."
  ARGF.each do |plaintext|
    if $options.decrypt
      verbose 0, "ERR: You may only decrypt in normal mode not using stdin."
      exit 1
    end
    next if plaintext.strip.length == 0
    puts "${#{$options.secret_text_tag}:#{encrypt(plaintext.strip)}}"
  end
end

#output info message to stderr
if not $options.decrypt
  verbose 0, ""
  verbose 0, "Replace the plain text string in your config file with the secure one."
  verbose 0, "NOTE: Don't forget to regenerate passwords or API keys if you've already"
  verbose 0, "committed them to the repository and published it as plain text."
  verbose 0, ""
end

#CHANGELOG
#0.1.0 - initial release
