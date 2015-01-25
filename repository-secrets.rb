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
require 'base64'
require 'digest/sha1'
require 'openssl'
#required for option parsing
require 'optparse'
#pretty printing of ruby objects
require 'pp'
#for file copying
require 'fileutils'
#for processing repository-secrets.yml
require 'yaml'

#The version of this program
Version = "repository-secrets.rb v0.2.0"

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
    options = Hash.new
    options["bits"] = 2048
    options["config"] = "/etc/repository-secrets.yml"
    options["decrypt"] = false
    options["files"] = []
    options["private_key"] = "secrets/id_rsa"
    options["public_key"] = "secrets/id_rsa.pub"
    options["secrets_directory"] = "/etc/repository-secrets/"
    options["secret_text_tag"] = "supersecret"
    options["verbose"] = 0
    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: repository-secrets.rb [options] [arguments]"

      opts.separator ""
      opts.separator "This is a full featured command line utility for performing string interpolation"
      opts.separator "on encrypted secrets in plain text files in a repository."
      opts.separator ""
      opts.separator "There are two modes: Encrypt and Decrypt.  Encrypt mode is on by default."

      #
      #ENCRYPT MODE OPTIONS
      #
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

      opts.on("","--public-key FILE",
              "Path to a public key to use for encryption.",
              "This gets overridden if --fingerprint",
              "option is used.") do |file|
        options["public_key"] = file
      end

      #
      #DECRYPT MODE OPTIONS
      #
      opts.separator ""
      opts.separator "Decryption options:"
      opts.separator "       Using any of these options will turn on Decrypt mode."
      opts.separator ""

      opts.on("", "--decrypt",
              "Force decrypt mode to be on.  Force mode to",
              "be on or off in the repository-secrets.yml.") do
        options["decrypt"] = true
      end

      opts.on("","--private-key FILE",
              "Path to a private key to use for",
              "decryption.  This gets overridden if",
              " --fingerprint option is used.") do |file|
        options["private_key"] = file
        options["decrypt"] = true
      end

      # Mandatory argument.
      opts.on("-s", "--secrets-file FILE",
              "Path to a secrets FILE; the contents",
              "contain one file per line.  It will do",
              "string interpolation on each file in the",
              "list replacing secrets with the decrypted",
              "text.  File paths are either full path or",
              "relative to the current working directory.") do |file|
        options["secrets_file"] = file
        options["decrypt"] = true
      end

      opts.on("-f", "--file FILE",
              "Use string interpolation on the specified",
              "FILE to decrypt secrets.") do |file|
        options["files"] << file
        options["decrypt"] = true
      end

      # Optional argument; multi-line description.
      opts.on("-i", "--inplace [EXTENSION]",
              "Perform string interpolation on files with",
              "in-place editing.  Otherwise print",
              "decrypted file to stdout.",
              "  (make backup if EXTENSION supplied)") do |ext|
        options["inplace"] = true
        options["extension"] = ext
        if options["extension"]
          options["extension"].sub!(/\A\.?(?=.)/, ".")  # Ensure extension begins with dot.
        end
        options["decrypt"] = true
      end

      #
      #OPTIONS COMMON TO BOTH ENCRYPT AND DECRYPT MODES
      #
      opts.separator ""
      opts.separator "Common options:"
      opts.separator "       These options are common to both Encrypt and Decrypt modes."
      opts.separator ""

      opts.on("-c", "--config FILE",
              "Config file to override options.  If config",
              "file doesn't exist then will check current",
              "working directory for",
              "repository-secrets.yml.  The format is YAML",
              "and any long option with hyphens replaced",
              "with underscores can be used.  For example,",
              " --secrets-directory would be",
              "secrets_directory in the config file.",
              "Default: /etc/repository-secrets.yml") do |file|
        options["config"] = file
      end

      # Optional argument; multi-line description.
      opts.on("-p", "--fingerprint [FINGERPRINT]",
              "Turn on fingerprint mode.  Optionally",
              "specify which fingerprinted key to use for",
              "encryption.  Decryption would automatically",
              "use the fingerprint attached to the secret.") do |fingerprint|
        options["fingerprint"] = fingerprint
        if not options["fingerprint"]
          options["fingerprint"] = ""
        end
      end

      opts.on("-d", "--secrets-directory DIR",
              "The directory to look for fingerprinted",
              "keys.  Generated key pairs will be placed",
              "here.",
              "Default: /etc/repository-secrets/") do |dir|
        #force trailing slash
        if (dir.length > 0) and not (dir[-1] == '/')
          dir += '/'
        end
        options["secrets_directory"] = dir
      end

      opts.on("-g", "--generate-key-pair",
              "Generate a fingerprinted key key pair in",
              "secrets_directory.") do
        options["generate_key_pair"] = true
      end

      opts.on("-b", "--bits BITS",
              "The number of bits that will be used in",
              "the generated key pair.  Default: 2048") do |bits|
        options["bits"] = bits.to_i
        if options["bits"] < 1024
          $stderr.puts "WARNING: --bits less than 1024 is insecure.  Setting to 1024."
          options["bits"] = 1024
        end
      end

      opts.on("--secret-text-tag TAG",
              "Change the unique text which defines the",
              "tag to be interpolated in files.",
              "Default: supersecret") do |tag|
        options["secret_text_tag"] = tag
      end

      opts.on("-v", "--[no-]verbose",
              "Run more verbosely.",
              "  (more verbosity with -vv or -vvv)",
              "  WARNING: -vvv displays plain text secrets") do |v|
        #increment verbosity by 1 for each -v used
        if v
          options["verbose"] += 1
        end
      end

      # No argument, shows at tail.  This will print an options summary.
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      # Another typical switch to print the version.
      opts.on_tail("--version", "Show version") do
        puts ::Version
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
  if $options["verbose"] >= level
    $stderr.puts "v#{level}> #{text}".gsub(/^v0> /, "")
  end
end # verbose()

#First decodes base64 cipher text input and then decrypts; returns plain text
def decrypt(keypath, ciphertext)
  verbose 3, "decrypt(\"#{keypath}\", \"#{ciphertext}\")"
  private_key=OpenSSL::PKey::RSA.new(File.read(keypath))
  plaintext=private_key.private_decrypt(Base64.strict_decode64(ciphertext))
  verbose 3, "  returns \"#{plaintext}\""
  return plaintext
end # decrypt()

#First encrypts plain text input and then encodes in base64; returns cipher text
def encrypt(keypath, plaintext)
  verbose 3, "encrypt(\"#{keypath}\", \"#{plaintext}\")"
  public_key = OpenSSL::PKey::RSA.new(File.read(keypath))
  ciphertext = Base64.strict_encode64(public_key.public_encrypt(plaintext))
  verbose 3, "  returns \"#{ciphertext}\""
  return ciphertext
end # encrypt()

#Fingerprint data by taking the first 8 characters of the sha1 hash.
#In the context of this program a public key is being used as data for the fingerprint.
def fingerprint(public_key)
  verbose 3, "fingerprint(\"#{public_key}\")"
  fingerprint = (Digest::SHA1.hexdigest public_key).slice(0..7)
  verbose 3, "  returns \"#{fingerprint}\""
  return fingerprint
end

#Generates a public key pair and writes out the file names based on the
#fingerprint of the public key.
def generate_fingerprinted_key_pair(destination, bits)
  verbose 3, "generate_fingerprinted_key_pair()"
  verbose 1, "Generating new key pair."
  rsa_key = OpenSSL::PKey::RSA.new(bits)
  private_key = rsa_key.to_s
  public_key = rsa_key.public_key.to_pem.to_s
  fingerprint = fingerprint(public_key)
  verbose 1, "Writing out private key: #{destination + fingerprint}"
  #write out the private key
  f = File.open(destination + fingerprint, "w")
  f.write(private_key)
  f.close()
  verbose 1, "Writing out public key: #{destination + fingerprint}.pub"
  #write out the public key
  f = File.open(destination + fingerprint + ".pub", "w")
  f.write(public_key)
  f.close()
  verbose 3, "  returns #{fingerprint}"
  return fingerprint
end

def load_yaml(filepath)
  verbose 3, "load_yaml(\"#{filepath}\")"
  yaml_config = YAML.load(File.read(filepath))
  #--config
  if yaml_config and yaml_config.has_key?("config")
    filepath = yaml_config["config"]
    yaml_config = YAML.load(File.read(filepath))
  end
  #yaml_config has been loaded.  Configure options.
  if yaml_config
    #set decrypt mode only if decrypt option is not in the config file
    if not yaml_config.has_key?("decrypt") and (\
       yaml_config.has_key?("private_key") or \
       yaml_config.has_key?("secrets_file") or \
       yaml_config.has_key?("inplace") or \
       yaml_config.has_key?("file")\
       )
      #end of long conditionals
      yaml_config["decrypt"] = true
    end
    #--file
    if yaml_config.has_key?("file")
      yaml_config["files"] = [yaml_config["file"]]
    end
    #--inplace
    if yaml_config.has_key?("inplace")
      yaml_config["inplace"] = yaml_config["inplace"].to_s
      if yaml_config["inplace"] == "true" or yaml_config["inplace"].length == 0
        yaml_config["inplace"] = true
        yaml_config["extension"] = nil
      elsif yaml_config["inplace"] == "false"
        yaml_config["inplace"] = false
        yaml_config["extension"] = nil
      else
        yaml_config["extension"] = yaml_config["inplace"]
        yaml_config["inplace"] = true
        yaml_config["extension"].sub!(/\A\.?(?=.)/, ".")  # Ensure extension begins with dot.
      end
    end
    #--fingerprint
    if yaml_config.has_key?("fingerprint")
      yaml_config["fingerprint"] = yaml_config["fingerprint"].to_s
      if yaml_config["fingerprint"] == "true"
        yaml_config["fingerprint"] = ""
      elsif yaml_config["fingerprint"] == "false"
        yaml_config["fingerprint"] = nil
      end
    end
    #--secrets-directory
    if yaml_config.has_key?("secrets_directory")
      if (yaml_config["secrets_directory"].length > 0) and not (yaml_config["secrets_directory"][-1] == '/')
        yaml_config["secrets_directory"] += '/'
      end
    end
    #--generate-key-pair
    if yaml_config.has_key?("generate_key_pair")
      verbose 0, "ERROR: generate_key_pair not allowed in config file: #{filepath}"
      exit 1
    end
    #--bits
    if yaml_config.has_key?("bits")
      yaml_config["bits"] = yaml_config["bits"].to_i
      if yaml_config["bits"] < 1024
        verbose 0, "WARNING: bits (from #{filepath}) less than 1024 is insecure.  Setting to 1024."
        yaml_config["bits"] = 1024
      end
    end
    #--verbose
    if yaml_config.has_key?("verbose")
      yaml_config["verbose"] = yaml_config["verbose"].to_i
    end
  end
  if not yaml_config
    yaml_config = {}
  end
  verbose 3, "  returns #{yaml_config}"
  return yaml_config
end

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

#LOAD THE CONFIG FILE FOR OVERRIDES
yaml_config = {}
if File.file?($options["config"])
  yaml_config = load_yaml($options["config"])
elsif File.file?("repository-secrets.yml")
  yaml_config = load_yaml("repository-secrets.yml")
end
$options.merge!(yaml_config)

#set the private and public keys if fingerprint used
if $options["fingerprint"] and ($options["fingerprint"].length > 0)
  $options["private_key"] = $options["secrets_directory"] + $options["fingerprint"]
  $options["public_key"] = $options["secrets_directory"] + $options["fingerprint"] + ".pub"
end

#print out the structures
verbose 2, "$options data structure after merging config file."
verbose 2, PP.pp($options, "")

#GENERATE PUBLIC KEY PAIR
if $options["generate_key_pair"]
  fingerprint = generate_fingerprinted_key_pair($options["secrets_directory"], $options["bits"])
  verbose 0, "Generated a fingerprinted key pair.  Place the following in your repository-secrets.yml"
  verbose 0, "fingerprint: \"#{fingerprint}\""
  exit
end

#DO ENCRYPTION OR DECRYPTION
if (ARGV.length > 0) || $options["decrypt"]
  if $options["decrypt"]
    verbose 0, "Performing decryption with string interpolation on files."
    if $options["inplace"]
      verbose 0, "Inplace editing enabled for all files."
    end
    #read the secrets file
    if $options["secrets_file"]
      verbose 0, "Reading a secrets file for a list of files."
      f = File.open($options["secrets_file"], "r")
      f.each_line do |line|
        #skip blank lines
        next if line.strip.length == 0
        #skip lines that start with a hash
        next if /^\s*#.*/.match(line.strip)
        $options["files"] << line.strip
      end
      f.close
    end
    $options["files"].each do |file|
      verbose 0, "Performing string interpolation on: #{file}"
      filecontents = File.read(file)
      if $options["fingerprint"]
        secrets = filecontents.scan(/\${#{Regexp.escape($options["secret_text_tag"])}_[0-9a-f]{8}:[^}]*}/)
      else
        secrets = filecontents.scan(/\${#{Regexp.escape($options["secret_text_tag"])}:[^}]*}/)
      end
      secrets.each do |secret|
        #extract just the cipher text from the secret
        if $options["fingerprint"]
          fingerprint = secret.gsub(/\${#{Regexp.escape($options["secret_text_tag"])}_([0-9a-f]{8}):[^}]*}/,'\1')
          ciphertext = secret.gsub(/\${#{Regexp.escape($options["secret_text_tag"])}_[0-9a-f]{8}:([^}]*)}/,'\1')
          verbose 3, "fingerprint = #{fingerprint}"
          verbose 3, "ciphertext = #{ciphertext}"
          #inline string replace the secret with the plain text
          filecontents.gsub!(secret, decrypt($options["secrets_directory"] + fingerprint, ciphertext))
        else
          ciphertext = secret.gsub(/\${#{Regexp.escape($options["secret_text_tag"])}:([^}]*)}/,'\1')
          #inline string replace the secret with the plain text
          filecontents.gsub!(secret, decrypt($options["private_key"], ciphertext))
        end
      end
      if $options["inplace"]
        if $options["extension"]
          FileUtils.cp(file, file+$options["extension"])
          verbose 1, "Making a backup of #{file} to #{file+$options["extension"]}"
        end
        verbose 1, "Writing to #{file}"
        f = File.open(file,"w")
        f.write(filecontents)
        f.close()
      else
        puts filecontents
      end
    end
  else
    ARGV.each do |plaintext|
      if $options["fingerprint"]
        puts "${#{$options["secret_text_tag"]}_#{$options["fingerprint"]}:#{encrypt($options["public_key"], plaintext.strip)}}"
      else
        puts "${#{$options["secret_text_tag"]}:#{encrypt($options["public_key"], plaintext.strip)}}"
      end
    end
  end
else
  verbose 0, "Reading from stdin.  Use CTRL+D to finish."
  ARGF.each do |plaintext|
    if $options["decrypt"]
      verbose 0, "ERR: You may only decrypt in normal mode not using stdin."
      exit 1
    end
    next if plaintext.strip.length == 0
    if $options["fingerprint"]
      puts "${#{$options["secret_text_tag"]}_#{$options["fingerprint"]}:#{encrypt($options["public_key"], plaintext.strip)}}"
    else
      puts "${#{$options["secret_text_tag"]}:#{encrypt($options["public_key"], plaintext.strip)}}"
    end
  end
end

#output info message to stderr
if not $options["decrypt"]
  verbose 0, ""
  verbose 0, "Replace the plain text string in your config file with the secure one."
  verbose 0, "NOTE: Don't forget to regenerate passwords or API keys if you've already"
  verbose 0, "committed them to the repository and published it as plain text."
  verbose 0, ""
end

#CHANGELOG
#0.2.0 - Jan 25, 2015
  #New feature: key rotation supported through --fingerprint option.
  #New options: --config, --fingerprint, --secrets-directory, --generate-key-pair, --bits
  #Fixed bug: --decrypt documentation was not properly showing up in Decrypt mode section.  It now does.
#0.1.0 - initial release
