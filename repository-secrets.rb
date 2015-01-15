#!/usr/bin/env ruby

#required for encryption/decryption
require 'openssl'
require 'base64'
#required for option parsing
require 'optparse'
require 'ostruct'
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
      opts.banner = "Usage: repository-secrets.rb [options]"

      opts.separator ""
      opts.separator "Specific options:"

      # Mandatory argument.
      opts.on("-s", "--secrets-file FILE",
              "Path to a secrets FILE; the contents contain one file per line.  It will",
              "do string interpolation on each file in the list replacing secrets with",
              "the decrypted text.  File paths are either full path or relative to the",
              "current working directory.") do |file|
        options.secrets_file = file
      end

      opts.on("-f", "--file FILE",
              "Use string interpolation on the specified FILE to decrypt secrets.") do |file|
        options.files << file
      end

      # Optional argument; multi-line description.
      opts.on("-i", "--inplace [EXTENSION]",
              "Edit string interpolated files in place",
              "  (make backup if EXTENSION supplied)") do |ext|
        options.inplace = true
        options.extension = ext || ''
        options.extension.sub!(/\A\.?(?=.)/, ".")  # Ensure extension begins with dot.
      end

      # Boolean switch.
      opts.on("-v", "--[no-]verbose",
              "Run verbosely",
              "  (more verbosity with -vv or -vvv)") do |v|
        #increment verbosity by 1 for each -v used
        if v
          options.verbose += 1
        end
      end

      opts.separator ""
      opts.separator "Common options:"

      # No argument, shows at tail.  This will print an options summary.
      # Try it and see!
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
  if $options.verbose > 2
    puts "v3> decrypt(#{ciphertext})"
  end
  private_key=OpenSSL::PKey::RSA.new(File.read($options.private_key_file))
  plaintext=private_key.private_decrypt(Base64.strict_decode64(ciphertext))
  if $options.verbose > 2
    puts "v3>  returns #{plaintext}"
  end
  return plaintext
end # decrypt()

#First encrypts plain text input and then encodes in base64; returns cipher text
def encrypt(plaintext)
  if $options.verbose > 2
    puts "v3> encrypt(#{plaintext})"
  end
  public_key = OpenSSL::PKey::RSA.new(File.read($options.public_key_file))
  ciphertext = Base64.strict_encode64(public_key.public_encrypt(plaintext))
  if $options.verbose > 2
    puts "v3>   returns #{ciphertext}"
  end
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

if ARGV.length > 0
  if $options.decrypt
    verbose 0, "Performing decryption with string interpolation on files."
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
verbose 0, ""
verbose 0, "Replace the plain text string in your config file with the secure one."
verbose 0, "NOTE: Don't forget to regenerate passwords or API keys if you've already"
verbose 0, "committed them to the repository and published it as plain text."
verbose 0, ""








#somefile=File.read('examples/myconfig.json')
#secrets=somefile.scan(/\${#{Regexp.escape(secret_text_tag)}:[^}]*}/)
#secrets.each do |secret|
#  ciphertext=secret.gsub(/\${#{Regexp.escape(secret_text_tag)}:([^}]*)}/,'\1')
#  somefile.gsub!(secret,decrypt(ciphertext,private_key_file))
#end
#puts somefile
