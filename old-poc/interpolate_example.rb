#http://stackoverflow.com/questions/9891708/ruby-file-encryption-decryption-with-private-public-keys
#A ruby example of string interpolation with RSA encrypted secrets

require 'openssl'
require 'base64'
#location of private key used for decryption
private_key_file="secrets/id_rsa"
#this text tag is the supersecret in ${supersecret:ciphertext}, this makes it configurable
secret_text_tag="supersecret"

#First decodes base64 ciphertext input and then decrypts; returns plain text
def decrypt(ciphertext,private_key_file)
  private_key=OpenSSL::PKey::RSA.new(File.read(private_key_file))
  plaintext=private_key.private_decrypt(Base64.strict_decode64(ciphertext))
  return plaintext
end

#read some file which needs string interpolation on secrets
somefile=File.read('examples/myconfig.json')
#find all of the secrets
secrets=somefile.scan(/\${#{Regexp.escape(secret_text_tag)}:[^}]*}/)
#loop over each found secret
secrets.each do |secret|
  #extract just the cipher text from the secret
  ciphertext=secret.gsub(/\${#{Regexp.escape(secret_text_tag)}:([^}]*)}/,'\1')
  #replace the secret with the plain text
  somefile.gsub!(secret,decrypt(ciphertext,private_key_file))
end
#print the file to stdout
puts somefile
