#http://stackoverflow.com/questions/9891708/ruby-file-encryption-decryption-with-private-public-keys
#A ruby example of string interpolation with RSA encrypted secrets
require 'openssl'
require 'base64'
private_key_file="secrets/id_rsa"
#this text tag is the supersecret in ${supersecret:ciphertext}, this makes it configurable
secret_text_tag="supersecret"

def decrypt(ciphertext,private_key_file)
  private_key=OpenSSL::PKey::RSA.new(File.read(private_key_file))
  plaintext=private_key.private_decrypt(Base64.decode64(ciphertext))
  return plaintext
end

somefile=File.read('examples/myconfig.json')
secrets=somefile.scan(/\${#{Regexp.escape(secret_text_tag)}:[^}]*}/)
secrets.each do |secret|
  ciphertext=secret.gsub(/\${#{Regexp.escape(secret_text_tag)}:([^}]*)}/,'\1')
  somefile.gsub!(secret,decrypt(ciphertext,private_key_file))
end
puts somefile
