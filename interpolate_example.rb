#http://stackoverflow.com/questions/9891708/ruby-file-encryption-decryption-with-private-public-keys
#A ruby example of string interpolation with RSA encrypted secrets
require 'openssl'
require 'base64'
private_key_file="secrets/id_rsa"

def decrypt(ciphertext,private_key_file)
  private_key=OpenSSL::PKey::RSA.new(File.read(private_key_file))
  plaintext=private_key.private_decrypt(Base64.decode64(ciphertext))
  return plaintext
end

somefile=File.read('examples/myconfig.json')
secrets=somefile.scan(/\${supersecret:[^}]*}/)
secrets.each do |secret|
  ciphertext=secret.gsub(/\${supersecret:([^}]*)}/,'\1')
  somefile.gsub!(secret,decrypt(ciphertext,private_key_file))
end
puts somefile
