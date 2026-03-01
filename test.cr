require "./src/age-crystal"

puts "==> keygen"
keypair = Age.keygen
puts "  public: #{keypair.public_key}"
puts "  secret: #{keypair.secret_key}"

puts "==> encrypt"
plaintext = "hello from dirless 🦝"
ciphertext = Age.encrypt(plaintext, keypair.public_key)
puts "  ciphertext: #{ciphertext.size} bytes"

puts "==> decrypt"
recovered = Age.decrypt_string(ciphertext, keypair.secret_key)
puts "  recovered: #{recovered}"

if recovered == plaintext
  puts "\n✓ round-trip OK"
else
  puts "\n✗ MISMATCH"
  exit 1
end
