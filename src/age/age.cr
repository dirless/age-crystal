require "./bech32"
require "./x25519"
require "./hkdf"
require "./chacha20poly1305"
require "./stream"
require "./format"
require "./keys"

module Age
  class Error < Exception; end

  X25519_INFO = "age-encryption.org/v1/X25519"

  def self.keygen : Keypair
    priv, pub = X25519.generate_keypair
    Keypair.new(
      PublicKey.new(Bech32.encode("age", pub)),
      SecretKey.new(Bech32.encode("age-secret-key-", priv).upcase)
    )
  end

  def self.encrypt(data : Bytes, recipient : PublicKey) : Bytes
    hrp, pub_bytes = Bech32.decode(recipient.value)
    raise Error.new("Invalid recipient key HRP: #{hrp}") unless hrp == "age"
    raise Error.new("Invalid recipient public key length") unless pub_bytes.size == 32

    file_key    = Random::Secure.random_bytes(16)
    ephem_priv, ephem_pub = X25519.generate_keypair
    shared      = X25519.shared_secret(ephem_priv, pub_bytes)

    salt = concat(ephem_pub, pub_bytes)
    wrap_key = HKDF.sha256(shared, salt, X25519_INFO.to_slice, 32)

    zero_nonce  = Bytes.new(12)
    wrapped_key = ChaCha20Poly1305.encrypt(wrap_key, zero_nonce, file_key)

    stanza  = Format::Stanza.new("X25519", [Format.b64_encode(ephem_pub)], wrapped_key)
    header  = Format.write_header([stanza], file_key)
    payload = Stream.encrypt(file_key, data)

    concat(header.to_slice, payload)
  end

  def self.encrypt(data : String, recipient : PublicKey) : Bytes
    encrypt(data.to_slice, recipient)
  end

  def self.decrypt(ciphertext : Bytes, identity : SecretKey) : Bytes
    hrp, sec_bytes = Bech32.decode(identity.value)
    raise Error.new("Invalid identity key HRP: #{hrp}") unless hrp == "age-secret-key-"
    raise Error.new("Invalid identity key length") unless sec_bytes.size == 32

    pub_bytes = X25519.public_from_private(sec_bytes)

    header_str, body = Format.split(ciphertext)
    stanzas, mac, header_for_mac = Format.parse_header(header_str)

    file_key = unwrap_file_key(stanzas, sec_bytes, pub_bytes)
    raise Error.new("No matching X25519 recipient found") unless file_key

    verify_header_mac(file_key, header_for_mac, mac)

    Stream.decrypt(file_key, body)
  end

  def self.decrypt_string(ciphertext : Bytes, identity : SecretKey) : String
    String.new(decrypt(ciphertext, identity))
  end

  private def self.unwrap_file_key(
    stanzas : Array(Format::Stanza),
    sec_bytes : Bytes,
    pub_bytes : Bytes
  ) : Bytes?
    stanzas.each do |s|
      next unless s.type == "X25519"
      next if s.args.empty?

      begin
        ephem_pub = Format.b64_decode(s.args[0])
        next unless ephem_pub.size == 32

        shared   = X25519.shared_secret(sec_bytes, ephem_pub)
        salt     = concat(ephem_pub, pub_bytes)
        wrap_key = HKDF.sha256(shared, salt, X25519_INFO.to_slice, 32)

        zero_nonce = Bytes.new(12)
        file_key   = ChaCha20Poly1305.decrypt(wrap_key, zero_nonce, s.body)
        return file_key if file_key.size == 16
      rescue Age::Error
        next
      end
    end
    nil
  end

  private def self.verify_header_mac(file_key : Bytes, header_for_mac : String, mac : Bytes)
    hmac_key     = HKDF.sha256(file_key, Bytes.new(0), "header".to_slice, 32)
    expected_mac = OpenSSL::HMAC.digest(:sha256, hmac_key, header_for_mac.to_slice)

    raise Error.new("Header MAC verification failed") unless constant_time_eq(mac, expected_mac)
  end

  private def self.constant_time_eq(a : Bytes, b : Bytes) : Bool
    return false if a.size != b.size
    diff = 0_u8
    a.size.times { |i| diff |= a[i] ^ b[i] }
    diff == 0
  end

  private def self.concat(a : Bytes, b : Bytes) : Bytes
    result = Bytes.new(a.size + b.size)
    a.copy_to(result)
    b.copy_to(result + a.size)
    result
  end
end
