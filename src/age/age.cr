require "./lib"
require "./keys"

module Age
  class Error < Exception; end

  # Generates a new X25519 keypair.
  # Returns an Age::Keypair with public_key (age1...) and secret_key (AGE-SECRET-KEY-1...).
  def self.keygen : Keypair
    result = LibAge.age_keygen

    if result.error
      msg = String.new(result.error)
      LibAge.age_free(result.error)
      raise Error.new(msg)
    end

    pub = String.new(result.public_key)
    sec = String.new(result.secret_key)

    LibAge.age_free(result.public_key)
    LibAge.age_free(result.secret_key)

    Keypair.new(PublicKey.new(pub), SecretKey.new(sec))
  end

  # Encrypts *data* for *recipient*.
  # Returns the binary age ciphertext as Bytes.
  def self.encrypt(data : Bytes, recipient : PublicKey) : Bytes
    result = LibAge.age_encrypt(data.to_unsafe, data.size, recipient.to_unsafe)

    if result.error
      msg = String.new(result.error)
      LibAge.age_free(result.error)
      raise Error.new(msg)
    end

    ciphertext = Bytes.new(result.len)
    ciphertext.copy_from(result.data, result.len)
    LibAge.age_free(result.data)
    ciphertext
  end

  # Convenience overload accepting a String.
  def self.encrypt(data : String, recipient : PublicKey) : Bytes
    encrypt(data.to_slice, recipient)
  end

  # Decrypts *ciphertext* with *identity*.
  # Returns the plaintext as Bytes.
  def self.decrypt(ciphertext : Bytes, identity : SecretKey) : Bytes
    result = LibAge.age_decrypt(ciphertext.to_unsafe, ciphertext.size, identity.to_unsafe)

    if result.error
      msg = String.new(result.error)
      LibAge.age_free(result.error)
      raise Error.new(msg)
    end

    plaintext = Bytes.new(result.len)
    plaintext.copy_from(result.data, result.len)
    LibAge.age_free(result.data)
    plaintext
  end

  # Convenience overload returning a String.
  def self.decrypt_string(ciphertext : Bytes, identity : SecretKey) : String
    String.new(decrypt(ciphertext, identity))
  end
end
