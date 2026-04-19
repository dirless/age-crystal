require "openssl"

# Extend OpenSSL::Cipher with AEAD tag methods missing from the stdlib.
class OpenSSL::Cipher
  EVP_CTRL_AEAD_GET_TAG = 0x10
  EVP_CTRL_AEAD_SET_TAG = 0x11

  @[Link("crypto")]
  lib LibCryptoAEAD
    fun EVP_CIPHER_CTX_ctrl(ctx : Void*, type : Int32, arg : Int32, ptr : Void*) : Int32
  end

  def auth_tag(len : Int32 = 16) : Bytes
    tag = Bytes.new(len)
    if LibCryptoAEAD.EVP_CIPHER_CTX_ctrl(@ctx, EVP_CTRL_AEAD_GET_TAG, len, tag.to_unsafe.as(Void*)) != 1
      raise OpenSSL::Error.new("EVP_CIPHER_CTX_ctrl GET_TAG")
    end
    tag
  end

  def auth_tag=(tag : Bytes)
    if LibCryptoAEAD.EVP_CIPHER_CTX_ctrl(@ctx, EVP_CTRL_AEAD_SET_TAG, tag.size, tag.to_unsafe.as(Void*)) != 1
      raise OpenSSL::Error.new("EVP_CIPHER_CTX_ctrl SET_TAG")
    end
  end
end

module Age
  module ChaCha20Poly1305
    TAG_SIZE = 16

    def self.encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes) : Bytes
      cipher = OpenSSL::Cipher.new("chacha20-poly1305")
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce

      output = IO::Memory.new
      output.write(cipher.update(plaintext))
      output.write(cipher.final)
      output.write(cipher.auth_tag(TAG_SIZE))
      output.to_slice
    end

    def self.decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes) : Bytes
      raise Age::Error.new("Ciphertext too short for ChaCha20-Poly1305") if ciphertext.size < TAG_SIZE

      data = ciphertext[0, ciphertext.size - TAG_SIZE]
      tag  = ciphertext[ciphertext.size - TAG_SIZE, TAG_SIZE]

      cipher = OpenSSL::Cipher.new("chacha20-poly1305")
      cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = tag

      begin
        output = IO::Memory.new
        output.write(cipher.update(data))
        output.write(cipher.final)
        output.to_slice
      rescue ex : OpenSSL::Error
        raise Age::Error.new("Decryption failed: authentication tag mismatch")
      end
    end
  end
end
