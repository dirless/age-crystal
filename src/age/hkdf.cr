require "openssl/hmac"

module Age
  # HKDF-SHA-256 (RFC 5869).
  module HKDF
    def self.sha256(ikm : Bytes, salt : Bytes, info : Bytes, length : Int32) : Bytes
      # Extract: PRK = HMAC-SHA256(salt, IKM)
      # Per RFC 5869 §2.2: if salt is not provided, use HashLen zeros.
      key = salt.empty? ? Bytes.new(32) : salt
      prk = OpenSSL::HMAC.digest(:sha256, key, ikm)

      # Expand: T(1) || T(2) || ... until we have `length` bytes
      output = IO::Memory.new
      t = Bytes.new(0)
      counter = 0_u8

      while output.pos < length
        counter += 1_u8
        msg = IO::Memory.new
        msg.write(t)
        msg.write(info)
        msg.write_byte(counter)
        t = OpenSSL::HMAC.digest(:sha256, prk, msg.to_slice)
        output.write(t)
      end

      output.to_slice[0, length]
    end
  end
end
