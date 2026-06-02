# Pure Crystal HMAC-SHA256 per RFC 2104, built on Age::SHA256.

module Age
  module HMAC
    BLOCK_SIZE = 64

    # Compute HMAC-SHA256. Returns 32-byte digest.
    def self.digest(key : Bytes, data : Bytes) : Bytes
      # If key > block size, key = SHA256(key)
      k = if key.size > BLOCK_SIZE
            SHA256.digest(key)
          elsif key.size < BLOCK_SIZE
            # Pad key with zeros to block size
            padded = Bytes.new(BLOCK_SIZE)
            padded.copy_from(key)
            padded
          else
            key
          end

      # Inner and outer padded keys
      ipad = Bytes.new(BLOCK_SIZE) { |i| k[i] ^ 0x36_u8 }
      opad = Bytes.new(BLOCK_SIZE) { |i| k[i] ^ 0x5c_u8 }

      # HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
      inner = Bytes.new(ipad.size + data.size)
      inner.copy_from(ipad)
      inner[ipad.size..].copy_from(data)

      outer = Bytes.new(BLOCK_SIZE + 32)
      outer.copy_from(opad)
      outer[BLOCK_SIZE..].copy_from(SHA256.digest(inner))

      SHA256.digest(outer)
    end
  end
end
