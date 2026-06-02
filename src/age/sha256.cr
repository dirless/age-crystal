# Pure Crystal SHA-256 implementation per FIPS 180-4.
# Modeled on Crystal stdlib's Crystal::Digest::SHA1 pattern.

module Age
  module SHA256
    DIGEST_SIZE = 32

    K = {
      0x428a2f98_u32, 0x71374491_u32, 0xb5c0fbcf_u32, 0xe9b5dba5_u32,
      0x3956c25b_u32, 0x59f111f1_u32, 0x923f82a4_u32, 0xab1c5ed5_u32,
      0xd807aa98_u32, 0x12835b01_u32, 0x243185be_u32, 0x550c7dc3_u32,
      0x72be5d74_u32, 0x80deb1fe_u32, 0x9bdc06a7_u32, 0xc19bf174_u32,
      0xe49b69c1_u32, 0xefbe4786_u32, 0x0fc19dc6_u32, 0x240ca1cc_u32,
      0x2de92c6f_u32, 0x4a7484aa_u32, 0x5cb0a9dc_u32, 0x76f988da_u32,
      0x983e5152_u32, 0xa831c66d_u32, 0xb00327c8_u32, 0xbf597fc7_u32,
      0xc6e00bf3_u32, 0xd5a79147_u32, 0x06ca6351_u32, 0x14292967_u32,
      0x27b70a85_u32, 0x2e1b2138_u32, 0x4d2c6dfc_u32, 0x53380d13_u32,
      0x650a7354_u32, 0x766a0abb_u32, 0x81c2c92e_u32, 0x92722c85_u32,
      0xa2bfe8a1_u32, 0xa81a664b_u32, 0xc24b8b70_u32, 0xc76c51a3_u32,
      0xd192e819_u32, 0xd6990624_u32, 0xf40e3585_u32, 0x106aa070_u32,
      0x19a4c116_u32, 0x1e376c08_u32, 0x2748774c_u32, 0x34b0bcb5_u32,
      0x391c0cb3_u32, 0x4ed8aa4a_u32, 0x5b9cca4f_u32, 0x682e6ff3_u32,
      0x748f82ee_u32, 0x78a5636f_u32, 0x84c87814_u32, 0x8cc70208_u32,
      0x90befffa_u32, 0xa4506ceb_u32, 0xbef9a3f7_u32, 0xc67178f2_u32,
    }

    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H_INIT = [
      0x6a09e667_u32, 0xbb67ae85_u32, 0x3c6ef372_u32, 0xa54ff53a_u32,
      0x510e527f_u32, 0x9b05688c_u32, 0x1f83d9ab_u32, 0x5be0cd19_u32,
    ]

    # Compute SHA-256 digest of data. Returns 32 bytes.
    def self.digest(data : Bytes) : Bytes
      h = H_INIT.dup

      # Pre-processing: pad message to multiple of 512 bits (64 bytes)
      msg_len_bits = data.size.to_u64 * 8
      padded = IO::Memory.new
      padded.write(data.to_slice)
      padded.write_byte(0x80_u8)

      # Pad with zeros until length ≡ 56 mod 64 (leaving 8 bytes for length)
      while padded.pos % 64 != 56
        padded.write_byte(0x00_u8)
      end

      # Append original message length in bits as big-endian 64-bit
      padded.write_bytes(msg_len_bits, IO::ByteFormat::BigEndian)

      padded_data = padded.to_slice

      # Process each 64-byte (512-bit) block
      0.step(to: padded_data.size - 1, by: 64) do |offset|
        block = padded_data[offset, 64]

        # Prepare message schedule w[0..63]
        w = uninitialized UInt32[64]
        (0...16).each do |t|
          w[t] = block[t * 4].to_u32 << 24 |
                 block[t * 4 + 1].to_u32 << 16 |
                 block[t * 4 + 2].to_u32 << 8 |
                 block[t * 4 + 3].to_u32
        end

        (16...64).each do |t|
          s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3)
          s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10)
          w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
        end

        # Working variables
        a = h[0]
        b = h[1]
        c = h[2]
        d = h[3]
        e = h[4]
        f = h[5]
        g = h[6]
        hh = h[7]

        # 64 rounds
        (0...64).each do |t|
          s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
          ch = (e & f) ^ (~e & g)
          temp1 = hh &+ s1 &+ ch &+ K[t] &+ w[t]
          s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
          maj = (a & b) ^ (a & c) ^ (b & c)
          temp2 = s0 &+ maj

          hh = g
          g = f
          f = e
          e = d &+ temp1
          d = c
          c = b
          b = a
          a = temp1 &+ temp2
        end

        h[0] &+= a
        h[1] &+= b
        h[2] &+= c
        h[3] &+= d
        h[4] &+= e
        h[5] &+= f
        h[6] &+= g
        h[7] &+= hh
      end

      # Produce final hash value (big-endian)
      result = Bytes.new(32)
      (0...8).each do |i|
        result[i * 4]     = (h[i] >> 24).to_u8!
        result[i * 4 + 1] = (h[i] >> 16).to_u8!
        result[i * 4 + 2] = (h[i] >> 8).to_u8!
        result[i * 4 + 3] = h[i].to_u8!
      end
      result
    end
  end
end
