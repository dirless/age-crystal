# Pure Crystal ChaCha20-Poly1305 AEAD per RFC 8439.
# IETF variant (96-bit nonce, 32-bit counter).
#
# ChaCha20: RFC 8439 §2.3 (little-endian state words).
# Poly1305: RFC 8439 §2.5 (5-limb 26-bit accumulator, per-block "1" bit).
# AEAD:     RFC 8439 §2.8 (empty AAD; framing = ciphertext || LE64(0) || LE64(ct_len)).

module Age
  module ChaCha20Poly1305
    TAG_SIZE  = 16
    LIMB_MASK = 0x3ffffff_u64

    # Encrypt plaintext. Returns ciphertext || 16-byte Poly1305 tag.
    def self.encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes) : Bytes
      block0     = chacha20_block(key, nonce, 0_u32)
      ciphertext = chacha20_encrypt(key, nonce, 1_u32, plaintext)
      tag    = poly1305_mac(block0[0, 32], aead_mac_data(ciphertext))
      result = Bytes.new(ciphertext.size + TAG_SIZE)
      ciphertext.copy_to(result)
      tag.copy_to(result + ciphertext.size)
      result
    end

    # Decrypt ciphertext || 16-byte tag. Returns plaintext or raises Age::Error.
    def self.decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes) : Bytes
      raise Age::Error.new("Ciphertext too short for ChaCha20-Poly1305") if ciphertext.size < TAG_SIZE
      data = ciphertext[0, ciphertext.size - TAG_SIZE]
      tag  = ciphertext[ciphertext.size - TAG_SIZE, TAG_SIZE]

      block0       = chacha20_block(key, nonce, 0_u32)
      expected_tag = poly1305_mac(block0[0, 32], aead_mac_data(data))
      raise Age::Error.new("Decryption failed: authentication tag mismatch") unless constant_time_eq(tag, expected_tag)

      chacha20_encrypt(key, nonce, 1_u32, data)
    end

    # ==================== ChaCha20 ====================

    private macro qr(a, b, c, d)
      {{a}} &+= {{b}}; {{d}} ^= {{a}}; {{d}} = {{d}}.rotate_left(16)
      {{c}} &+= {{d}}; {{b}} ^= {{c}}; {{b}} = {{b}}.rotate_left(12)
      {{a}} &+= {{b}}; {{d}} ^= {{a}}; {{d}} = {{d}}.rotate_left(8)
      {{c}} &+= {{d}}; {{b}} ^= {{c}}; {{b}} = {{b}}.rotate_left(7)
    end

    private def self.chacha20_block(key : Bytes, nonce : Bytes, counter : UInt32) : Bytes
      s = uninitialized UInt32[16]
      s[0] = 0x61707865_u32; s[1] = 0x3320646e_u32
      s[2] = 0x79622d32_u32; s[3] = 0x6b206574_u32
      (0...8).each { |i| s[4 + i] = u32_le(key, i * 4) }
      s[12] = counter
      (0...3).each { |i| s[13 + i] = u32_le(nonce, i * 4) }

      w = s.dup
      10.times do
        qr(w[0], w[4], w[8],  w[12]); qr(w[1], w[5], w[9],  w[13])
        qr(w[2], w[6], w[10], w[14]); qr(w[3], w[7], w[11], w[15])
        qr(w[0], w[5], w[10], w[15]); qr(w[1], w[6], w[11], w[12])
        qr(w[2], w[7], w[8],  w[13]); qr(w[3], w[4], w[9],  w[14])
      end

      r = Bytes.new(64)
      (0...16).each { |i| put_u32_le(r, i * 4, s[i] &+ w[i]) }
      r
    end

    private def self.chacha20_encrypt(key : Bytes, nonce : Bytes, counter : UInt32, data : Bytes) : Bytes
      buf = Bytes.new(data.size)
      off = 0
      ctr = counter
      while off < data.size
        block = chacha20_block(key, nonce, ctr)
        n = {data.size - off, 64}.min
        n.times { |j| buf[off + j] = data[off + j] ^ block[j] }
        off += n
        ctr &+= 1_u32
      end
      buf
    end

    # ==================== Poly1305 ====================

    # Build RFC 8439 §2.8 AEAD MAC input for empty AAD:
    # ciphertext || pad16(ciphertext) || LE64(0) || LE64(len(ciphertext))
    private def self.aead_mac_data(ciphertext : Bytes) : Bytes
      pad  = (16 - ciphertext.size % 16) % 16
      size = ciphertext.size + pad + 16  # 16 = 8 bytes LE64(0) + 8 bytes LE64(ct_len)
      buf  = Bytes.new(size, 0_u8)
      ciphertext.copy_to(buf)
      ct_len = ciphertext.size.to_u64
      8.times { |i| buf[ciphertext.size + pad + 8 + i] = ((ct_len >> (8 * i)) & 0xff_u64).to_u8 }
      buf
    end

    # Poly1305 MAC per RFC 8439 §2.5. key is 32 bytes (r || s).
    private def self.poly1305_mac(key : Bytes, msg : Bytes) : Bytes
      k = Bytes.new(32)
      k.copy_from(key)

      # Clamp r per RFC 8439 §2.5
      k[3] &= 0x0f_u8; k[7] &= 0x0f_u8; k[11] &= 0x0f_u8; k[15] &= 0x0f_u8
      k[4] &= 0xfc_u8; k[8] &= 0xfc_u8; k[12] &= 0xfc_u8

      # Load r as 5×26-bit limbs (little-endian, overlapping reads)
      r = StaticArray(UInt64, 5).new(0_u64)
      r[0] = u32_le(k, 0).to_u64 & LIMB_MASK
      r[1] = (u32_le(k, 3).to_u64 >> 2) & LIMB_MASK
      r[2] = (u32_le(k, 6).to_u64 >> 4) & LIMB_MASK
      r[3] = (u32_le(k, 9).to_u64 >> 6) & LIMB_MASK
      r[4] = (u32_le(k, 12).to_u64 >> 8) & LIMB_MASK

      s = key[16, 16]

      h = StaticArray(UInt64, 5).new(0_u64)

      off = 0
      while off < msg.size
        n = {msg.size - off, 16}.min

        # Per RFC 8439 §2.5: append 0x01 after each block's bytes.
        # For a 17-byte buffer, load bits 0-129 as 5×26-bit limbs.
        buf = Bytes.new(17, 0_u8)
        buf.copy_from(msg[off, n])
        buf[n] = 0x01_u8

        m = StaticArray(UInt64, 5).new(0_u64)
        m[0] = (buf[0].to_u64 | buf[1].to_u64 << 8 | buf[2].to_u64 << 16 | buf[3].to_u64 << 24) & LIMB_MASK
        m[1] = (buf[3].to_u64 >> 2 | buf[4].to_u64 << 6 | buf[5].to_u64 << 14 | buf[6].to_u64 << 22) & LIMB_MASK
        m[2] = (buf[6].to_u64 >> 4 | buf[7].to_u64 << 4 | buf[8].to_u64 << 12 | buf[9].to_u64 << 20) & LIMB_MASK
        m[3] = (buf[9].to_u64 >> 6 | buf[10].to_u64 << 2 | buf[11].to_u64 << 10 | buf[12].to_u64 << 18) & LIMB_MASK
        m[4] = (buf[13].to_u64 | buf[14].to_u64 << 8 | buf[15].to_u64 << 16 | buf[16].to_u64 << 24) & LIMB_MASK

        5.times { |i| h[i] += m[i] }
        h = poly1305_mulmod(h, r)

        off += 16
      end

      # Convert h (5×26-bit limbs) to 4×32-bit words (bits 0-127).
      # Add s mod 2^128 with carry propagation.
      v0 = (h[0] | h[1] << 26) & 0xFFFFFFFF_u64
      v1 = (h[1] >> 6 | h[2] << 20) & 0xFFFFFFFF_u64
      v2 = (h[2] >> 12 | h[3] << 14) & 0xFFFFFFFF_u64
      v3 = (h[3] >> 18 | h[4] << 8) & 0xFFFFFFFF_u64

      c0 = v0 + u32_le(s, 0).to_u64
      c1 = v1 + u32_le(s, 4).to_u64 + (c0 >> 32)
      c2 = v2 + u32_le(s, 8).to_u64 + (c1 >> 32)
      c3 = v3 + u32_le(s, 12).to_u64 + (c2 >> 32)

      tag = Bytes.new(16)
      put_u32_le(tag, 0,  c0.to_u32!)
      put_u32_le(tag, 4,  c1.to_u32!)
      put_u32_le(tag, 8,  c2.to_u32!)
      put_u32_le(tag, 12, c3.to_u32!)
      tag
    end

    # Multiply h by r and reduce mod (2^130 - 5), returning 5×26-bit limbs.
    private def self.poly1305_mulmod(h : StaticArray(UInt64, 5), r : StaticArray(UInt64, 5)) : StaticArray(UInt64, 5)
      # Schoolbook 5×5 → 9 partial sums (indices 0..8)
      u = StaticArray(UInt64, 9).new(0_u64)
      5.times { |i| 5.times { |j| u[i + j] &+= h[i] * r[j] } }

      # Reduce limbs 5..8 back: 2^130 ≡ 5 (mod 2^130-5)
      4.times { |i| u[i] &+= u[i + 5] * 5 }

      # Propagate carries to normalise to 26-bit limbs
      out = StaticArray(UInt64, 5).new(0_u64)
      carry = 0_u64
      5.times do |i|
        t       = u[i] &+ carry
        out[i]  = t & LIMB_MASK
        carry   = t >> 26
      end
      # Fold final carry back (2^130 ≡ 5)
      out[0] &+= carry * 5
      carry = out[0] >> 26; out[0] &= LIMB_MASK; out[1] &+= carry
      carry = out[1] >> 26; out[1] &= LIMB_MASK; out[2] &+= carry
      carry = out[2] >> 26; out[2] &= LIMB_MASK; out[3] &+= carry
      carry = out[3] >> 26; out[3] &= LIMB_MASK; out[4] &+= carry

      out
    end

    # ==================== Helpers ====================

    private def self.u32_le(data : Bytes, off : Int) : UInt32
      data[off].to_u32 | data[off + 1].to_u32 << 8 |
        data[off + 2].to_u32 << 16 | data[off + 3].to_u32 << 24
    end

    private def self.put_u32_le(data : Bytes, off : Int, v : UInt32) : Nil
      data[off]     = v.to_u8!
      data[off + 1] = (v >> 8).to_u8!
      data[off + 2] = (v >> 16).to_u8!
      data[off + 3] = (v >> 24).to_u8!
    end

    private def self.constant_time_eq(a : Bytes, b : Bytes) : Bool
      return false if a.size != b.size
      diff = 0_u8
      a.size.times { |i| diff |= a[i] ^ b[i] }
      diff == 0
    end
  end
end
