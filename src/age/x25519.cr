require "big"

# Pure Crystal X25519 key exchange on Curve25519 (RFC 7748).
# Uses BigInt field arithmetic with the Montgomery ladder.

module Age
  module X25519
    P   = (BigInt.new(1) << 255) - BigInt.new(19)
    A24 = BigInt.new(121665)

    BASE = begin
      b = Bytes.new(32)
      b[0] = 9_u8
      b
    end

    private def self.add(a : BigInt, b : BigInt) : BigInt
      (a + b) % P
    end

    private def self.sub(a : BigInt, b : BigInt) : BigInt
      r = (a - b) % P
      r < 0 ? r + P : r
    end

    private def self.mul(a : BigInt, b : BigInt) : BigInt
      (a * b) % P
    end

    # Modular inverse via Fermat's little theorem: a^(p-2) mod p
    private def self.inv(a : BigInt) : BigInt
      pow_mod(a, P - 2, P)
    end

    private def self.pow_mod(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
      result = BigInt.new(1)
      b = base % mod
      e = exp
      while e > 0
        result = result * b % mod if (e & 1) == 1
        b = b * b % mod
        e >>= 1
      end
      result
    end

    private def self.decode_u(u : Bytes) : BigInt
      n = BigInt.new(0)
      31.downto(0) { |i| n = (n << 8) | BigInt.new(u[i]) }
      n & ((BigInt.new(1) << 255) - 1)
    end

    private def self.encode_u(n : BigInt) : Bytes
      result = Bytes.new(32)
      v = n % P
      32.times do |i|
        result[i] = (v % 256).to_u8
        v //= 256
      end
      result
    end

    # Clamp scalar per RFC 7748 §5.
    private def self.clamp(k : Bytes) : Bytes
      z = k.dup
      z[0] &= 248_u8
      z[31] &= 127_u8
      z[31] |= 64_u8
      z
    end

    # Montgomery ladder scalar multiplication (RFC 7748 §5).
    def self.scalarmult(k_bytes : Bytes, u_bytes : Bytes) : Bytes
      k = clamp(k_bytes)
      u = decode_u(u_bytes)

      x1 = u
      x2 = BigInt.new(1)
      z2 = BigInt.new(0)
      x3 = u
      z3 = BigInt.new(1)
      swap = 0

      254.downto(0) do |t|
        k_t = (k[t >> 3].to_i32 >> (t & 7)) & 1
        swap ^= k_t
        if swap != 0
          x2, x3 = x3, x2
          z2, z3 = z3, z2
        end
        swap = k_t

        a  = add(x2, z2)
        aa = mul(a, a)
        b  = sub(x2, z2)
        bb = mul(b, b)
        e  = sub(aa, bb)
        c  = add(x3, z3)
        d  = sub(x3, z3)
        da = mul(d, a)
        cb = mul(c, b)
        s1 = add(da, cb)
        x3 = mul(s1, s1)
        s2 = sub(da, cb)
        z3 = mul(x1, mul(s2, s2))
        x2 = mul(aa, bb)
        z2 = mul(e, add(aa, mul(A24, e)))
      end

      if swap != 0
        x2, x3 = x3, x2
        z2, z3 = z3, z2
      end

      encode_u(mul(x2, inv(z2)))
    end

    def self.generate_keypair : {Bytes, Bytes}
      private_key = Random::Secure.random_bytes(32)
      {private_key, scalarmult(private_key, BASE)}
    end

    def self.public_from_private(private_key : Bytes) : Bytes
      scalarmult(private_key, BASE)
    end

    def self.shared_secret(private_key : Bytes, peer_public_key : Bytes) : Bytes
      result = scalarmult(private_key, peer_public_key)
      raise Age::Error.new("X25519 produced all-zero shared secret (low-order point)") if result.all?(&.zero?)
      result
    end
  end
end
