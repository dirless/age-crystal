module Age
  module Bech32
    CHARSET   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GENERATOR = [0x3b6a57b2_u32, 0x26508e6d_u32, 0x1ea119fa_u32, 0x3d4233dd_u32, 0x2a1462b3_u32]

    def self.encode(hrp : String, data : Bytes) : String
      five_bit = convertbits(data, 8, 5, pad: true)
      checksum = create_checksum(hrp, five_bit)
      chars = (five_bit + checksum).map { |i| CHARSET[i] }.join
      "#{hrp}1#{chars}"
    end

    def self.decode(bech : String) : {String, Bytes}
      lower = bech.downcase
      pos = lower.rindex('1')
      raise Age::Error.new("Invalid bech32 string: no separator") unless pos
      raise Age::Error.new("Invalid bech32 string: HRP too short") if pos < 1
      raise Age::Error.new("Invalid bech32 string: too short") if lower.size < pos + 7

      hrp = lower[0...pos]
      data = lower[(pos + 1)..].chars.map do |c|
        idx = CHARSET.index(c)
        raise Age::Error.new("Invalid bech32 character: #{c}") unless idx
        idx.to_u8
      end

      raise Age::Error.new("Invalid bech32 checksum") unless verify_checksum(hrp, data)

      decoded = convertbits(data[0...-6], 5, 8, pad: false)
      {hrp, Bytes.new(decoded.size) { |i| decoded[i] }}
    end

    private def self.polymod(values : Array(UInt8)) : UInt32
      chk = 1_u32
      values.each do |v|
        b = (chk >> 25).to_u8
        chk = ((chk & 0x1ffffff_u32) << 5) ^ v.to_u32
        5.times { |i| chk ^= GENERATOR[i] if ((b >> i) & 1) == 1 }
      end
      chk
    end

    private def self.hrp_expand(hrp : String) : Array(UInt8)
      result = [] of UInt8
      hrp.each_byte { |c| result << (c >> 5).to_u8 }
      result << 0_u8
      hrp.each_byte { |c| result << (c & 31).to_u8 }
      result
    end

    private def self.verify_checksum(hrp : String, data : Array(UInt8)) : Bool
      polymod(hrp_expand(hrp) + data) == 1_u32
    end

    private def self.create_checksum(hrp : String, data : Array(UInt8)) : Array(UInt8)
      values = hrp_expand(hrp) + data + Array(UInt8).new(6, 0_u8)
      pmod = polymod(values) ^ 1_u32
      Array(UInt8).new(6) { |i| ((pmod >> (5 * (5 - i))) & 31).to_u8 }
    end

    private def self.convertbits(data : Array(UInt8) | Bytes, frombits : Int32, tobits : Int32, pad : Bool) : Array(UInt8)
      acc = 0
      bits = 0
      result = [] of UInt8
      maxv = (1 << tobits) - 1

      data.each do |value|
        acc = ((acc << frombits) | value.to_i) & 0xffffff
        bits += frombits
        while bits >= tobits
          bits -= tobits
          result << ((acc >> bits) & maxv).to_u8
        end
      end

      if pad
        result << ((acc << (tobits - bits)) & maxv).to_u8 if bits > 0
      else
        if bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0
          raise Age::Error.new("Invalid bech32 padding")
        end
      end

      result
    end
  end
end
