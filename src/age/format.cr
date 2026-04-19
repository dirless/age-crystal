require "base64"
require "openssl/hmac"

module Age
  # Serialises and parses the age text header (https://age-encryption.org/v1).
  module Format
    MAGIC = "age-encryption.org/v1"

    record Stanza, type : String, args : Array(String), body : Bytes

    # Serialises stanzas + MAC into the age header string (including the trailing newline).
    def self.write_header(stanzas : Array(Stanza), file_key : Bytes) : String
      io = IO::Memory.new
      io.puts MAGIC

      stanzas.each do |s|
        io.puts "-> #{([s.type] + s.args).join(' ')}"
        write_b64_body(io, s.body)
      end

      # Write "--- " then compute MAC over everything so far (that is the MAC input).
      io.print "--- "
      hmac_key = HKDF.sha256(file_key, Bytes.new(0), "header".to_slice, 32)
      mac = OpenSSL::HMAC.digest(:sha256, hmac_key, io.to_s.to_slice)
      io.puts b64_encode(mac)

      io.to_s
    end

    # Parses the header portion of an age file.
    # Returns {stanzas, mac_bytes, header_for_mac_string}.
    def self.parse_header(header : String) : {Array(Stanza), Bytes, String}
      lines = header.lines(chomp: true)
      raise Age::Error.new("Invalid age header: missing magic line") if lines.empty?
      raise Age::Error.new("Invalid age header: wrong magic '#{lines[0]}'") if lines[0] != MAGIC

      stanzas = [] of Stanza
      i = 1

      while i < lines.size
        line = lines[i]
        break if line.starts_with?("---")

        raise Age::Error.new("Expected stanza line starting with '->', got: #{line[0, 4]}") unless line.starts_with?("-> ")
        parts = line[3..].split(' ')
        raise Age::Error.new("Stanza missing type") if parts.empty?
        type = parts[0]
        args = parts[1..]

        i += 1
        body_lines = [] of String
        while i < lines.size && !lines[i].starts_with?("->") && !lines[i].starts_with?("---")
          body_lines << lines[i]
          i += 1
        end

        body = b64_decode(body_lines.join)
        stanzas << Stanza.new(type, args, body)
      end

      raise Age::Error.new("Age header missing '---' footer") if i >= lines.size

      footer = lines[i]
      raise Age::Error.new("Invalid footer line") unless footer.starts_with?("--- ")
      mac = b64_decode(footer[4..])

      # Reconstruct the bytes the MAC was computed over: everything up to and including "--- "
      header_for_mac = lines[0...i].map { |l| "#{l}\n" }.join + "--- "

      {stanzas, mac, header_for_mac}
    end

    # Splits raw age file bytes into (header_string, body_bytes).
    def self.split(data : Bytes) : {String, Bytes}
      pos = 0
      while pos < data.size
        nl = pos
        while nl < data.size && data[nl] != 10_u8
          nl += 1
        end

        # Check if this line starts with "--- "
        if nl - pos >= 4 &&
           data[pos]     == 45_u8 &&  # '-'
           data[pos + 1] == 45_u8 &&  # '-'
           data[pos + 2] == 45_u8 &&  # '-'
           data[pos + 3] == 32_u8     # ' '
          header_end = nl < data.size ? nl + 1 : nl
          body_start = nl < data.size ? nl + 1 : data.size
          return {String.new(data[0, header_end]), data[body_start, data.size - body_start]}
        end

        pos = nl + 1
      end

      raise Age::Error.new("Invalid age file: no '---' footer found")
    end

    # Encodes body bytes in 48-byte chunks (= 64 base64 chars/line).
    # Appends an empty line when body.size is divisible by 48 (spec requirement).
    private def self.write_b64_body(io : IO, body : Bytes)
      i = 0
      while i < body.size
        chunk_end = {i + 48, body.size}.min
        io.puts b64_encode(body[i, chunk_end - i])
        i = chunk_end
      end
      io.puts if body.size % 48 == 0
    end

    def self.b64_encode(data : Bytes) : String
      Base64.strict_encode(data).rstrip("=")
    end

    def self.b64_decode(s : String) : Bytes
      begin
        Base64.decode(s)
      rescue e : Base64::Error
        raise Age::Error.new("Invalid base64: #{e.message}")
      end
    end
  end
end
