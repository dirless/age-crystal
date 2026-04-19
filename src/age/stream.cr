module Age
  # STREAM construction as used by the age encryption format.
  # Splits plaintext into 64 KiB chunks, each encrypted with ChaCha20-Poly1305.
  # The 12-byte per-chunk nonce is: 11-byte big-endian counter || last_flag (0x00 or 0x01).
  module Stream
    CHUNK_SIZE = 64 * 1024

    def self.encrypt(file_key : Bytes, plaintext : Bytes) : Bytes
      nonce = Random::Secure.random_bytes(16)
      stream_key = HKDF.sha256(file_key, nonce, "payload".to_slice, 32)

      output = IO::Memory.new
      output.write(nonce)

      offset  = 0
      counter = 0_i64

      loop do
        chunk_end = {offset + CHUNK_SIZE, plaintext.size}.min
        chunk     = plaintext[offset, chunk_end - offset]
        is_last   = chunk_end >= plaintext.size

        output.write(ChaCha20Poly1305.encrypt(stream_key, chunk_nonce(counter, is_last), chunk))

        offset  = chunk_end
        counter += 1
        break if is_last
      end

      output.to_slice
    end

    def self.decrypt(file_key : Bytes, ciphertext : Bytes) : Bytes
      raise Age::Error.new("STREAM ciphertext too short") if ciphertext.size < 16

      nonce      = ciphertext[0, 16]
      stream_key = HKDF.sha256(file_key, nonce, "payload".to_slice, 32)
      data       = ciphertext[16, ciphertext.size - 16]

      output           = IO::Memory.new
      offset           = 0
      counter          = 0_i64
      chunk_with_tag   = CHUNK_SIZE + ChaCha20Poly1305::TAG_SIZE

      loop do
        remaining     = data.size - offset
        is_last       = remaining <= chunk_with_tag

        chunk_len = is_last ? remaining : chunk_with_tag
        chunk     = data[offset, chunk_len]

        begin
          output.write(ChaCha20Poly1305.decrypt(stream_key, chunk_nonce(counter, is_last), chunk))
        rescue Age::Error
          raise Age::Error.new("Decryption failed: stream authentication error")
        end

        offset  += chunk_len
        counter += 1
        break if is_last
      end

      output.to_slice
    end

    # Builds a 12-byte chunk nonce: 11-byte big-endian counter || last_flag.
    private def self.chunk_nonce(counter : Int64, last : Bool) : Bytes
      n = Bytes.new(12)
      # Bytes 0–2 are always zero for a 64-bit counter (fits in bytes 3–10)
      n[3]  = ((counter >> 56) & 0xff).to_u8
      n[4]  = ((counter >> 48) & 0xff).to_u8
      n[5]  = ((counter >> 40) & 0xff).to_u8
      n[6]  = ((counter >> 32) & 0xff).to_u8
      n[7]  = ((counter >> 24) & 0xff).to_u8
      n[8]  = ((counter >> 16) & 0xff).to_u8
      n[9]  = ((counter >> 8)  & 0xff).to_u8
      n[10] = (counter         & 0xff).to_u8
      n[11] = last ? 0x01_u8 : 0x00_u8
      n
    end
  end
end
