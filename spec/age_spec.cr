require "spec"
require "../src/age-crystal"

describe Age do
  describe ".keygen" do
    it "returns a keypair with correct key formats" do
      keypair = Age.keygen
      keypair.public_key.value.should start_with("age1")
      keypair.secret_key.value.should start_with("AGE-SECRET-KEY-1")
    end

    it "generates unique keypairs on each call" do
      keypairs = Array.new(5) { Age.keygen }
      public_keys = keypairs.map(&.public_key.value)
      secret_keys = keypairs.map(&.secret_key.value)
      public_keys.uniq.size.should eq(5)
      secret_keys.uniq.size.should eq(5)
    end
  end

  describe ".encrypt / .decrypt" do
    it "round-trips plaintext bytes" do
      keypair = Age.keygen
      plaintext = "hello from dirless 🦝".to_slice

      ciphertext = Age.encrypt(plaintext, keypair.public_key)
      ciphertext.should_not eq(plaintext)

      recovered = Age.decrypt(ciphertext, keypair.secret_key)
      recovered.should eq(plaintext)
    end

    it "round-trips a string via decrypt_string" do
      keypair = Age.keygen
      message = "envelope encryption is great"

      ciphertext = Age.encrypt(message, keypair.public_key)
      Age.decrypt_string(ciphertext, keypair.secret_key).should eq(message)
    end

    it "round-trips empty data" do
      keypair = Age.keygen
      plaintext = Bytes.empty

      ciphertext = Age.encrypt(plaintext, keypair.public_key)
      recovered = Age.decrypt(ciphertext, keypair.secret_key)
      recovered.should eq(plaintext)
    end

    it "round-trips empty string via decrypt_string" do
      keypair = Age.keygen
      ciphertext = Age.encrypt("", keypair.public_key)
      Age.decrypt_string(ciphertext, keypair.secret_key).should eq("")
    end

    it "round-trips large data (1 MB)" do
      keypair = Age.keygen
      plaintext = Random::Secure.random_bytes(1_048_576)

      ciphertext = Age.encrypt(plaintext, keypair.public_key)
      recovered = Age.decrypt(ciphertext, keypair.secret_key)
      recovered.should eq(plaintext)
    end

    it "round-trips binary data with null bytes and non-UTF8 content" do
      keypair = Age.keygen
      # Build a buffer with null bytes and bytes invalid in UTF-8
      plaintext = Bytes.new(256, &.to_u8)

      ciphertext = Age.encrypt(plaintext, keypair.public_key)
      recovered = Age.decrypt(ciphertext, keypair.secret_key)
      recovered.should eq(plaintext)
    end

    it "produces different ciphertexts for the same plaintext and key" do
      keypair = Age.keygen
      plaintext = "determinism check"

      ct1 = Age.encrypt(plaintext, keypair.public_key)
      ct2 = Age.encrypt(plaintext, keypair.public_key)
      ct1.should_not eq(ct2)

      # Both must still decrypt to the same plaintext
      Age.decrypt_string(ct1, keypair.secret_key).should eq(plaintext)
      Age.decrypt_string(ct2, keypair.secret_key).should eq(plaintext)
    end

    it "encrypt(String) and encrypt(Bytes) both produce decryptable output" do
      keypair = Age.keygen
      message = "test string vs bytes"

      ct_string = Age.encrypt(message, keypair.public_key)
      ct_bytes = Age.encrypt(message.to_slice, keypair.public_key)

      Age.decrypt_string(ct_string, keypair.secret_key).should eq(message)
      Age.decrypt_string(ct_bytes, keypair.secret_key).should eq(message)
    end

    it "raises on wrong key" do
      keypair = Age.keygen
      other = Age.keygen

      ciphertext = Age.encrypt("secret", keypair.public_key)

      expect_raises(Age::Error) do
        Age.decrypt(ciphertext, other.secret_key)
      end
    end

    it "raises on corrupted ciphertext" do
      keypair = Age.keygen
      ciphertext = Age.encrypt("important data", keypair.public_key)

      # Flip bits in the middle of the ciphertext
      corrupted = ciphertext.dup
      mid = corrupted.size // 2
      corrupted[mid] = corrupted[mid] ^ 0xFF_u8

      expect_raises(Age::Error) do
        Age.decrypt(corrupted, keypair.secret_key)
      end
    end
  end

  describe "key validation" do
    it "rejects a bad public key" do
      expect_raises(Age::Error) do
        Age::PublicKey.new("notavalidkey")
      end
    end

    it "rejects a bad secret key" do
      expect_raises(Age::Error) do
        Age::SecretKey.new("notavalidkey")
      end
    end

    it "rejects an empty string as public key" do
      expect_raises(Age::Error) do
        Age::PublicKey.new("")
      end
    end

    it "rejects an empty string as secret key" do
      expect_raises(Age::Error) do
        Age::SecretKey.new("")
      end
    end

    it "rejects public key with only the prefix" do
      expect_raises(Age::Error) do
        # "age1" alone is not a valid key — encryption should fail
        key = Age::PublicKey.new("age1")
        Age.encrypt("test", key)
      end
    end

    it "rejects secret key with only the prefix" do
      expect_raises(Age::Error) do
        # "AGE-SECRET-KEY-1" alone is not a valid key — decryption should fail
        keypair = Age.keygen
        ct = Age.encrypt("test", keypair.public_key)
        key = Age::SecretKey.new("AGE-SECRET-KEY-1")
        Age.decrypt(ct, key)
      end
    end

    it "rejects a truncated public key" do
      keypair = Age.keygen
      truncated = keypair.public_key.value[0..10]
      expect_raises(Age::Error) do
        key = Age::PublicKey.new(truncated)
        Age.encrypt("test", key)
      end
    end

    it "rejects a public key with spaces" do
      keypair = Age.keygen
      spaced = keypair.public_key.value.insert(10, ' ')
      expect_raises(Age::Error) do
        key = Age::PublicKey.new(spaced)
        Age.encrypt("test", key)
      end
    end
  end
end
