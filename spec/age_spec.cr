require "spec"
require "../src/age-crystal"

describe Age do
  describe ".keygen" do
    it "returns a keypair with correct key formats" do
      keypair = Age.keygen
      keypair.public_key.value.should start_with("age1")
      keypair.secret_key.value.should start_with("AGE-SECRET-KEY-1")
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

    it "raises on wrong key" do
      keypair = Age.keygen
      other = Age.keygen

      ciphertext = Age.encrypt("secret", keypair.public_key)

      expect_raises(Age::Error) do
        Age.decrypt(ciphertext, other.secret_key)
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
  end
end
