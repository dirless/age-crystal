require "spec"
require "../src/age-crystal"

TESTDATA = File.join(__DIR__, "testdata")

describe "age interop" do
  it "decrypts a Go age-encrypted file" do
    # Pre-recorded test vector encrypted by Go's age CLI v1.2.1
    key_data = File.read(File.join(TESTDATA, "go_test.key"))
    key_line = key_data.lines.find { |l| l.starts_with?("AGE-SECRET-KEY-") }
    key_line.should_not be_nil
    identity = Age::SecretKey.new(key_line.not_nil!.strip)

    ct = File.read(File.join(TESTDATA, "go_test.age")).to_slice
    plaintext = Age.decrypt_string(ct, identity)
    plaintext.should eq("test plaintext for interop verification")
  end
end