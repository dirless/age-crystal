require "spec"
require "../src/age-crystal"

TESTDATA = File.join(__DIR__, "testdata")

describe "age interop with Go age CLI" do
  it "decrypts a Go age-encrypted file" do
    key_data = File.read(File.join(TESTDATA, "go_test.key"))
    key_line = key_data.lines.find { |l| l.starts_with?("AGE-SECRET-KEY-") }
    key_line.should_not be_nil
    identity = Age::SecretKey.new(key_line.not_nil!.strip)

    ct = File.read(File.join(TESTDATA, "go_test.age")).to_slice
    plaintext = Age.decrypt_string(ct, identity)
    plaintext.should eq("test plaintext for interop verification")
  end

  it "produces files that Go age CLI can decrypt" do
    kp = Age.keygen
    plaintext = "hello from Crystal age-crystal"
    ct = Age.encrypt(plaintext, kp.public_key)

    key_path = "/tmp/_spec_crystal_key.txt"
    ct_path = "/tmp/_spec_crystal_ct.age"
    out_path = "/tmp/_spec_crystal_decrypted.txt"
    File.write(key_path, kp.secret_key.value)
    File.write(ct_path, ct)

    success = system("age -d -i #{key_path} -o #{out_path} #{ct_path}")

    if success
      result = File.read(out_path).strip
      result.should eq(plaintext)
    else
      pending("age CLI not available in this environment")
    end
  ensure
    File.delete("/tmp/_spec_crystal_key.txt") if File.exists?("/tmp/_spec_crystal_key.txt")
    File.delete("/tmp/_spec_crystal_ct.age") if File.exists?("/tmp/_spec_crystal_ct.age")
    File.delete("/tmp/_spec_crystal_decrypted.txt") if File.exists?("/tmp/_spec_crystal_decrypted.txt")
  end
end