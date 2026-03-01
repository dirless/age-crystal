@[Link("age", ldflags: "-L#{__DIR__}/../../dist -Wl,-rpath,#{__DIR__}/../../dist -lage")]
lib LibAge
  struct Result
    data  : UInt8*
    len   : Int32
    error : UInt8*
  end

  struct Keypair
    public_key : UInt8*
    secret_key : UInt8*
    error       : UInt8*
  end

  fun age_free(ptr : Void*) : Void
  fun age_keygen : Keypair
  fun age_encrypt(data : UInt8*, data_len : Int32, public_key : UInt8*) : Result
  fun age_decrypt(data : UInt8*, data_len : Int32, secret_key : UInt8*) : Result
end
