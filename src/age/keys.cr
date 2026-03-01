module Age
  # Wraps a native age public key string (age1...).
  # Compatible with the age CLI and filippo.io/age Go library.
  struct PublicKey
    PUBLIC_KEY_PREFIX = "age1"

    getter value : String

    def initialize(@value : String)
      raise Age::Error.new("Invalid public key format: must start with '#{PUBLIC_KEY_PREFIX}'") \
        unless @value.starts_with?(PUBLIC_KEY_PREFIX)
    end

    def to_s(io : IO)
      io << @value
    end

    def to_unsafe : UInt8*
      @value.to_unsafe
    end
  end

  # Wraps a native age secret key string (AGE-SECRET-KEY-1...).
  # Compatible with the age CLI and filippo.io/age Go library.
  struct SecretKey
    SECRET_KEY_PREFIX = "AGE-SECRET-KEY-1"

    getter value : String

    def initialize(@value : String)
      raise Age::Error.new("Invalid secret key format: must start with '#{SECRET_KEY_PREFIX}'") \
        unless @value.starts_with?(SECRET_KEY_PREFIX)
    end

    def to_s(io : IO)
      io << @value
    end

    def to_unsafe : UInt8*
      @value.to_unsafe
    end
  end

  struct Keypair
    getter public_key : PublicKey
    getter secret_key : SecretKey

    def initialize(@public_key : PublicKey, @secret_key : SecretKey)
    end
  end
end
