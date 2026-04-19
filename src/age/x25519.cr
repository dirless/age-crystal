require "openssl"

module Age
  module X25519
    NID_X25519 = 1034

    @[Link("crypto")]
    lib LibEvpX25519
      fun EVP_PKEY_CTX_new_id(id : Int32, e : Void*) : Void*
      fun EVP_PKEY_CTX_new(pkey : Void*, e : Void*) : Void*
      fun EVP_PKEY_CTX_free(ctx : Void*) : Void
      fun EVP_PKEY_keygen_init(ctx : Void*) : Int32
      fun EVP_PKEY_keygen(ctx : Void*, ppkey : Void**) : Int32
      fun EVP_PKEY_derive_init(ctx : Void*) : Int32
      fun EVP_PKEY_derive_set_peer(ctx : Void*, peer : Void*) : Int32
      fun EVP_PKEY_derive(ctx : Void*, key : UInt8*, keylen : LibC::SizeT*) : Int32
      fun EVP_PKEY_free(pkey : Void*) : Void
      fun EVP_PKEY_new_raw_private_key(type : Int32, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Void*
      fun EVP_PKEY_new_raw_public_key(type : Int32, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Void*
      fun EVP_PKEY_get_raw_private_key(pkey : Void*, priv : UInt8*, len : LibC::SizeT*) : Int32
      fun EVP_PKEY_get_raw_public_key(pkey : Void*, pub : UInt8*, len : LibC::SizeT*) : Int32
    end

    def self.generate_keypair : {Bytes, Bytes}
      ctx = LibEvpX25519.EVP_PKEY_CTX_new_id(NID_X25519, nil)
      raise Age::Error.new("EVP_PKEY_CTX_new_id failed") if ctx.null?
      begin
        raise Age::Error.new("EVP_PKEY_keygen_init failed") if LibEvpX25519.EVP_PKEY_keygen_init(ctx) != 1
        pkey = Pointer(Void).null
        raise Age::Error.new("EVP_PKEY_keygen failed") if LibEvpX25519.EVP_PKEY_keygen(ctx, pointerof(pkey)) != 1
        begin
          {raw_private(pkey), raw_public(pkey)}
        ensure
          LibEvpX25519.EVP_PKEY_free(pkey) unless pkey.null?
        end
      ensure
        LibEvpX25519.EVP_PKEY_CTX_free(ctx)
      end
    end

    def self.public_from_private(private_key : Bytes) : Bytes
      pkey = LibEvpX25519.EVP_PKEY_new_raw_private_key(NID_X25519, nil, private_key.to_unsafe, LibC::SizeT.new(private_key.size))
      raise Age::Error.new("EVP_PKEY_new_raw_private_key failed") if pkey.null?
      begin
        raw_public(pkey)
      ensure
        LibEvpX25519.EVP_PKEY_free(pkey)
      end
    end

    def self.shared_secret(private_key : Bytes, peer_public_key : Bytes) : Bytes
      priv = LibEvpX25519.EVP_PKEY_new_raw_private_key(NID_X25519, nil, private_key.to_unsafe, LibC::SizeT.new(private_key.size))
      raise Age::Error.new("Invalid X25519 private key") if priv.null?

      pub = LibEvpX25519.EVP_PKEY_new_raw_public_key(NID_X25519, nil, peer_public_key.to_unsafe, LibC::SizeT.new(peer_public_key.size))

      begin
        raise Age::Error.new("Invalid X25519 public key") if pub.null?

        ctx = LibEvpX25519.EVP_PKEY_CTX_new(priv, nil)
        raise Age::Error.new("EVP_PKEY_CTX_new failed") if ctx.null?

        begin
          raise Age::Error.new("EVP_PKEY_derive_init failed") if LibEvpX25519.EVP_PKEY_derive_init(ctx) != 1
          raise Age::Error.new("EVP_PKEY_derive_set_peer failed") if LibEvpX25519.EVP_PKEY_derive_set_peer(ctx, pub) != 1

          keylen = LibC::SizeT.new(32)
          secret = Bytes.new(32)
          raise Age::Error.new("EVP_PKEY_derive failed") if LibEvpX25519.EVP_PKEY_derive(ctx, secret.to_unsafe, pointerof(keylen)) != 1

          raise Age::Error.new("X25519 produced all-zero shared secret (low-order point)") if secret.all?(&.zero?)
          secret
        ensure
          LibEvpX25519.EVP_PKEY_CTX_free(ctx)
        end
      ensure
        LibEvpX25519.EVP_PKEY_free(priv)
        LibEvpX25519.EVP_PKEY_free(pub) unless pub.null?
      end
    end

    private def self.raw_private(pkey : Void*) : Bytes
      len = LibC::SizeT.new(32)
      buf = Bytes.new(32)
      LibEvpX25519.EVP_PKEY_get_raw_private_key(pkey, buf.to_unsafe, pointerof(len))
      buf
    end

    private def self.raw_public(pkey : Void*) : Bytes
      len = LibC::SizeT.new(32)
      buf = Bytes.new(32)
      LibEvpX25519.EVP_PKEY_get_raw_public_key(pkey, buf.to_unsafe, pointerof(len))
      buf
    end
  end
end
