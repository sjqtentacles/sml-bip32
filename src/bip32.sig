(* bip32.sig

   BIP-32 hierarchical deterministic (HD) wallets in pure Standard ML.

   Byte convention (shared across the sjqtentacles crypto/codec family):
   `string` is a raw-byte container - one byte per char, values 0-255 - so
   seeds, chain codes, keys and addresses interoperate directly with the
   vendored `sml-secp256k1` (point/pubkey), `sml-crypto` (HMAC-SHA512),
   `sml-codec` (SHA-256), `sml-ripemd160` (hash160) and `sml-base58`
   (Base58Check). `*Hex` helpers cover the common case of a hex-encoded seed.

   Scope - PRIVATE-TREE derivation only:
     master -> CKDpriv (hardened + normal) -> neuter at each node.
   This covers exactly what the official BIP-32 test vectors exercise. The
   public-parent CKDpub function (deriving a child xpub from a parent xpub
   WITHOUT the private key) is intentionally out of scope: it needs an
   elliptic-curve point addition (point(IL) + K_par) and `sml-secp256k1`
   exposes only `pubkey` (scalar -> point), not a tweak/point-add. CKDpub is
   a documented follow-up that would add `tweakAdd` to `sml-secp256k1`.

   Derivation (BIP-32):
     master:        I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
                    k = parse256(I_L), c = I_R
     CKDpriv(i):    Data = (i hardened) 0x00 || ser256(k_par) || ser32(i)
                           (i normal)   serP(point(k_par)) || ser32(i)
                    I = HMAC-SHA512(Key = c_par, Data),
                    k_i = (parse256(I_L) + k_par) mod n,  c_i = I_R
     neuter:        (k, c) -> (point(k), c)

   Serialization is the standard 78-byte form (version || depth ||
   parent-fingerprint || child-number || chain-code || key-data), Base58Check
   encoded (mainnet xprv = 0x0488ADE4, xpub = 0x0488B21E). A P2PKH address is
   Base58Check(0x00 || RIPEMD160(SHA256(pubkey))). *)

signature BIP32 =
sig
  type xprv   (* extended private key: (depth, parentFp, childNumber, chainCode, k) *)
  type xpub   (* extended public  key: (depth, parentFp, childNumber, chainCode, K) *)

  (* Raised by [derivePath] on a malformed path component. Carries the path. *)
  exception InvalidPath of string

  (* Raised by [masterFromSeedHex] when the argument is not valid hex. *)
  exception InvalidHex

  (* Raised when a derived key is invalid - parse256(I_L) >= n or the resulting
     scalar is zero. The BIP-32 spec says one should then try the next index;
     in practice this has probability < 1 in 2^127, so we surface it. *)
  exception InvalidKey

  (* master key from a seed (BIP-32 advises 16..64 raw bytes). *)
  val masterFromSeed    : string -> xprv
  (* master key from a hex-encoded seed. Raises [InvalidHex] on non-hex input. *)
  val masterFromSeedHex : string -> xprv

  (* CKDpriv: child extended private key at index i (i >= 0x80000000 hardened). *)
  val ckdPriv    : xprv * Word32.word -> xprv

  (* N(.): the neutered (public) extended key. *)
  val neuter     : xprv -> xpub

  (* Walk a path like "m/44'/0'/0'/0/0" ("m"/"M" prefix optional; a trailing
     "'", "h" or "H" marks a hardened index). Raises [InvalidPath]. *)
  val derivePath : xprv * string -> xprv

  (* Base58Check serialization (mainnet version bytes). *)
  val xprvToBase58 : xprv -> string
  val xpubToBase58 : xpub -> string

  (* Mainnet P2PKH address: Base58Check(0x00 || hash160(pubkey)). *)
  val toAddressP2PKH : xpub -> string
end
