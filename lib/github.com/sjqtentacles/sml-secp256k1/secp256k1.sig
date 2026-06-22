(* secp256k1.sig

   ECDSA and Schnorr (BIP-340) signatures over the secp256k1 elliptic curve,
   implemented in pure Standard ML using IntInf for field/scalar arithmetic.

   All keys, hashes, and signatures are raw byte strings (each char is one
   byte). Hex helpers live in the consuming code, not here. *)

signature SECP256K1 =
sig
  val scalarSize    : int   (* 32 *)
  val publicKeySize : int   (* 33 compressed *)

  (* 32-byte secret key -> 33-byte compressed public key. *)
  val pubkey   : string -> string
  (* 32-byte secret key -> 65-byte uncompressed public key. *)
  val pubkeyU  : string -> string

  (* ecdsaSign sk msgHash -> DER-encoded signature.
     sk and msgHash are each 32 bytes; uses RFC 6979 deterministic nonce
     and low-s normalization. *)
  val ecdsaSign   : string -> string -> string
  (* ecdsaVerify pk msgHash der -> validity. pk is 33 or 65 bytes. *)
  val ecdsaVerify : string -> string -> string -> bool

  (* schnorrSign sk msg -> 64-byte BIP-340 signature.
     sk and msg are each 32 bytes; aux_rand is all-zero. *)
  val schnorrSign   : string -> string -> string
  (* schnorrVerify xonlyPk msg sig64 -> validity.
     xonlyPk is the 32-byte x-only public key. *)
  val schnorrVerify : string -> string -> string -> bool

  (* compress: 65-byte uncompressed -> 33-byte compressed. *)
  val compress   : string -> string
  (* decompress: 33-byte compressed -> 65-byte uncompressed. *)
  val decompress : string -> string

  (* Hex convenience for the raw byte representations above (secret keys,
     public keys, signatures). toHex encodes bytes as lowercase hex; fromHex
     decodes hex back to bytes, returning NONE on odd length or non-hex input.
     Round-trip: fromHex (toHex b) = SOME b. *)
  val toHex   : string -> string
  val fromHex : string -> string option
end
