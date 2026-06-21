(* ripemd160.sig

   RIPEMD-160 (Dobbertin, Bosselaers, Preneel). Operates on byte strings;
   returns the 20-byte digest as raw bytes or as 40 lowercase hex
   characters. The little-endian sibling of the SHA family: this is the
   inner hash of Bitcoin's hash160 (RIPEMD160(SHA256(x))). *)

signature RIPEMD160 =
sig
  val digest    : string -> string   (* raw 20-byte digest *)
  val hexDigest : string -> string   (* 40-char lowercase hex *)
end
