(* base58.sig

   Base58 and Base58Check using the Bitcoin alphabet
   ("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

   Values are raw byte strings (one byte per `char`, 0-255). Encoding is pure,
   total, and deterministic, and byte-identical under MLton and Poly/ML.

   Conventions:
   - Plain Base58 maps each leading 0x00 byte to a leading '1' and encodes the
     remaining big-endian integer with the 58-symbol alphabet.
   - `decode` returns NONE on any character outside the alphabet.
   - Base58Check appends the first 4 bytes of double-SHA256(payload) as a
     checksum before encoding; `decodeCheck` verifies and strips it, returning
     NONE on a bad/short checksum or invalid characters. The vendored
     `Sha256.digest` supplies the hash. *)

signature BASE58 =
sig
  (* Plain Base58. *)
  val encode : string -> string
  val decode : string -> string option

  (* Base58Check (double-SHA256, 4-byte checksum). *)
  val encodeCheck : string -> string
  val decodeCheck : string -> string option
end
