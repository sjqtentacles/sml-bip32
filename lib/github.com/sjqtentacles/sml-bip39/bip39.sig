(* bip39.sig

   BIP-39 mnemonic seed phrases (English wordlist) in pure Standard ML.

   Byte convention (shared across the sjqtentacles crypto/codec family):
   `string` is a raw-byte container - one byte per char, values 0-255 - so
   entropy and the derived seed interoperate directly with `sml-crypto`
   (PBKDF2-HMAC-SHA512) and `sml-codec` (SHA-256). `*Hex` helpers are provided
   for the common case of working with hex-encoded entropy/seeds.

   The mnemonic <-> entropy mapping (BIP-39):
     - Valid entropy is 128/160/192/224/256 bits (16/20/24/28/32 bytes).
     - A checksum of ENT/32 bits (the leading bits of SHA-256(entropy)) is
       appended; the resulting ENT+CS bits are split into 11-bit groups, each
       selecting a word from the 2048-word list (12/15/18/21/24 words).

   Seed derivation (BIP-39):
     seed = PBKDF2(PRF = HMAC-SHA512, password = mnemonic,
                   salt = "mnemonic" ^ passphrase, c = 2048, dkLen = 64).
   The mnemonic and passphrase are used verbatim as UTF-8 byte strings; for the
   English wordlist (and ASCII passphrases such as the canonical "TREZOR") this
   matches the spec's NFKD requirement, since those inputs are already
   normalized. Callers using non-ASCII passphrases must pass NFKD-normalized
   UTF-8. *)

signature BIP39 =
sig
  (* Raised by [entropyToMnemonic] / [entropyHexToMnemonic] when the entropy is
     not one of the valid byte lengths {16,20,24,28,32}. Carries that length. *)
  exception InvalidEntropy of int

  (* Raised by [entropyHexToMnemonic] when the argument is not valid hex. *)
  exception InvalidHex

  (* Raw entropy bytes -> space-separated mnemonic. Raises [InvalidEntropy]. *)
  val entropyToMnemonic : string -> string

  (* Mnemonic -> raw entropy bytes. NONE when the word count is invalid, a word
     is not in the list, or the checksum does not verify. *)
  val mnemonicToEntropy : string -> string option

  (* Derive the 64-byte BIP-39 seed (raw bytes). Does not validate the
     mnemonic's checksum - seed derivation is defined for any string. *)
  val mnemonicToSeed : {mnemonic:string, passphrase:string} -> string

  (* True iff [mnemonicToEntropy] succeeds (valid words + checksum). *)
  val isValid : string -> bool

  (* Hex conveniences. *)
  val entropyHexToMnemonic : string -> string          (* hex entropy -> mnemonic *)
  val mnemonicToEntropyHex : string -> string option   (* mnemonic -> hex entropy *)
  val mnemonicToSeedHex    : {mnemonic:string, passphrase:string} -> string
end
