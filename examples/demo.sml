(* sml-bip32 demo: an end-to-end HD-wallet walk -

     mnemonic --(BIP-39 PBKDF2-HMAC-SHA512)--> 64-byte seed
             --(BIP-32 master)--> m
             --(BIP-44 path)--> m/44'/0'/0'/0/0
             --(neuter + hash160 + Base58Check)--> P2PKH address

   The mnemonic is the canonical BIP-39 test vector; everything below it is
   deterministic, so the printed output is byte-identical under MLton and
   Poly/ML. *)

fun line s = print (s ^ "\n")

val () = line "sml-bip32 demo"
val () = line "=============="

val mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
val passphrase = ""

val () = line ("mnemonic   : " ^ mnemonic)
val () = line ("passphrase : " ^ (if passphrase = "" then "(none)" else passphrase))

(* BIP-39: mnemonic -> raw 64-byte seed (via the vendored sml-bip39). *)
val seed   = Bip39.mnemonicToSeed {mnemonic = mnemonic, passphrase = passphrase}

(* BIP-32: seed -> master extended key. *)
val master = Bip32.masterFromSeed seed
val () = line ""
val () = line ("master xprv     : " ^ Bip32.xprvToBase58 master)
val () = line ("master xpub     : " ^ Bip32.xpubToBase58 (Bip32.neuter master))
val () = line ("master address  : " ^ Bip32.toAddressP2PKH (Bip32.neuter master))

(* BIP-44 account 0, external chain, first address: m/44'/0'/0'/0/0. *)
val path = "m/44'/0'/0'/0/0"
val node = Bip32.derivePath (master, path)
val pub  = Bip32.neuter node

val () = line ""
val () = line ("path            : " ^ path)
val () = line ("node xprv       : " ^ Bip32.xprvToBase58 node)
val () = line ("node xpub       : " ^ Bip32.xpubToBase58 pub)
val () = line ("P2PKH address   : " ^ Bip32.toAddressP2PKH pub)
