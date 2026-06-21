(* bip39.sml

   BIP-39 mnemonic seed phrases over the English wordlist.

   `string` carries raw bytes (one char per byte). The mnemonic/entropy mapping
   packs entropy bits (most-significant first) followed by a SHA-256 checksum
   into 11-bit groups, each selecting a word from [Bip39English.words] (which is
   the 2048-word list in alphabetical order, so word -> index is a binary
   search). Seed derivation is PBKDF2-HMAC-SHA512 from the vendored sml-crypto. *)

structure Bip39 :> BIP39 =
struct
  exception InvalidEntropy of int
  exception InvalidHex

  val words = Bip39English.words
  val nWords = Vector.length words   (* 2048 *)

  (* Bit i (0-indexed from the MSB of byte 0) of a raw byte string. *)
  fun bitOf (s, i) =
    let val byte = Char.ord (String.sub (s, i div 8))
    in Word.toInt (Word.andb
         (Word.>> (Word.fromInt byte, Word.fromInt (7 - i mod 8)), 0w1)) end

  (* Bit i (from the MSB of an 11-bit word) of word [w]. *)
  fun bitOfWord (w, i) =
    Word.toInt (Word.andb
      (Word.>> (Word.fromInt w, Word.fromInt (10 - i)), 0w1))

  (* word -> index via binary search over the alphabetically sorted list. *)
  fun wordIndex w =
    let
      fun bs (lo, hi) =
        if lo > hi then NONE
        else
          let val mid = (lo + hi) div 2
          in case String.compare (w, Vector.sub (words, mid)) of
               EQUAL => SOME mid
             | LESS => bs (lo, mid - 1)
             | GREATER => bs (mid + 1, hi)
          end
    in bs (0, nWords - 1) end

  fun lookupAll [] = SOME []
    | lookupAll (w :: rest) =
        (case wordIndex w of
           NONE => NONE
         | SOME i =>
             (case lookupAll rest of
                NONE => NONE
              | SOME xs => SOME (i :: xs)))

  fun validEntropyLen n =
    n = 16 orelse n = 20 orelse n = 24 orelse n = 28 orelse n = 32

  fun entropyToMnemonic entropy =
    let
      val ent = String.size entropy
      val () = if validEntropyLen ent then () else raise InvalidEntropy ent
      val entBits = ent * 8
      val cs = entBits div 32
      val hash = Sha256.digest entropy
      fun bit p = if p < entBits then bitOf (entropy, p) else bitOf (hash, p - entBits)
      val total = entBits + cs
      val groups = total div 11
      fun group g =
        let fun loop (k, acc) = if k = 11 then acc else loop (k + 1, acc * 2 + bit (g * 11 + k))
        in loop (0, 0) end
      val idxs = List.tabulate (groups, group)
    in
      String.concatWith " " (List.map (fn i => Vector.sub (words, i)) idxs)
    end

  fun mnemonicToEntropy mnemonic =
    let
      val isSep = fn c => c = #" " orelse c = #"\t" orelse c = #"\n" orelse c = #"\r"
      val ws = String.tokens isSep mnemonic
      val mw = length ws
    in
      if mw <> 12 andalso mw <> 15 andalso mw <> 18 andalso mw <> 21 andalso mw <> 24
      then NONE
      else
        case lookupAll ws of
          NONE => NONE
        | SOME idxs =>
            let
              val iv = Vector.fromList idxs
              val totalBits = mw * 11
              val entBits = totalBits * 32 div 33
              val cs = totalBits - entBits
              fun bit p = bitOfWord (Vector.sub (iv, p div 11), p mod 11)
              val entBytesN = entBits div 8
              fun byteAt b =
                let fun loop (k, acc) = if k = 8 then acc else loop (k + 1, acc * 2 + bit (b * 8 + k))
                in Char.chr (loop (0, 0)) end
              val entropy = String.implode (List.tabulate (entBytesN, byteAt))
              val hash = Sha256.digest entropy
              fun checkCs i =
                if i = cs then true
                else if bit (entBits + i) = bitOf (hash, i) then checkCs (i + 1)
                else false
            in
              if checkCs 0 then SOME entropy else NONE
            end
    end

  fun mnemonicToSeed {mnemonic, passphrase} =
    Pbkdf2.pbkdf2Sha512
      {password = mnemonic, salt = "mnemonic" ^ passphrase, iters = 2048, dkLen = 64}

  fun isValid mnemonic = Option.isSome (mnemonicToEntropy mnemonic)

  fun entropyHexToMnemonic hx =
    (case Base16.decode hx of
       NONE => raise InvalidHex
     | SOME bytes => entropyToMnemonic bytes)

  fun mnemonicToEntropyHex mnemonic =
    Option.map Base16.encode (mnemonicToEntropy mnemonic)

  fun mnemonicToSeedHex args = Base16.encode (mnemonicToSeed args)
end
