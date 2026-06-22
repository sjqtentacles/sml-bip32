(* bip32.sml

   BIP-32 hierarchical deterministic wallets - private-tree derivation.

   Field/scalar arithmetic for the child-key tweak goes through the vendored
   sml-bigint (parse256(I_L) + k_par mod n); elliptic-curve points come from
   sml-secp256k1 (`pubkey`: 32-byte scalar -> 33-byte compressed point);
   HMAC-SHA512 from sml-crypto; SHA-256 from sml-codec; RIPEMD-160 from
   sml-ripemd160; and Base58Check from sml-base58. All values are raw byte
   strings (one char per byte, 0-255). *)

structure Bip32 :> BIP32 =
struct
  exception InvalidPath of string
  exception InvalidHex
  exception InvalidKey

  (* ---------------------------------------------------------------- *)
  (* Byte / word helpers                                              *)
  (* ---------------------------------------------------------------- *)

  fun byte (n : int) : string = String.str (Char.chr n)
  fun bytesOf (l : int list) : string = String.implode (List.map Char.chr l)

  (* ser32: Word32 -> 4-byte big-endian string. *)
  fun ser32 (w : Word32.word) : string =
    let
      fun at k = Char.chr (Word32.toInt (Word32.andb (Word32.>> (w, k), 0wxFF)))
    in
      String.implode [at 0w24, at 0w16, at 0w8, at 0w0]
    end

  val hardenedBit : Word32.word = 0wx80000000

  (* ---------------------------------------------------------------- *)
  (* Scalar arithmetic via sml-bigint                                 *)
  (* ---------------------------------------------------------------- *)

  val b256 = BigInt.fromInt 256
  val zero = BigInt.fromInt 0

  (* The secp256k1 group order n. *)
  val curveN =
    case BigInt.fromString
           "115792089237316195423570985008687907852837564279074904382605163141518161494337"
     of SOME v => v
      | NONE   => raise Fail "bad curve order"

  (* big-endian bytes -> bignum *)
  fun parse256 (s : string) : BigInt.int =
    CharVector.foldl
      (fn (c, acc) => BigInt.add (BigInt.mul (acc, b256), BigInt.fromInt (Char.ord c)))
      zero s

  (* bignum in [0, 2^256) -> 32-byte big-endian string (left zero-padded) *)
  fun ser256 (x : BigInt.int) : string =
    let
      fun loop (0, _, acc) = acc
        | loop (k, v, acc) =
            let val (q, r) = BigInt.divMod (v, b256)
            in loop (k - 1, q, Char.chr (valOf (BigInt.toInt r)) :: acc) end
    in
      String.implode (loop (32, x, []))
    end

  fun geN x = BigInt.compare (x, curveN) <> LESS
  fun isZero x = BigInt.compare (x, zero) = EQUAL

  (* ---------------------------------------------------------------- *)
  (* Curve / hash primitives from the vendored deps                   *)
  (* ---------------------------------------------------------------- *)

  (* point(k): 32-byte secret scalar -> 33-byte compressed public key. *)
  fun point (k : string) : string = Secp256k1.pubkey k
  (* hash160 = RIPEMD160(SHA256(.)) *)
  fun hash160 (s : string) : string = Ripemd160.digest (Sha256.digest s)

  (* ---------------------------------------------------------------- *)
  (* Extended keys                                                    *)
  (* ---------------------------------------------------------------- *)

  type xprv = { depth : int, parentFp : string, childNumber : Word32.word,
                chainCode : string, key : string }     (* key: 32 raw bytes *)
  type xpub = { depth : int, parentFp : string, childNumber : Word32.word,
                chainCode : string, pubKey : string }  (* pubKey: 33 compressed *)

  (* Mainnet serialization version bytes. *)
  val verPrv = bytesOf [0x04, 0x88, 0xAD, 0xE4]
  val verPub = bytesOf [0x04, 0x88, 0xB2, 0x1E]

  (* parent fingerprint = first 4 bytes of the parent's key identifier. *)
  fun fingerprintPrv (p : xprv) = String.substring (hash160 (point (#key p)), 0, 4)

  fun masterFromSeed (seed : string) : xprv =
    let
      val i  = Hmac.hmacSha512 "Bitcoin seed" seed
      val il = String.substring (i, 0, 32)
      val ir = String.substring (i, 32, 32)
    in
      if isZero (parse256 il) orelse geN (parse256 il) then raise InvalidKey
      else { depth = 0, parentFp = bytesOf [0,0,0,0], childNumber = 0w0,
             chainCode = ir, key = il }
    end

  fun masterFromSeedHex (h : string) : xprv =
    case Base16.decode h of
      SOME b => masterFromSeed b
    | NONE   => raise InvalidHex

  fun ckdPriv (parent : xprv, i : Word32.word) : xprv =
    let
      val hardened = Word32.>= (i, hardenedBit)
      val data =
        if hardened then byte 0 ^ #key parent ^ ser32 i        (* 0x00 || ser256(k_par) || ser32(i) *)
        else point (#key parent) ^ ser32 i                     (* serP(point(k_par)) || ser32(i) *)
      val iHmac = Hmac.hmacSha512 (#chainCode parent) data
      val il = String.substring (iHmac, 0, 32)
      val ir = String.substring (iHmac, 32, 32)
      val ilNum = parse256 il
      val ki = #2 (BigInt.divMod (BigInt.add (ilNum, parse256 (#key parent)), curveN))
    in
      if geN ilNum orelse isZero ki then raise InvalidKey
      else { depth = #depth parent + 1, parentFp = fingerprintPrv parent,
             childNumber = i, chainCode = ir, key = ser256 ki }
    end

  fun neuter (p : xprv) : xpub =
    { depth = #depth p, parentFp = #parentFp p, childNumber = #childNumber p,
      chainCode = #chainCode p, pubKey = point (#key p) }

  (* ---------------------------------------------------------------- *)
  (* Path parsing: "m/44'/0'/0'/0/0" (h/H/' all mark hardened)        *)
  (* ---------------------------------------------------------------- *)

  fun derivePath (root : xprv, path : string) : xprv =
    let
      val toks = String.tokens (fn c => c = #"/") path
      val toks =
        case toks of
          (h :: t) => if h = "m" orelse h = "M" then t else toks
        | []       => []

      fun parseIndex tok =
        let
          val n = String.size tok
          val (numStr, hard) =
            if n > 0 then
              let val last = String.sub (tok, n - 1) in
                if last = #"'" orelse last = #"h" orelse last = #"H"
                then (String.substring (tok, 0, n - 1), true)
                else (tok, false)
              end
            else (tok, false)
          val () = if numStr = "" orelse not (CharVector.all Char.isDigit numStr)
                   then raise InvalidPath path else ()
          val v = (case Int.fromString numStr of
                     SOME v => v | NONE => raise InvalidPath path)
                  handle Overflow => raise InvalidPath path
          (* indices are 0 .. 2^31 - 1 (the hardened flag is added separately) *)
          val () = if v < 0 orelse v > 2147483647 then raise InvalidPath path else ()
          val w = Word32.fromInt v
        in
          if hard then Word32.orb (w, hardenedBit) else w
        end
    in
      List.foldl (fn (tok, acc) => ckdPriv (acc, parseIndex tok)) root toks
    end

  (* ---------------------------------------------------------------- *)
  (* Serialization / addresses                                        *)
  (* ---------------------------------------------------------------- *)

  fun serializePrv (x : xprv) =
    String.concat [ verPrv, byte (#depth x), #parentFp x, ser32 (#childNumber x),
                    #chainCode x, byte 0, #key x ]

  fun serializePub (x : xpub) =
    String.concat [ verPub, byte (#depth x), #parentFp x, ser32 (#childNumber x),
                    #chainCode x, #pubKey x ]

  fun xprvToBase58 x = Base58.encodeCheck (serializePrv x)
  fun xpubToBase58 x = Base58.encodeCheck (serializePub x)

  (* deser32: 4-byte big-endian string slice -> Word32. *)
  fun deser32 (s : string) : Word32.word =
    let
      fun at k = Word32.fromInt (Char.ord (String.sub (s, k)))
    in
      Word32.orb (Word32.<< (at 0, 0w24),
        Word32.orb (Word32.<< (at 1, 0w16),
          Word32.orb (Word32.<< (at 2, 0w8), at 3)))
    end

  (* Common 78-byte field layout: ver(4) depth(1) parentFp(4) childNumber(4)
     chainCode(32) keyData(33). Returns the shared fields plus the keyData. *)
  fun parseSerialized (expectedVer : string) (raw : string) =
    if String.size raw <> 78 then NONE
    else if String.substring (raw, 0, 4) <> expectedVer then NONE
    else
      SOME { depth       = Char.ord (String.sub (raw, 4)),
             parentFp    = String.substring (raw, 5, 4),
             childNumber = deser32 (String.substring (raw, 9, 4)),
             chainCode   = String.substring (raw, 13, 32),
             keyData     = String.substring (raw, 45, 33) }

  fun xprvFromBase58 (s : string) : xprv option =
    case Base58.decodeCheck s of
      NONE => NONE
    | SOME raw =>
        (case parseSerialized verPrv raw of
           NONE => NONE
         | SOME f =>
             if Char.ord (String.sub (#keyData f, 0)) <> 0 then NONE
             else SOME { depth = #depth f, parentFp = #parentFp f,
                         childNumber = #childNumber f, chainCode = #chainCode f,
                         key = String.substring (#keyData f, 1, 32) })

  fun xpubFromBase58 (s : string) : xpub option =
    case Base58.decodeCheck s of
      NONE => NONE
    | SOME raw =>
        (case parseSerialized verPub raw of
           NONE => NONE
         | SOME f =>
             SOME { depth = #depth f, parentFp = #parentFp f,
                    childNumber = #childNumber f, chainCode = #chainCode f,
                    pubKey = #keyData f })

  fun toAddressP2PKH (x : xpub) =
    Base58.encodeCheck (byte 0 ^ hash160 (#pubKey x))
end
