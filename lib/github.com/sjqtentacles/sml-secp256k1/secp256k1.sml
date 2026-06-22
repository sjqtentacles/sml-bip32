(* secp256k1.sml

   ECDSA and Schnorr (BIP-340) over secp256k1 in pure Standard ML.

   All field and scalar arithmetic uses IntInf for portability and clarity;
   performance is secondary to correctness and dual-compiler (MLton + Poly/ML)
   support. Keys, hashes and signatures are raw byte strings. *)

structure Secp256k1 :> SECP256K1 =
struct
  (* ---------------------------------------------------------------- *)
  (* Curve parameters                                                 *)
  (* ---------------------------------------------------------------- *)

  fun ii (s : string) : IntInf.int =
    case IntInf.fromString s of
        SOME v => v
      | NONE   => raise Fail "bad integer literal"

  (* hex -> IntInf via base 16 *)
  fun hexToInt (s : string) : IntInf.int =
    let
      fun d c =
        if c >= #"0" andalso c <= #"9" then IntInf.fromInt (Char.ord c - 48)
        else if c >= #"a" andalso c <= #"f" then IntInf.fromInt (Char.ord c - 87)
        else if c >= #"A" andalso c <= #"F" then IntInf.fromInt (Char.ord c - 55)
        else raise Fail "bad hex"
    in
      List.foldl (fn (c, acc) => acc * 16 + d c) 0 (explode s)
    end

  val p  = hexToInt "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
  val n  = hexToInt "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  val gx = hexToInt "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
  val gy = hexToInt "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

  val scalarSize = 32
  val publicKeySize = 33

  (* ---------------------------------------------------------------- *)
  (* Byte / IntInf conversions (big-endian, fixed width)              *)
  (* ---------------------------------------------------------------- *)

  fun bytesToInt (s : string) : IntInf.int =
    List.foldl (fn (c, acc) => acc * 256 + IntInf.fromInt (Char.ord c)) 0 (explode s)

  (* big-endian fixed-width encoding into `len` bytes *)
  fun intToBytes (len : int) (v : IntInf.int) : string =
    let
      fun loop (0, _, acc) = acc
        | loop (k, x, acc) =
            let
              val byte = IntInf.toInt (IntInf.andb (x, 0xFF))
            in
              loop (k - 1, IntInf.~>> (x, 0w8), str (chr byte) ^ acc)
            end
    in
      loop (len, v, "")
    end

  (* ---------------------------------------------------------------- *)
  (* Modular arithmetic                                               *)
  (* ---------------------------------------------------------------- *)

  fun emod (a, m) =
    let val r = IntInf.mod (a, m)
    in if r < 0 then r + m else r end

  fun addm (a, b, m) = emod (a + b, m)
  fun subm (a, b, m) = emod (a - b, m)
  fun mulm (a, b, m) = emod (a * b, m)

  (* modular exponentiation *)
  fun powm (base, exp, m) =
    let
      fun loop (b, e, acc) =
        if e = 0 then acc
        else
          let
            val acc' = if IntInf.andb (e, 1) = 1 then mulm (acc, b, m) else acc
          in
            loop (mulm (b, b, m), IntInf.~>> (e, 0w1), acc')
          end
    in
      loop (emod (base, m), exp, 1)
    end

  (* modular inverse via Fermat: a^(m-2) mod m, m prime *)
  fun invm (a, m) = powm (a, m - 2, m)

  (* ---------------------------------------------------------------- *)
  (* Elliptic-curve point operations (affine, a = 0, b = 7)           *)
  (* ---------------------------------------------------------------- *)

  (* point is NONE = identity (point at infinity), or SOME (x, y) *)
  type point = (IntInf.int * IntInf.int) option

  val gP : point = SOME (gx, gy)

  fun isInf (p' : point) = not (Option.isSome p')

  fun pointEq (NONE, NONE) = true
    | pointEq (SOME (x1, y1), SOME (x2, y2)) = x1 = x2 andalso y1 = y2
    | pointEq _ = false

  fun pointDouble (NONE) = NONE
    | pointDouble (SOME (x, y)) =
        if y = 0 then NONE
        else
          let
            (* lambda = (3 x^2) / (2 y) *)
            val num = mulm (3, mulm (x, x, p), p)
            val den = invm (mulm (2, y, p), p)
            val lam = mulm (num, den, p)
            val x3 = subm (mulm (lam, lam, p), mulm (2, x, p), p)
            val y3 = subm (mulm (lam, subm (x, x3, p), p), y, p)
          in
            SOME (x3, y3)
          end

  fun pointAdd (NONE, q) = q
    | pointAdd (p', NONE) = p'
    | pointAdd (SOME (x1, y1), SOME (x2, y2)) =
        if x1 = x2 then
          (if emod (y1 + y2, p) = 0 then NONE          (* P + (-P) = inf *)
           else pointDouble (SOME (x1, y1)))           (* P + P *)
        else
          let
            val lam = mulm (subm (y2, y1, p), invm (subm (x2, x1, p), p), p)
            val x3 = subm (subm (mulm (lam, lam, p), x1, p), x2, p)
            val y3 = subm (mulm (lam, subm (x1, x3, p), p), y1, p)
          in
            SOME (x3, y3)
          end

  fun scalarMul (k : IntInf.int, pt : point) : point =
    let
      val k = emod (k, n)
      fun loop (e, addend, acc) =
        if e = 0 then acc
        else
          let
            val acc' = if IntInf.andb (e, 1) = 1 then pointAdd (acc, addend) else acc
          in
            loop (IntInf.~>> (e, 0w1), pointDouble addend, acc')
          end
    in
      loop (k, pt, NONE)
    end

  (* ---------------------------------------------------------------- *)
  (* Public-key derivation and encoding                               *)
  (* ---------------------------------------------------------------- *)

  fun pointToUncompressed (SOME (x, y)) =
        str (chr 4) ^ intToBytes 32 x ^ intToBytes 32 y
    | pointToUncompressed NONE = raise Fail "point at infinity"

  fun pointToCompressed (SOME (x, y)) =
        let val prefix = if emod (y, 2) = 0 then 2 else 3
        in str (chr prefix) ^ intToBytes 32 x end
    | pointToCompressed NONE = raise Fail "point at infinity"

  fun checkSk (sk : string) : IntInf.int =
    let val d = bytesToInt sk
    in if d <= 0 orelse d >= n then raise Fail "invalid secret key" else d end

  fun pubkeyPoint (sk : string) : point =
    scalarMul (checkSk sk, gP)

  fun pubkey sk = pointToCompressed (pubkeyPoint sk)
  fun pubkeyU sk = pointToUncompressed (pubkeyPoint sk)

  (* recover y from x and parity (p = 3 mod 4, so sqrt via (p+1)/4 power) *)
  fun liftX (x : IntInf.int) (wantOdd : bool) : IntInf.int =
    let
      val rhs = emod (mulm (mulm (x, x, p), x, p) + 7, p)   (* x^3 + 7 *)
      val y = powm (rhs, IntInf.div (p + 1, 4), p)
    in
      if mulm (y, y, p) <> rhs then raise Fail "x not on curve"
      else
        let val yIsOdd = emod (y, 2) = 1
        in if yIsOdd = wantOdd then y else emod (p - y, p) end
    end

  fun decompress (pkC : string) : string =
    if String.size pkC <> 33 then raise Fail "bad compressed length"
    else
      let
        val prefix = Char.ord (String.sub (pkC, 0))
        val x = bytesToInt (String.substring (pkC, 1, 32))
        val wantOdd =
          if prefix = 2 then false
          else if prefix = 3 then true
          else raise Fail "bad compressed prefix"
        val y = liftX x wantOdd
      in
        str (chr 4) ^ intToBytes 32 x ^ intToBytes 32 y
      end

  fun compress (pkU : string) : string =
    if String.size pkU <> 65 then raise Fail "bad uncompressed length"
    else if Char.ord (String.sub (pkU, 0)) <> 4 then raise Fail "bad uncompressed prefix"
    else
      let
        val x = bytesToInt (String.substring (pkU, 1, 32))
        val y = bytesToInt (String.substring (pkU, 33, 32))
        val prefix = if emod (y, 2) = 0 then 2 else 3
      in
        str (chr prefix) ^ intToBytes 32 x
      end

  (* parse a public key (33 compressed or 65 uncompressed) to a point *)
  fun parsePubkey (pk : string) : point =
    case String.size pk of
        33 =>
          let
            val u = decompress pk
            val x = bytesToInt (String.substring (u, 1, 32))
            val y = bytesToInt (String.substring (u, 33, 32))
          in SOME (x, y) end
      | 65 =>
          if Char.ord (String.sub (pk, 0)) <> 4 then raise Fail "bad pubkey prefix"
          else
            let
              val x = bytesToInt (String.substring (pk, 1, 32))
              val y = bytesToInt (String.substring (pk, 33, 32))
            in SOME (x, y) end
      | _ => raise Fail "bad pubkey length"

  (* ---------------------------------------------------------------- *)
  (* RFC 6979 deterministic nonce (HMAC-SHA256)                       *)
  (* ---------------------------------------------------------------- *)

  val zero32 = implode (List.tabulate (32, fn _ => chr 0))

  (* bits2int per RFC 6979: take leftmost qlen bits. Here hash and q are both
     256 bits, so this is just the integer value of the 32-byte input. *)
  fun rfc6979 (sk : IntInf.int) (msgHash : string) : IntInf.int =
    let
      val x = intToBytes 32 sk
      val h1 = msgHash    (* already 32 bytes *)
      (* step b/c: V = 0x01*32, K = 0x00*32 *)
      val V0 = implode (List.tabulate (32, fn _ => chr 1))
      val K0 = zero32
      (* step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) *)
      val K1 = Hmac.hmacSha256 K0 (V0 ^ str (chr 0) ^ x ^ h1)
      val V1 = Hmac.hmacSha256 K1 V0
      (* step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) *)
      val K2 = Hmac.hmacSha256 K1 (V1 ^ str (chr 1) ^ x ^ h1)
      val V2 = Hmac.hmacSha256 K2 V1
      fun gen (K, V) =
        let
          val V' = Hmac.hmacSha256 K V
          val candidate = bytesToInt V'
        in
          if candidate >= 1 andalso candidate < n then (candidate, K, V')
          else
            let
              val K' = Hmac.hmacSha256 K (V' ^ str (chr 0))
              val V'' = Hmac.hmacSha256 K' V'
            in gen (K', V'') end
        end
      val (k, _, _) = gen (K2, V2)
    in
      k
    end

  (* ---------------------------------------------------------------- *)
  (* DER encoding of (r, s)                                           *)
  (* ---------------------------------------------------------------- *)

  (* minimal big-endian encoding of a positive integer, with a leading 0x00
     if the top bit is set (DER signedness). *)
  fun derInt (v : IntInf.int) : string =
    let
      fun bytesOf (x, acc) =
        if x = 0 then acc
        else bytesOf (IntInf.~>> (x, 0w8),
                      str (chr (IntInf.toInt (IntInf.andb (x, 0xFF)))) ^ acc)
      val raw = if v = 0 then str (chr 0) else bytesOf (v, "")
      val raw = if Char.ord (String.sub (raw, 0)) >= 0x80
                then str (chr 0) ^ raw else raw
    in
      str (chr 0x02) ^ str (chr (String.size raw)) ^ raw
    end

  fun derEncode (r, s) =
    let
      val body = derInt r ^ derInt s
    in
      str (chr 0x30) ^ str (chr (String.size body)) ^ body
    end

  (* DER decode -> (r, s); minimal validation. *)
  fun derDecode (der : string) : (IntInf.int * IntInf.int) option =
    let
      fun byte i = Char.ord (String.sub (der, i))
    in
      if String.size der < 8 then NONE
      else if byte 0 <> 0x30 then NONE
      else
        let
          val totalLen = byte 1
        in
          if totalLen + 2 <> String.size der then NONE
          else if byte 2 <> 0x02 then NONE
          else
            let
              val rLen = byte 3
              val rStart = 4
              val r = bytesToInt (String.substring (der, rStart, rLen))
              val sTagPos = rStart + rLen
            in
              if byte sTagPos <> 0x02 then NONE
              else
                let
                  val sLen = byte (sTagPos + 1)
                  val sStart = sTagPos + 2
                  val s = bytesToInt (String.substring (der, sStart, sLen))
                in
                  SOME (r, s)
                end
            end
        end
    end handle _ => NONE

  (* ---------------------------------------------------------------- *)
  (* ECDSA                                                            *)
  (* ---------------------------------------------------------------- *)

  fun xOf (SOME (x, _)) = x
    | xOf NONE = raise Fail "point at infinity"

  fun ecdsaSign (sk : string) (msgHash : string) : string =
    let
      val d = checkSk sk
      val z = bytesToInt msgHash
      fun trySign () =
        let
          val k = rfc6979 d msgHash
          val R = scalarMul (k, gP)
          val r = emod (xOf R, n)
        in
          if r = 0 then raise Fail "retry"   (* astronomically unlikely *)
          else
            let
              val kinv = invm (k, n)
              val s = mulm (kinv, emod (z + mulm (r, d, n), n), n)
              val s = if s = 0 then raise Fail "retry" else s
              (* low-s normalization *)
              val s = if s > IntInf.div (n, 2) then n - s else s
            in
              derEncode (r, s)
            end
        end
    in
      trySign ()
    end

  fun ecdsaVerify (pk : string) (msgHash : string) (der : string) : bool =
    (case derDecode der of
         NONE => false
       | SOME (r, s) =>
           if r < 1 orelse r >= n orelse s < 1 orelse s >= n then false
           else
             let
               val Q = parsePubkey pk
               val z = bytesToInt msgHash
               val w = invm (s, n)
               val u1 = mulm (z, w, n)
               val u2 = mulm (r, w, n)
               val pt = pointAdd (scalarMul (u1, gP), scalarMul (u2, Q))
             in
               case pt of
                   NONE => false
                 | SOME (x, _) => emod (x, n) = r
             end)
    handle _ => false

  (* ---------------------------------------------------------------- *)
  (* Hex convenience (reuses the vendored Base16 codec)               *)
  (* ---------------------------------------------------------------- *)

  fun toHex (b : string) : string = Base16.encode b
  fun fromHex (s : string) : string option = Base16.decode s

  (* ---------------------------------------------------------------- *)
  (* Schnorr (BIP-340)                                                *)
  (* ---------------------------------------------------------------- *)

  fun taggedHash (tag : string) (msg : string) : string =
    let val th = Sha256.digest tag
    in Sha256.digest (th ^ th ^ msg) end

  (* x-only pubkey: 32-byte x of the point with even y *)
  fun schnorrSign (sk : string) (msg : string) : string =
    let
      val d0 = bytesToInt sk
      val () = if d0 < 1 orelse d0 >= n then raise Fail "invalid secret key" else ()
      val P = scalarMul (d0, gP)
      val (px, py) = case P of SOME pr => pr | NONE => raise Fail "inf"
      (* if P.y is odd, negate d *)
      val d = if emod (py, 2) = 0 then d0 else n - d0
      val pxBytes = intToBytes 32 px
      (* aux_rand = 0; t = d XOR tagged_hash("BIP0340/aux", aux_rand) *)
      val aux = zero32
      val tAux = taggedHash "BIP0340/aux" aux
      val dBytes = intToBytes 32 d
      val t = implode (ListPair.map
                (fn (a, b) => chr (Word.toInt (Word.xorb
                    (Word.fromInt (Char.ord a), Word.fromInt (Char.ord b)))))
                (explode dBytes, explode tAux))
      (* rand = tagged_hash("BIP0340/nonce", t || P.x || msg) *)
      val rand = taggedHash "BIP0340/nonce" (t ^ pxBytes ^ msg)
      val k0 = emod (bytesToInt rand, n)
      val () = if k0 = 0 then raise Fail "k0 = 0" else ()
      val R = scalarMul (k0, gP)
      val (rx, ry) = case R of SOME pr => pr | NONE => raise Fail "inf"
      val k = if emod (ry, 2) = 0 then k0 else n - k0
      val rxBytes = intToBytes 32 rx
      (* e = tagged_hash("BIP0340/challenge", R.x || P.x || msg) mod n *)
      val e = emod (bytesToInt (taggedHash "BIP0340/challenge" (rxBytes ^ pxBytes ^ msg)), n)
      val s = emod (k + mulm (e, d, n), n)
    in
      rxBytes ^ intToBytes 32 s
    end

  fun schnorrVerify (xonlyPk : string) (msg : string) (sig64 : string) : bool =
    (if String.size xonlyPk <> 32 orelse String.size sig64 <> 64 then false
     else
       let
         val px = bytesToInt xonlyPk
       in
         if px >= p then false
         else
           let
             val P = SOME (px, liftX px false)   (* P has even y *)
             val r = bytesToInt (String.substring (sig64, 0, 32))
             val s = bytesToInt (String.substring (sig64, 32, 32))
           in
             if r >= p orelse s >= n then false
             else
               let
                 val e = emod (bytesToInt (taggedHash "BIP0340/challenge"
                            (String.substring (sig64, 0, 32) ^ xonlyPk ^ msg)), n)
                 (* R = s*G - e*P *)
                 val R = pointAdd (scalarMul (s, gP), scalarMul (n - e, P))
               in
                 case R of
                     NONE => false
                   | SOME (rx, ry) =>
                       emod (ry, 2) = 0 andalso rx = r
               end
           end
       end)
    handle _ => false
end
