(* test_derivation.sml -- properties of the derivation primitives:
   ckdPriv vs derivePath, hardened-index handling, neuter/address shape,
   the raw/hex seed equivalence, and path-parsing errors. *)

structure DerivationTests =
struct
  open Support

  val hardened : Word32.word = 0wx80000000

  fun run () =
    let
      val () = Harness.section "masterFromSeed: raw vs hex"
      val seedHex = #seed tv1
      val mRaw = B.masterFromSeed (hex seedHex)
      val mHex = B.masterFromSeedHex seedHex
      val () =
        Harness.checkString "raw seed == hex seed (xprv)"
          (B.xprvToBase58 mHex, B.xprvToBase58 mRaw)

      val () = Harness.section "derivePath m == master"
      val () =
        Harness.checkString "m is the master itself"
          (B.xprvToBase58 mHex, B.xprvToBase58 (B.derivePath (mHex, "m")))

      val () = Harness.section "ckdPriv builds the vector-1 chain step by step"
      (* m -> m/0' -> m/0'/1 -> m/0'/1/2' -> .../2 -> .../1000000000 *)
      val n0 = B.ckdPriv (mHex, hardened)                 (* m/0'  *)
      val n1 = B.ckdPriv (n0, 0w1)                        (* m/0'/1 *)
      val n2 = B.ckdPriv (n1, Word32.orb (0w2, hardened)) (* m/0'/1/2' *)
      val n3 = B.ckdPriv (n2, 0w2)                        (* m/0'/1/2'/2 *)
      val n4 = B.ckdPriv (n3, 0w1000000000)              (* .../1000000000 *)
      val expect = #nodes tv1
      fun nth k = List.nth (expect, k)
      val () = Harness.checkString "ckdPriv m/0'" (#xprv (nth 1), B.xprvToBase58 n0)
      val () = Harness.checkString "ckdPriv m/0'/1" (#xprv (nth 2), B.xprvToBase58 n1)
      val () = Harness.checkString "ckdPriv m/0'/1/2'" (#xprv (nth 3), B.xprvToBase58 n2)
      val () = Harness.checkString "ckdPriv m/0'/1/2'/2" (#xprv (nth 4), B.xprvToBase58 n3)
      val () = Harness.checkString "ckdPriv .../1000000000" (#xprv (nth 5), B.xprvToBase58 n4)

      val () = Harness.section "hardened index notations agree"
      (* "0'", "0h", "0H" all mean index 0 + 2^31. *)
      val a = B.xprvToBase58 (B.derivePath (mHex, "m/0'"))
      val b = B.xprvToBase58 (B.derivePath (mHex, "m/0h"))
      val c = B.xprvToBase58 (B.derivePath (mHex, "m/0H"))
      val () = Harness.checkString "0' == 0h" (a, b)
      val () = Harness.checkString "0' == 0H" (a, c)
      val () = Harness.checkString "ckdPriv hardened == derivePath 0'"
                 (a, B.xprvToBase58 (B.ckdPriv (mHex, hardened)))

      val () = Harness.section "neuter / address shape"
      val pub = B.neuter mHex
      val addr = B.toAddressP2PKH pub
      val () = Harness.checkBool "P2PKH address starts with '1'"
                 (true, String.size addr > 0 andalso String.sub (addr, 0) = #"1")
      val () = Harness.checkString "master address == vector"
                 (valOf (#addr (nth 0)), addr)

      val () = Harness.section "derivePath rejects malformed paths"
      val () = Harness.checkRaises "non-numeric component" (fn () => B.derivePath (mHex, "m/abc"))
      val () = Harness.checkRaises "index out of range" (fn () => B.derivePath (mHex, "m/4294967296"))

      val () = Harness.section "Base58 decode round-trip"
      (* known BIP-32 vector-1 master xprv / xpub *)
      val xprv0 = #xprv (nth 0)
      val xpub0 = #xpub (nth 0)
      (* encode (decode s) = s on a known test vector *)
      val () = Harness.checkString "xprvFromBase58 then re-encode == xprv"
                 (xprv0, B.xprvToBase58 (valOf (B.xprvFromBase58 xprv0)))
      val () = Harness.checkString "xpubFromBase58 then re-encode == xpub"
                 (xpub0, B.xpubToBase58 (valOf (B.xpubFromBase58 xpub0)))
      (* full chain: encode (decode (encode k)) = encode k for a derived node *)
      val k = B.derivePath (mHex, "m/0'/1/2'")
      val () = Harness.checkString "decode(encode xprv) round-trip on derived node"
                 (B.xprvToBase58 k,
                  B.xprvToBase58 (valOf (B.xprvFromBase58 (B.xprvToBase58 k))))
      val () = Harness.checkString "decode(encode xpub) round-trip on derived node"
                 (B.xpubToBase58 (B.neuter k),
                  B.xpubToBase58 (valOf (B.xpubFromBase58 (B.xpubToBase58 (B.neuter k)))))
      (* malformed / mismatched inputs -> NONE *)
      val () = Harness.checkBool "xprvFromBase58 of an xpub = NONE (wrong version)"
                 (true, not (Option.isSome (B.xprvFromBase58 xpub0)))
      val () = Harness.checkBool "xpubFromBase58 of an xprv = NONE (wrong version)"
                 (true, not (Option.isSome (B.xpubFromBase58 xprv0)))
      val () = Harness.checkBool "xprvFromBase58 of garbage = NONE"
                 (true, not (Option.isSome (B.xprvFromBase58 "not-valid-base58-0OIl")))
      val () = Harness.checkBool "xprvFromBase58 of truncated = NONE"
                 (true, not (Option.isSome (B.xprvFromBase58 (String.substring (xprv0, 0, 20)))))
    in
      ()
    end
end
