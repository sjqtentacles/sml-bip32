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
    in
      ()
    end
end
