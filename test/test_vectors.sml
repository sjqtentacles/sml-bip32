(* test_vectors.sml -- the official BIP-32 test vectors (1-4).

   For every node: derive it from the master with derivePath, then check the
   Base58Check xprv, the neutered xpub, and (vectors 1 & 2) the P2PKH address
   byte-exact against the spec / canonical reference. *)

structure VectorTests =
struct
  open Support

  fun shortPath p = if String.size p <= 26 then p else String.substring (p, 0, 26) ^ "..."

  fun checkNode (master : B.xprv) ({ path, xprv, xpub, addr } : node) =
    let
      val k = B.derivePath (master, path)
      val () = Harness.checkString ("xprv " ^ shortPath path) (xprv, B.xprvToBase58 k)
      val pub = B.neuter k
      val () = Harness.checkString ("xpub " ^ shortPath path) (xpub, B.xpubToBase58 pub)
      val () =
        case addr of
          NONE => ()
        | SOME a => Harness.checkString ("addr " ^ shortPath path) (a, B.toAddressP2PKH pub)
    in
      ()
    end

  fun checkVector (name, { seed, nodes } : vector) =
    let
      val () = Harness.section ("BIP-32 " ^ name)
      val master = B.masterFromSeedHex seed
    in
      List.app (checkNode master) nodes
    end

  fun run () = List.app checkVector allVectors
end
