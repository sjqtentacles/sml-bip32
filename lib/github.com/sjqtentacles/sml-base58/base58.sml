(* base58.sml

   Big-endian byte string <-> Base58 via IntInf (available and identical on
   both MLton and Poly/ML). Base58Check layers a 4-byte double-SHA256 checksum
   on top, using the vendored `Sha256.digest`. *)

structure Base58 :> BASE58 =
struct
  val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  val base = 58

  (* Reverse lookup table: char code -> alphabet index, or ~1 if absent. *)
  val decodeTable =
    let
      val t = Array.array (256, ~1)
      val () =
        Vector.appi
          (fn (i, c) => Array.update (t, ord c, i))
          (Vector.tabulate (String.size alphabet,
                            fn i => String.sub (alphabet, i)))
    in
      t
    end

  fun indexOf c =
    let val i = Array.sub (decodeTable, ord c) in
      if i < 0 then NONE else SOME i
    end

  fun countLeading pred s =
    let
      val n = String.size s
      fun loop i = if i < n andalso pred (String.sub (s, i)) then loop (i + 1) else i
    in
      loop 0
    end

  fun repeatChar (c, n) = String.implode (List.tabulate (n, fn _ => c))

  val zero = IntInf.fromInt 0
  val biBase = IntInf.fromInt base
  val bi256 = IntInf.fromInt 256

  fun encode s =
    let
      val zeros = countLeading (fn c => c = #"\000") s
      (* big-endian bytes -> integer *)
      val n =
        CharVector.foldl
          (fn (c, acc) => IntInf.+ (IntInf.* (acc, bi256), IntInf.fromInt (ord c)))
          zero s
      fun digits (m, acc) =
        if m = zero then acc
        else
          let
            val q = IntInf.div (m, biBase)
            val r = IntInf.toInt (IntInf.mod (m, biBase))
          in
            digits (q, String.sub (alphabet, r) :: acc)
          end
      val body = String.implode (digits (n, []))
    in
      repeatChar (#"1", zeros) ^ body
    end

  fun decode s =
    let
      val ones = countLeading (fn c => c = #"1") s
      (* fold every character into the accumulator; invalid chars abort. *)
      fun loop (i, acc) =
        if i >= String.size s then SOME acc
        else
          case indexOf (String.sub (s, i)) of
            NONE => NONE
          | SOME d => loop (i + 1, IntInf.+ (IntInf.* (acc, biBase), IntInf.fromInt d))
    in
      case loop (0, zero) of
        NONE => NONE
      | SOME n =>
          let
            fun bytes (m, acc) =
              if m = zero then acc
              else
                let
                  val q = IntInf.div (m, bi256)
                  val r = IntInf.toInt (IntInf.mod (m, bi256))
                in
                  bytes (q, chr r :: acc)
                end
            val body = String.implode (bytes (n, []))
          in
            SOME (repeatChar (#"\000", ones) ^ body)
          end
    end

  fun checksum payload =
    String.substring (Sha256.digest (Sha256.digest payload), 0, 4)

  fun encodeCheck payload = encode (payload ^ checksum payload)

  fun decodeCheck s =
    case decode s of
      NONE => NONE
    | SOME bytes =>
        let val n = String.size bytes in
          if n < 4 then NONE
          else
            let
              val payload = String.substring (bytes, 0, n - 4)
              val given   = String.substring (bytes, n - 4, 4)
            in
              if given = checksum payload then SOME payload else NONE
            end
        end
end
