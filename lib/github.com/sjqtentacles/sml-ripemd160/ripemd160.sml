(* ripemd160.sml

   RIPEMD-160 over a byte string, all arithmetic on Word32.word so the usual
   32-bit wrap-around is automatic. Unlike the SHA family, RIPEMD-160 is
   little-endian: message words are read least-significant-byte first, the
   appended length is a little-endian 64-bit count, and the final state words
   are emitted little-endian. The compression function runs two parallel
   lines of five 16-step rounds and combines them at the end. Message length
   is tracked as an IntInf to support inputs beyond 2^29 bytes. *)

structure Ripemd160 :> RIPEMD160 =
struct
  type w = Word32.word
  val andb = Word32.andb
  val orb  = Word32.orb
  val xorb = Word32.xorb
  infix andb orb xorb
  fun << (a, b) = Word32.<< (a, b)
  fun >> (a, b) = Word32.>> (a, b)
  infix << >>
  val op ++ = Word32.+
  infix 6 ++

  fun notb x = Word32.xorb (x, 0wxFFFFFFFF)

  fun rotl (x, n : int) =
    if n = 0 then x
    else (x << Word.fromInt n) orb (x >> Word.fromInt (32 - n))

  (* Nonlinear round functions, selected by the round group 0..4. *)
  fun ff (0, x, y, z) = x xorb y xorb z
    | ff (1, x, y, z) = (x andb y) orb ((notb x) andb z)
    | ff (2, x, y, z) = (x orb (notb y)) xorb z
    | ff (3, x, y, z) = (x andb z) orb (y andb (notb z))
    | ff (_, x, y, z) = x xorb (y orb (notb z))

  (* Per-group additive constants for the left and right lines. *)
  val kl = Vector.fromList [0wx00000000, 0wx5A827999, 0wx6ED9EBA1, 0wx8F1BBCDC, 0wxA953FD4E]
  val kr = Vector.fromList [0wx50A28BE6, 0wx5C4DD124, 0wx6D703EF3, 0wx7A6D76E9, 0wx00000000]

  (* Message-word selection per step (left line / right line). *)
  val rl : int vector = Vector.fromList
    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
      7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
      3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
      1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
      4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13]
  val rr : int vector = Vector.fromList
    [ 5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
      6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
     15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
      8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
     12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11]

  (* Rotate-left amounts per step (left line / right line). *)
  val sl : int vector = Vector.fromList
    [11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
      7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
     11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
     11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
      9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6]
  val sr : int vector = Vector.fromList
    [ 8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
      9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
      9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
     15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
      8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11]

  (* Pad the message per the spec and return a list of 32-bit little-endian
     words (each block is 16 words). *)
  fun padded (msg : string) : Word32.word list =
    let
      val len = String.size msg
      val bitLen = IntInf.fromInt len * 8
      val withOne = msg ^ String.str (Char.chr 0x80)
      val padZeros : int =
        let val m = String.size withOne mod 64
        in if m <= 56 then 56 - m else 120 - m end
      val zeros = String.implode (List.tabulate (padZeros, fn _ => Char.chr 0))
      fun lenByte (i : int) =
        Char.chr (IntInf.toInt (IntInf.andb (IntInf.~>> (bitLen, Word.fromInt (i * 8)), 0xFF)))
      val lenBytes = String.implode (List.map lenByte [0,1,2,3,4,5,6,7])
      val full = withOne ^ zeros ^ lenBytes
      val n = String.size full
      fun word (i : int) =
        let fun b (kk : int) = Word32.fromInt (Char.ord (String.sub (full, i + kk)))
        in (b 0) orb (b 1 << 0w8) orb (b 2 << 0w16) orb (b 3 << 0w24) end
      fun loop (i : int) acc = if i >= n then List.rev acc else loop (i + 4) (word i :: acc)
    in
      loop 0 []
    end

  fun chunk16 ws =
    case ws of
        [] => []
      | _ =>
          let
            fun take 0 xs acc = (List.rev acc, xs)
              | take (j : int) (x :: xs) acc = take (j - 1) xs (x :: acc)
              | take _ [] acc = (List.rev acc, [])
            val (blk, rest) = take 16 ws []
          in blk :: chunk16 rest end

  fun processBlock ((h0,h1,h2,h3,h4), block) =
    let
      val x = Array.array (16, 0w0 : Word32.word)
      val _ = List.foldl (fn (v, i) => (Array.update (x, i, v); i + 1)) 0 block

      (* One line of 80 steps. `pick` chooses the round group (left: j div 16,
         right: 4 - j div 16); the schedule vectors carry everything else. *)
      fun line (rsel, ssel, ksel, pick) =
        let
          fun step (j, a, b, c, d, e) =
            if j >= 80 then (a, b, c, d, e)
            else
              let
                val g = pick j
                val t = rotl (a ++ ff (g, b, c, d)
                              ++ Array.sub (x, Vector.sub (rsel, j))
                              ++ Vector.sub (ksel, j div 16),
                              Vector.sub (ssel, j))
                        ++ e
              in
                step (j + 1, e, t, b, rotl (c, 10), d)
              end
        in
          step (0, h0, h1, h2, h3, h4)
        end

      val (al, bl, cl, dl, el) = line (rl, sl, kl, fn j => j div 16)
      val (ar, br, cr, dr, er) = line (rr, sr, kr, fn j => 4 - j div 16)
    in
      (h1 ++ cl ++ dr,
       h2 ++ dl ++ er,
       h3 ++ el ++ ar,
       h4 ++ al ++ br,
       h0 ++ bl ++ cr)
    end

  fun digestWords msg =
    let
      val blocks = chunk16 (padded msg)
      val init = (0wx67452301, 0wxEFCDAB89, 0wx98BADCFE, 0wx10325476, 0wxC3D2E1F0)
    in
      List.foldl (fn (blk, st) => processBlock (st, blk)) init blocks
    end

  fun wordBytes w =
    String.implode
      (List.map
        (fn (sh : int) => Char.chr (Word32.toInt ((w >> Word.fromInt sh) andb 0wxFF)))
        [0, 8, 16, 24])

  fun digest msg =
    let val (h0,h1,h2,h3,h4) = digestWords msg
    in String.concat (List.map wordBytes [h0,h1,h2,h3,h4]) end

  fun hexDigest msg = String.map Char.toLower
    (String.concat
      (List.map
        (fn c => StringCvt.padLeft #"0" 2 (Int.fmt StringCvt.HEX (Char.ord c)))
        (String.explode (digest msg))))
end
