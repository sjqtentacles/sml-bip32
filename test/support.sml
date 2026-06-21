(* support.sml -- shared helpers + the official BIP-32 test vectors.

   Vectors 1-4 are taken verbatim from the BIP-32 specification
   (bitcoin/bips bip-0032.mediawiki). For each node we record the Base58Check
   xprv/xpub and, where the canonical reference lists it (vectors 1 and 2, from
   en.bitcoin.it/wiki/BIP_0032_TestVectors), the mainnet P2PKH address. Vectors
   3 and 4 exercise the retention of leading zeros in serialization. *)

structure Support =
struct
  structure B = Bip32

  fun hexDigit c =
    if c >= #"0" andalso c <= #"9" then ord c - ord #"0"
    else if c >= #"a" andalso c <= #"f" then ord c - ord #"a" + 10
    else if c >= #"A" andalso c <= #"F" then ord c - ord #"A" + 10
    else raise Fail ("bad hex digit: " ^ str c)

  (* hex string (even length) -> raw bytes *)
  fun hex s =
    let
      val cs = explode s
      fun loop [] = []
        | loop (a :: b :: rest) = chr (hexDigit a * 16 + hexDigit b) :: loop rest
        | loop [_] = raise Fail "odd-length hex"
    in
      String.implode (loop cs)
    end

  (* raw bytes -> lowercase hex *)
  fun toHex s =
    String.concat
      (List.map
         (fn c =>
            let val n = ord c
                fun d n = String.sub ("0123456789abcdef", n)
            in String.implode [d (n div 16), d (n mod 16)] end)
         (explode s))

  (* A node in the HD tree as the spec presents it. *)
  type node = { path : string, xprv : string, xpub : string, addr : string option }
  type vector = { seed : string (* hex *), nodes : node list }

  val tv1 : vector =
  { seed = "000102030405060708090a0b0c0d0e0f",
    nodes =
    [ { path = "m",
        xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        addr = SOME "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma" },
      { path = "m/0'",
        xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        addr = SOME "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh" },
      { path = "m/0'/1",
        xprv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        addr = SOME "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj" },
      { path = "m/0'/1/2'",
        xprv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        addr = SOME "1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x" },
      { path = "m/0'/1/2'/2",
        xprv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        xpub = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        addr = SOME "1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt" },
      { path = "m/0'/1/2'/2/1000000000",
        xprv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        addr = SOME "1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam" } ] }

  val tv2 : vector =
  { seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    nodes =
    [ { path = "m",
        xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        addr = SOME "1JEoxevbLLG8cVqeoGKQiAwoWbNYSUyYjg" },
      { path = "m/0",
        xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        addr = SOME "19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ" },
      { path = "m/0/2147483647'",
        xprv = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        xpub = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        addr = SOME "1Lke9bXGhn5VPrBuXgN12uGUphrttUErmk" },
      { path = "m/0/2147483647'/1",
        xprv = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        addr = SOME "1BxrAr2pHpeBheusmd6fHDP2tSLAUa3qsW" },
      { path = "m/0/2147483647'/1/2147483646'",
        xprv = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        addr = SOME "15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R" },
      { path = "m/0/2147483647'/1/2147483646'/2",
        xprv = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        xpub = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        addr = SOME "14UKfRV9ZPUp6ZC9PLhqbRtxdihW9em3xt" } ] }

  (* Vector 3 - retention of leading zeros (only m and m/0' are specified). *)
  val tv3 : vector =
  { seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    nodes =
    [ { path = "m",
        xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        addr = NONE },
      { path = "m/0'",
        xprv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        addr = NONE } ] }

  (* Vector 4 - retention of leading zeros. *)
  val tv4 : vector =
  { seed = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    nodes =
    [ { path = "m",
        xprv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        xpub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        addr = NONE },
      { path = "m/0'",
        xprv = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        xpub = "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        addr = NONE },
      { path = "m/0'/1'",
        xprv = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        xpub = "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
        addr = NONE } ] }

  val allVectors = [ ("vector 1", tv1), ("vector 2", tv2),
                     ("vector 3", tv3), ("vector 4", tv4) ]
end
