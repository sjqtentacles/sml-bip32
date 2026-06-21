# sml-bip32

[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
hierarchical deterministic (HD) wallets in pure Standard ML — master key from
seed, child key derivation (`CKDpriv`, hardened + normal), neutering to extended
public keys, Base58Check `xprv`/`xpub` serialization, and P2PKH addresses. No
FFI, no external dependencies, and **deterministic**, byte-identically under
both [MLton](http://mlton.org/) and [Poly/ML](https://www.polyml.org/).

Built on the vendored sjqtentacles crypto/Bitcoin stack:
[`sml-secp256k1`](https://github.com/sjqtentacles/sml-secp256k1) (EC points),
[`sml-bigint`](https://github.com/sjqtentacles/sml-bigint) (scalar tweak),
[`sml-crypto`](https://github.com/sjqtentacles/sml-crypto) (HMAC-SHA512),
[`sml-codec`](https://github.com/sjqtentacles/sml-codec) (SHA-256),
[`sml-ripemd160`](https://github.com/sjqtentacles/sml-ripemd160) (hash160) and
[`sml-base58`](https://github.com/sjqtentacles/sml-base58) (Base58Check).

## Scope: private-tree derivation

This library implements the **private tree** that the official BIP-32 vectors
exercise:

```
master  ──►  CKDpriv (hardened + normal)  ──►  neuter at each node
```

The **public-parent `CKDpub`** function (deriving a child *xpub* from a parent
*xpub* without the private key) is intentionally **out of scope**: it requires
an elliptic-curve point addition `point(I_L) + K_par`, and the vendored
`sml-secp256k1` exposes only `pubkey` (scalar → point), not a tweak/point-add.
`CKDpub` is a documented follow-up that would add `tweakAdd` to
`sml-secp256k1`. Because `N(CKDpriv(x, i)) = CKDpub(N(x), i)` for non-hardened
`i`, every public key in the tree is still reachable here — via the private
tree, then `neuter`.

## Status

- 60 assertions, green on MLton and Poly/ML.
- Basis-library only; deterministic across compilers.
- Vendors the full dependency stack (Layout B), so the repo builds standalone.
- Validated against the **official BIP-32 test vectors 1–4** (seed → master
  `xprv`/`xpub`, then the derived chains such as `m/0'/1/2'/2/1000000000`):
  the Base58Check `xprv` and `xpub` are checked byte-exact at every node, the
  P2PKH addresses byte-exact at every node of vectors 1 & 2, and vectors 3 & 4
  pin down leading-zero retention.

## Install

With [`smlpkg`](https://github.com/diku-dk/smlpkg):

```
smlpkg add github.com/sjqtentacles/sml-bip32
smlpkg sync
```

Include the MLB from your own (it pulls in the vendored dependency stack):

```
local
  $(SML_LIB)/basis/basis.mlb
  lib/github.com/sjqtentacles/sml-bip32/... (via smlpkg)
in
  ...
end
```

This brings `structure Bip32` (and the vendored codec/crypto/secp256k1/...
structures) into scope.

## Quick start

```sml
(* seeds, keys, chain codes and addresses are raw byte strings: 1 byte/char *)

(* BIP-32 test vector 1 seed *)
val master = Bip32.masterFromSeedHex "000102030405060708090a0b0c0d0e0f"

val () = print (Bip32.xprvToBase58 master ^ "\n")
(* xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi *)

(* derive m/0'/1/2'/2/1000000000 *)
val node = Bip32.derivePath (master, "m/0'/1/2'/2/1000000000")
val pub  = Bip32.neuter node

val () = print (Bip32.xpubToBase58 pub ^ "\n")
(* xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy *)

val () = print (Bip32.toAddressP2PKH pub ^ "\n")
(* 1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam *)
```

Single-step derivation with `ckdPriv` (index is a `Word32.word`; values
`>= 0x80000000` are hardened):

```sml
val m0h = Bip32.ckdPriv (master, 0wx80000000)  (* m/0' *)
val m0h1 = Bip32.ckdPriv (m0h, 0w1)            (* m/0'/1 *)
```

## Demo

`make example` runs [`examples/demo.sml`](examples/demo.sml): a BIP-39 mnemonic
→ seed → BIP-32 master → BIP-44 `m/44'/0'/0'/0/0` → P2PKH address, end to end
(the mnemonic → seed step uses the vendored
[`sml-bip39`](https://github.com/sjqtentacles/sml-bip39)):

```
sml-bip32 demo
==============
mnemonic   : abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
passphrase : (none)

master xprv     : xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
master xpub     : xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8
master address  : 1BZ9j3F7m4H1RPyeDp5iFwpR31SB6zrs19

path            : m/44'/0'/0'/0/0
node xprv       : xprvA2cWYEXRrpaYZmR4Mat3aHw7ARSGFAtb5LQNfSuyQCCGVJXRNWA3zkkHZcBM4voi9TBrb9WaC65HGv5e8gZgfnjzH71WofaXT3haLw8LYqQ
node xpub       : xpub6Fbrwk4KhC8qnFVXTcR3wRsqiTGkedcSSZKyTqKaxXjFN6rZv3UJYZ4mQtjNYY3gCa181iCHSBWyWst2PFiXBKgLpFVSdcyLbHyAahin8pd
P2PKH address   : 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
```

`1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` is the well-known first receiving address
of the canonical `abandon … about` mnemonic.

## What's inside

| Function | Behavior |
| --- | --- |
| `masterFromSeed : string -> xprv` | master key from a raw seed: `I = HMAC-SHA512("Bitcoin seed", seed)`, `k = parse256(I_L)`, `c = I_R` |
| `masterFromSeedHex : string -> xprv` | as above, from a hex-encoded seed; raises `InvalidHex` |
| `ckdPriv : xprv * Word32.word -> xprv` | `CKDpriv`: child private key at index `i` (`i >= 0x80000000` is hardened) |
| `neuter : xprv -> xpub` | `N(.)`: the neutered (public) extended key |
| `derivePath : xprv * string -> xprv` | walk a path like `"m/44'/0'/0'/0/0"`; raises `InvalidPath` |
| `xprvToBase58 : xprv -> string` | 78-byte serialization, Base58Check (mainnet `0x0488ADE4`) |
| `xpubToBase58 : xpub -> string` | 78-byte serialization, Base58Check (mainnet `0x0488B21E`) |
| `toAddressP2PKH : xpub -> string` | mainnet P2PKH address: `Base58Check(0x00 ‖ RIPEMD160(SHA256(pubkey)))` |

### Conventions

- **Bytes as `string`.** Seeds, chain codes and keys are raw byte strings (one
  char per byte, 0–255), matching the rest of the sjqtentacles crypto/codec
  family. `masterFromSeedHex` converts a hex seed.
- **Hardened indices.** In `ckdPriv`, an index `>= 0x80000000` (= `2^31`) is
  hardened. In path strings, a trailing `'`, `h` or `H` marks a hardened
  component (`m/0'` ≡ `m/0h` ≡ `m/0H`).
- **Child scalar.** `k_i = (parse256(I_L) + k_par) mod n`, computed with the
  vendored `sml-bigint`; `n` is the secp256k1 group order. The astronomically
  unlikely invalid case (`parse256(I_L) >= n` or `k_i = 0`) raises `InvalidKey`.
- **Serialization.** The standard 78-byte structure (version ‖ depth ‖
  parent-fingerprint ‖ child-number ‖ chain-code ‖ key-data), Base58Check
  encoded. Parent fingerprints use the first 4 bytes of
  `RIPEMD160(SHA256(pubkey))`.

## Build & test

```
make test        # MLton
make test-poly   # Poly/ML
make all-tests   # both
make example     # build + run examples/demo.sml
make clean
```

## License

MIT — see [LICENSE](LICENSE).
