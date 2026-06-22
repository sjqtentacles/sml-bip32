# sml-bip32 build
#
#   make            build the test binary with MLton (default)
#   make test       build + run tests under MLton
#   make test-poly  run tests under Poly/ML (use-and-run; no link step)
#   make all-tests  run the suite under both compilers
#   make example    build + run the demo (mnemonic -> seed -> HD address)
#   make clean      remove build artifacts
#
# Layout B (dependent): own sources live in src/; the dependency trees are
# vendored under lib/ and loaded in dependency order. The diamond on sml-codec
# is broken by pulling codec/crypto in along the single sml-secp256k1 path (see
# src/bip32.mlb); the Poly/ML use-chain mirrors that ordering by hand.

MLTON      ?= mlton
POLY       ?= poly
BIN        := bin

CODECDIR   := lib/github.com/sjqtentacles/sml-codec
CRYPTODIR  := lib/github.com/sjqtentacles/sml-crypto
SECPDIR    := lib/github.com/sjqtentacles/sml-secp256k1
BIGINTDIR  := lib/github.com/sjqtentacles/sml-bigint
RIPEMDDIR  := lib/github.com/sjqtentacles/sml-ripemd160
BASE58DIR  := lib/github.com/sjqtentacles/sml-base58
BIP39DIR   := lib/github.com/sjqtentacles/sml-bip39

TEST_MLB   := test/test.mlb
SRCS       := $(wildcard $(CODECDIR)/* $(CRYPTODIR)/* $(SECPDIR)/* $(BIGINTDIR)/* \
                         $(RIPEMDDIR)/* $(BASE58DIR)/* $(BIP39DIR)/* src/* test/*.sml) $(TEST_MLB)

.PHONY: all test poly test-poly all-tests example clean

all: $(BIN)/test-mlton

example: $(BIN)/demo
	./$(BIN)/demo

$(BIN)/demo: $(SRCS) examples/demo.sml examples/sources.mlb | $(BIN)
	$(MLTON) -output $@ examples/sources.mlb

$(BIN)/test-mlton: $(SRCS) | $(BIN)
	$(MLTON) -output $@ $(TEST_MLB)

test: $(BIN)/test-mlton
	$(BIN)/test-mlton

# Poly/ML has no native .mlb support; load each vendored source in dependency
# order (codec -> crypto -> secp256k1; bigint; ripemd160; base58), then the
# bip32 sources, then the test driver. The suite exits on its own.
poly test-poly:
	printf 'use "$(CODECDIR)/base16.sig";\nuse "$(CODECDIR)/base16.sml";\nuse "$(CODECDIR)/sha1.sig";\nuse "$(CODECDIR)/sha1.sml";\nuse "$(CODECDIR)/sha256.sig";\nuse "$(CODECDIR)/sha256.sml";\nuse "$(CODECDIR)/sha512.sig";\nuse "$(CODECDIR)/sha512.sml";\nuse "$(CRYPTODIR)/hmac.sig";\nuse "$(CRYPTODIR)/hmac.sml";\nuse "$(SECPDIR)/secp256k1.sig";\nuse "$(SECPDIR)/secp256k1.sml";\nuse "$(BIGINTDIR)/bigint.sig";\nuse "$(BIGINTDIR)/bigint.sml";\nuse "$(RIPEMDDIR)/ripemd160.sig";\nuse "$(RIPEMDDIR)/ripemd160.sml";\nuse "$(BASE58DIR)/base58.sig";\nuse "$(BASE58DIR)/base58.sml";\nuse "src/bip32.sig";\nuse "src/bip32.sml";\nuse "test/harness.sml";\nuse "test/support.sml";\nuse "test/test_vectors.sml";\nuse "test/test_derivation.sml";\nuse "test/entry.sml";\nuse "test/main.sml";\n' | $(POLY) -q --error-exit

all-tests: test test-poly

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -f $(BIN)/test-mlton $(BIN)/demo
