# Aegis - Security Analytics Engine
CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
SRC      = src/aegis.c
BIN      = build/aegis

.PHONY: all test demo bench debug clean
all: $(BIN)

$(BIN): $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: $(BIN)
	@printf 'T\n0\n' | $(BIN) | grep -E "tests passed|FAIL"

demo: $(BIN)
	@sh scripts/demo.sh

bench: $(BIN)
	@printf '8\n0\n' | $(BIN)

# AddressSanitizer + UBSan build for memory-safety checking
debug:
	@mkdir -p build
	$(CC) -std=c11 -g -O1 -Wall -Wextra -fsanitize=address,undefined -o build/aegis_asan $(SRC)
	@printf 'T\n0\n' | build/aegis_asan | grep -E "tests passed|FAIL|ERROR"

clean:
	rm -rf build results.csv
