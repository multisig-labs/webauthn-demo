# Justfiles are better Makefiles (Don't @ me)
# Install the `just` command from here https://github.com/casey/just
# or `cargo install just` or `brew install just`
# https://cheatography.com/linux-china/cheat-sheets/justfile/

# Build vars for versioning the binary
VERSION := `grep "const Version " pkg/version/version.go | sed -E 's/.*"(.+)"$$/\1/'`
GIT_COMMIT := `git rev-parse HEAD`
BUILD_DATE := `date '+%Y-%m-%d'`
VERSION_PATH := "github.com/multisig-labs/webauthn-demo/pkg/version"
LDFLAGS := "-X " + VERSION_PATH + ".BuildDate=" + BUILD_DATE + " -X " + VERSION_PATH + ".Version=" + VERSION + " -X " + VERSION_PATH + ".GitCommit=" + GIT_COMMIT

export ETH_RPC_URL := env_var_or_default("ETH_RPC_URL", "http://127.0.0.1:9650")
export MNEMONIC := env_var_or_default("MNEMONIC", "test test test test test test test test test test test junk")
# First key from MNEMONIC
export PRIVATE_KEY := env_var_or_default("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

# Autoload a .env if one exists
set dotenv-load

# Print out some help
default:
	@just --list --unsorted

# Install dependencies
install:

# Build
build:
	sqlc generate
	go build -ldflags "{{LDFLAGS}}" -o bin/webauthn main.go

# Cleanup
clean:
	rm -rf bin
	rm -rf webauthn.db
	rm -rf webauthn.db-shm
	rm -rf webauthn.db-wal
	rm -rf webauthn

# Run the server
serve:
	./bin/webauthn serve

# GET /balance?address={{address}}
get-addr address:
	curl "http://localhost:8000/balance?address={{address}}"

# Run dummy transfer tests
dummy-test:
	@echo "Checking initial dummy balances..."
	curl "http://localhost:8000/balance?address=dummyAddr1"
	curl "http://localhost:8000/balance?address=dummyAddr2"
	@echo "\nTransfering 10 from dummyAddr1 to dummyAddr2..."
	curl -X POST "http://localhost:8000/transfer" -H "Content-Type: application/json" -d '{"from_address": "dummyAddr1", "to_address": "dummyAddr2", "amount": 10, "tx_hash": "0x123456789", "sig": "SIG"}'
	@echo "\nVerifying final dummy balances..."
	curl "http://localhost:8000/balance?address=dummyAddr1"
	curl "http://localhost:8000/balance?address=dummyAddr2"

# Check if there is an http(s) server listening on [url]
_ping url:
	@if ! curl -k --silent --connect-timeout 2 {{url}} >/dev/null 2>&1; then echo 'No server at {{url}}!' && exit 1; fi
