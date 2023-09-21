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

# Autoload a .env if one exists
set dotenv-load

# Print out some help
default:
	@just --list --unsorted

# Install dependencies
install:
	echo TODO

# Build
build:
	sqlc generate
	go build -ldflags "{{LDFLAGS}}" -o bin/webauthn main.go

# Cleanup
clean:
	rm -rf bin
	rm -rf data

# Delete and recreate a sqlite db
create-db:
	mkdir -p data
	rm -f data/webauthn.db*
	cat pkg/db/schema.sql | sqlite3 data/webauthn.db

# Run the server
serve:
	./bin/webauthn serve

fly-deploy:
  fly deploy --config fly.toml --app gogo-webauthn
