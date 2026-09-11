DB_NAME := incident_response
PSQL := PGPASSWORD=postgres psql -U postgres -h localhost

.PHONY: build run test seed agent eval eval-held-out server frontend db-create db-drop db-reset clean

build:
	cargo build

run:
	cargo run

test:
	cargo test --lib

seed:
	cargo run --bin seed

agent:
	cargo run --bin agent

eval:
	cargo run --bin eval

eval-held-out:
	cargo run --bin eval -- --held-out

server:
	cargo run --bin server

# Alias: the server binary serves both the API and the static frontend.
frontend: server

db-create:
	$(PSQL) -c "CREATE DATABASE $(DB_NAME);"

db-drop:
	$(PSQL) -c "DROP DATABASE IF EXISTS $(DB_NAME);"

db-reset: db-drop db-create seed

clean:
	cargo clean
