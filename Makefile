DB_NAME := incident_response
PSQL := PGPASSWORD=postgres psql -U postgres -h localhost

.PHONY: build run test seed agent eval eval-held-out db-create db-drop db-reset clean

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

db-create:
	$(PSQL) -c "CREATE DATABASE $(DB_NAME);"

db-drop:
	$(PSQL) -c "DROP DATABASE IF EXISTS $(DB_NAME);"

db-reset: db-drop db-create seed

clean:
	cargo clean
