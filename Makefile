.PHONY: build run test clean generate proto sqlc migrate-up migrate-down migrate-create docker-up docker-down env-dev

# Build variables
BINARY_NAME=authservice
BUILD_DIR=bin

# Database
DB_URL=postgres://postgres:postgres@localhost:5432/authservice?sslmode=disable

# Build the application
build:
	@echo "Building..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Run the application
run:
	@go run ./cmd/server

# Run tests
test:
	@go test -v ./...

# Clean build artifacts
clean:
	@rm -rf $(BUILD_DIR)

# Generate all (proto + sqlc)
generate: proto sqlc

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/auth/auth.proto

# Generate sqlc files
sqlc:
	@echo "Generating sqlc files..."
	@cd db && sqlc generate

# Install dependencies
deps:
	@go mod tidy
	@go mod download

# Install tools
tools:
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Database migrations
migrate-up:
	@migrate -path migrations -database "$(DB_URL)" up

migrate-down:
	@migrate -path migrations -database "$(DB_URL)" down

migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir migrations -seq $$name

# Docker compose commands
docker-up:
	@docker-compose up -d

docker-down:
	@docker-compose down

docker-logs:
	@docker-compose logs -f

# Development setup
dev-setup: tools deps docker-up
	@sleep 3
	@make migrate-up
	@make generate

# Lint
lint:
	@golangci-lint run ./...

# Format code
fmt:
	@go fmt ./...

# Create ENV Copy
env-dev:
	@cp .env.example .env

# Help
help:
	@echo "Available commands:"
	@echo "  make build         - Build the application"
	@echo "  make run           - Run the application"
	@echo "  make test          - Run tests"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make generate      - Generate proto and sqlc files"
	@echo "  make proto         - Generate protobuf files"
	@echo "  make sqlc          - Generate sqlc files"
	@echo "  make deps          - Install Go dependencies"
	@echo "  make tools         - Install required tools"
	@echo "  make migrate-up    - Run database migrations up"
	@echo "  make migrate-down  - Run database migrations down"
	@echo "  make migrate-create- Create a new migration"
	@echo "  make docker-up     - Start docker containers"
	@echo "  make docker-down   - Stop docker containers"
	@echo "  make dev-setup     - Full development setup"
	@echo "  make lint          - Run linter"
	@echo "  make fmt           - Format code"
