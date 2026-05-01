.PHONY: build run clean test install bench-up bench-down bench-logs bench-report bench-clean

BINARY=xalgorix
BUILD_DIR=./build
VERSION=4.2.0
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/xalgorix/
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

run:
	go run ./cmd/xalgorix/ $(ARGS)

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test ./... -v

install: build
	@echo "Installing $(BINARY) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "Installed!"

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
	@echo "Lint passed"

tidy:
	go mod tidy

all: tidy lint build

bench-up:
	docker compose -f testbench/docker-compose.yml up -d --build
	@echo "Testbench ready at http://127.0.0.1:8088"

bench-down:
	docker compose -f testbench/docker-compose.yml down

bench-logs:
	@mkdir -p testbench/logs
	tail -f testbench/logs/requests.log

bench-report:
	@mkdir -p testbench/logs
	python3 testbench/analyze/extract_commands.py $${SCAN_DIR:-$$HOME/xalgorix-data} > testbench/REPORT.md
	@echo "Wrote testbench/REPORT.md"

bench-clean:
	docker compose -f testbench/docker-compose.yml down -v || true
	rm -f testbench/logs/requests.log
