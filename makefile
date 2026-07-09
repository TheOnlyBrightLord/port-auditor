# Имя бинарника
BINARY_NAME=port-auditor
VERSION=1.0.0
BUILD_DIR=build

# Go команды
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Флаги сборки
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: all build clean test run fmt deps docker help

## all: Собрать бинарник (по умолчанию)
all: clean build

## build: Собрать бинарник для текущей ОС
build:
	@echo "🔨 Сборка $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/scanner
	@echo "✅ Готово: $(BUILD_DIR)/$(BINARY_NAME)"

## build-all: Собрать бинарники для всех платформ (Linux, macOS, Windows)
build-all:
	@echo "🌍 Кросс-компиляция для всех платформ..."
	@mkdir -p $(BUILD_DIR)
	
	@echo "📦 Linux amd64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/scanner
	
	@echo "📦 Linux arm64..."
	@GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/scanner
	
	@echo "📦 macOS amd64..."
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/scanner
	
	@echo "📦 macOS arm64 (M1/M2)..."
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/scanner
	
	@echo "📦 Windows amd64..."
	@GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/scanner
	
	@echo "✅ Все бинарники собраны в $(BUILD_DIR)/"

## run: Запустить сканер (пример для localhost)
run:
	@echo "🚀 Запуск сканера..."
	$(GOCMD) run ./cmd/scanner -target 127.0.0.1/32

## test: Запустить тесты
test:
	@echo "🧪 Запуск тестов..."
	$(GOTEST) -v ./...

## clean: Очистить собранные файлы
clean:
	@echo "🧹 Очистка..."
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f report.json report.html
	@echo "✅ Очищено"

## fmt: Форматировать код
fmt:
	@echo "🎨 Форматирование кода..."
	@$(GOFMT) ./...
	@echo "✅ Код отформатирован"

## deps: Обновить зависимости
deps:
	@echo "📦 Обновление зависимостей..."
	@$(GOMOD) tidy
	@$(GOMOD) download
	@echo "✅ Зависимости обновлены"

## docker-build: Собрать Docker-образ
docker-build:
	@echo "🐳 Сборка Docker-образа..."
	@docker build -t $(BINARY_NAME):$(VERSION) .
	@docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest
	@echo "✅ Образ готов: $(BINARY_NAME):$(VERSION)"

## docker-scan: Запустить сканирование в Docker
docker-scan:
	@echo "🐳 Запуск в Docker..."
	@docker run --rm --network host $(BINARY_NAME):latest -target 127.0.0.1/32

## install: Установить бинарник в GOPATH/bin
install: build
	@echo "📥 Установка в GOPATH..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "✅ Установлено. Теперь можно запускать: $(BINARY_NAME)"

## help: Показать эту справку
help:
	@echo "Port Auditor - сетевой сканер и аудитор безопасности"
	@echo ""
	@echo "Использование: make <цель>"
	@echo ""
	@echo "Доступные команды:"
	@sed -n 's/^##//p' Makefile | column -t -s ':' | sed -e 's/^/ /'