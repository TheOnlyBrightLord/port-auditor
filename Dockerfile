# Stage 1: Сборка (multi-stage build)
FROM golang:1.22-alpine AS builder

# Устанавливаем git для зависимостей
RUN apk add --no-cache git

WORKDIR /app

# Копируем go.mod и go.sum для кэширования зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем статический бинарник
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /port-auditor ./cmd/scanner

# Stage 2: Минимальный образ для запуска
FROM alpine:latest

# Устанавливаем ca-certificates для HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /

# Копируем бинарник из builder
COPY --from=builder /port-auditor /port-auditor

# Создаём непривилегированного пользователя (security best practice)
RUN adduser -D -u 1000 scanner && \
    chown scanner:scanner /port-auditor
USER scanner

# Точка входа
ENTRYPOINT ["/port-auditor"]