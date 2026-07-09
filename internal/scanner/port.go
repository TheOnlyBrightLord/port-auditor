package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// PortResult описывает результат сканирования одного порта
type PortResult struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Open     bool     `json:"open"`
	Service  string   `json:"service,omitempty"`
	Version  string   `json:"version,omitempty"`
	Risk     string   `json:"risk,omitempty"`
	SSL      *SSLInfo `json:"ssl,omitempty"`
	Duration float64  `json:"duration_ms"`
	Error    string   `json:"error,omitempty"`
}

// Общий таймаут на всю операцию: подключение + чтение баннера
const totalOperationTimeout = 4 * time.Second

func ScanPort(ctx context.Context, host string, port int) PortResult {
	address := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	// Создаем контекст с общим таймаутом для всей операции
	opCtx, cancel := context.WithTimeout(ctx, totalOperationTimeout)
	defer cancel()

	dialer := net.Dialer{
		Timeout: 2 * time.Second, // 2 секунды на подключение
	}

	conn, err := dialer.DialContext(opCtx, "tcp", address)
	if err != nil {
		return PortResult{
			Host:     host,
			Port:     port,
			Open:     false,
			Duration: float64(time.Since(start)) / float64(time.Millisecond), // ← вот здесь
			Error:    err.Error(),
		}
	}
	// Важно: закрываем соединение, даже если что-то пошло не так
	defer conn.Close()

	// Устанавливаем ЖЕСТКИЙ deadline на всё соединение
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	result := PortResult{
		Host:     host,
		Port:     port,
		Open:     true,
		Duration: float64(time.Since(start)) / float64(time.Millisecond), // ← и здесь
	}

	// Передаем контекст в GrabBanner для дополнительных проверок
	serviceInfo := GrabBanner(opCtx, conn, port)
	result.Service = serviceInfo.Name
	result.Version = serviceInfo.Version
	result.Risk = serviceInfo.Risk

	// ПРОВЕРКА SSL для HTTPS портов
	if port == 443 || port == 8443 {
		sslInfo := CheckSSL(opCtx, host, port)
		result.SSL = &sslInfo

		// Автоматические алерты
		if !sslInfo.Valid {
			result.Risk = "⚠️  SSL EXPIRED OR INVALID - CRITICAL"
		} else if sslInfo.DaysLeft < 30 {
			result.Risk = fmt.Sprintf("⚠️  SSL EXPIRES IN %d DAYS", sslInfo.DaysLeft)
		} else if sslInfo.DaysLeft < 90 {
			result.Risk = fmt.Sprintf("⚠️  SSL EXPIRES IN %d DAYS (plan renewal)", sslInfo.DaysLeft)
		}

		// Проверка слабых протоколов
		if sslInfo.Protocol == "TLS 1.0 ⚠️ INSECURE" || sslInfo.Protocol == "TLS 1.1 ⚠️ INSECURE" {
			if result.Risk != "" {
				result.Risk += " | " + sslInfo.Protocol
			} else {
				result.Risk = sslInfo.Protocol
			}
		}
	}

	return result
}
