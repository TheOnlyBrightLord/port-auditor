package scanner

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"
)

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Risk    string `json:"risk,omitempty"`
}

func GrabBanner(ctx context.Context, conn net.Conn, port int) ServiceInfo {
	// Проверяем, не отменён ли контекст
	select {
	case <-ctx.Done():
		return ServiceInfo{Name: "cancelled"}
	default:
	}

	switch port {
	case 22:
		return detectSSH(conn)
	case 80, 8080, 8000, 3000, 9200:
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		return detectHTTP(conn, host)
	case 443, 8443:
		return ServiceInfo{Name: "HTTPS"}
	case 3306:
		return detectMySQL(conn)
	case 5432:
		return detectPostgres(conn)
	case 6379:
		return detectRedis(conn)
	case 11211:
		return detectMemcached(conn)
	case 27017:
		return detectMongoDB(conn)
	default:
		return detectGeneric(conn)
	}
}

func detectSSH(conn net.Conn) ServiceInfo {
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil || len(banner) == 0 {
		return ServiceInfo{Name: "SSH"}
	}

	banner = strings.TrimSpace(banner)
	version := "unknown"

	if strings.Contains(banner, "OpenSSH") {
		parts := strings.Split(banner, "_")
		if len(parts) > 1 {
			version = strings.Split(parts[1], " ")[0]
		}
	}

	return ServiceInfo{
		Name:    "SSH",
		Version: version,
		Banner:  banner,
	}
}

func detectHTTP(conn net.Conn, host string) ServiceInfo {
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	request := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: PortAuditor\r\n\r\n"
	_, err := conn.Write([]byte(request))
	if err != nil {
		return ServiceInfo{Name: "HTTP"}
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	var response strings.Builder

	// Читаем только заголовки (до пустой строки)
	for i := 0; i < 20; i++ { // Максимум 20 строк
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		response.WriteString(line)
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	content := response.String()
	server := "unknown"

	lines := strings.Split(content, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			server = strings.TrimSpace(line[7:])
			break
		}
	}

	// Для Elasticsearch
	if strings.Contains(content, "cluster_name") || strings.Contains(content, "tagline") {
		return ServiceInfo{
			Name:    "Elasticsearch",
			Version: server,
			Risk:    "⚠️  Check authentication",
		}
	}

	return ServiceInfo{
		Name:    "HTTP",
		Version: server,
	}
}

func detectMySQL(conn net.Conn) ServiceInfo {
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	data := make([]byte, 1024)
	n, err := conn.Read(data)
	if err != nil || n < 5 {
		return ServiceInfo{Name: "MySQL"}
	}

	versionStart := 5
	versionEnd := versionStart

	for i := versionStart; i < n; i++ {
		if data[i] == 0 {
			versionEnd = i
			break
		}
	}

	version := "unknown"
	if versionEnd > versionStart {
		version = string(data[versionStart:versionEnd])
	}

	return ServiceInfo{
		Name:    "MySQL",
		Version: version,
	}
}

func detectPostgres(conn net.Conn) ServiceInfo {
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	sslRequest := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	_, err := conn.Write(sslRequest)
	if err != nil {
		return ServiceInfo{Name: "PostgreSQL"}
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	response := make([]byte, 1)
	n, err := conn.Read(response)

	if err == nil && n > 0 {
		// Tagged switch вместо if/else
		switch response[0] {
		case 'S':
			return ServiceInfo{Name: "PostgreSQL", Version: "SSL supported"}
		case 'N':
			return ServiceInfo{Name: "PostgreSQL", Version: "SSL not supported"}
		}
	}

	return ServiceInfo{Name: "PostgreSQL"}
}

func detectRedis(conn net.Conn) ServiceInfo {
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Write([]byte("PING\r\n"))
	if err != nil {
		return ServiceInfo{Name: "Redis"}
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	data := make([]byte, 256)
	n, err := conn.Read(data)
	if err != nil || n == 0 {
		return ServiceInfo{Name: "Redis"}
	}

	response := strings.TrimSpace(string(data[:n]))

	if response == "+PONG" {
		return ServiceInfo{
			Name: "Redis",
			Risk: "⚠️  NO PASSWORD - CRITICAL RISK",
		}
	}

	if strings.HasPrefix(response, "-NOAUTH") {
		return ServiceInfo{
			Name:    "Redis",
			Version: "password protected",
		}
	}

	return ServiceInfo{
		Name:   "Redis",
		Banner: response,
	}
}

func detectMemcached(conn net.Conn) ServiceInfo {
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Write([]byte("stats\r\n"))
	if err != nil {
		return ServiceInfo{Name: "Memcached"}
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	data := make([]byte, 256)
	n, err := conn.Read(data)
	if err != nil || n == 0 {
		return ServiceInfo{Name: "Memcached"}
	}

	if strings.HasPrefix(string(data[:n]), "STAT") {
		return ServiceInfo{
			Name: "Memcached",
			Risk: "⚠️  EXPOSED TO NETWORK - CRITICAL RISK",
		}
	}

	return ServiceInfo{Name: "Memcached"}
}

func detectMongoDB(conn net.Conn) ServiceInfo {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	data := make([]byte, 256)
	n, _ := conn.Read(data)
	if n > 0 {
		return ServiceInfo{
			Name: "MongoDB",
			Risk: "⚠️  Check authentication",
		}
	}
	return ServiceInfo{Name: "MongoDB"}
}

func detectGeneric(conn net.Conn) ServiceInfo {
	// Всего 500мс на чтение — если молчит, значит "silent service"
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	data := make([]byte, 256)
	n, _ := conn.Read(data)

	if n == 0 {
		return ServiceInfo{Name: "unknown (silent)"}
	}

	banner := string(data[:n])
	if len(banner) > 100 {
		banner = banner[:100]
	}

	banner = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '.'
		}
		return r
	}, banner)

	return ServiceInfo{
		Name:   "unknown",
		Banner: banner,
	}
}
