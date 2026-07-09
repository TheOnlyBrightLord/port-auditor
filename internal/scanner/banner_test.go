package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockConn имитирует сетевое соединение для тестов
type mockConn struct {
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, nil
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error        { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestDetectSSH(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantVersion string
	}{
		{
			name:        "OpenSSH 8.9",
			banner:      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
			wantName:    "SSH",
			wantVersion: "8.9p1",
		},
		{
			name:        "Dropbear",
			banner:      "SSH-2.0-dropbear_2022.83\r\n",
			wantName:    "SSH",
			wantVersion: "unknown",
		},
		{
			name:        "Empty banner",
			banner:      "",
			wantName:    "SSH",
			wantVersion: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: []byte(tt.banner)}
			ctx := context.Background()

			result := detectSSH(ctx, conn)

			if result.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", result.Name, tt.wantName)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

func TestDetectRedis(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantRisk bool
		wantName string
	}{
		{
			name:     "No password (PONG)",
			response: "+PONG\r\n",
			wantRisk: true,
			wantName: "Redis",
		},
		{
			name:     "Password protected",
			response: "-NOAUTH Authentication required.\r\n",
			wantRisk: false,
			wantName: "Redis",
		},
		{
			name:     "Unknown response",
			response: "-ERR unknown command\r\n",
			wantRisk: false,
			wantName: "Redis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: []byte(tt.response)}
			ctx := context.Background()

			result := detectRedis(ctx, conn)

			if result.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", result.Name, tt.wantName)
			}
			hasRisk := result.Risk != ""
			if hasRisk != tt.wantRisk {
				t.Errorf("Risk present = %v, want %v (risk=%q)", hasRisk, tt.wantRisk, result.Risk)
			}
		})
	}
}

func TestDetectMySQL(t *testing.T) {
	// Реальный MySQL greeting packet (упрощенный)
	// Формат: [length(3)] [seq(1)] [protocol_version(1)] [version_string\0] ...
	greeting := make([]byte, 100)
	greeting[0] = 50 // length
	greeting[4] = 10 // protocol version
	copy(greeting[5:], "8.0.32\x00")

	conn := &mockConn{readData: greeting}
	ctx := context.Background()

	result := detectMySQL(ctx, conn)

	if result.Name != "MySQL" {
		t.Errorf("Name = %q, want MySQL", result.Name)
	}
	if result.Version != "8.0.32" {
		t.Errorf("Version = %q, want 8.0.32", result.Version)
	}
}
