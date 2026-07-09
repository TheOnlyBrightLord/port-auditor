package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// SSLInfo содержит информацию о SSL-сертификате
type SSLInfo struct {
	Valid       bool      `json:"valid"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	DaysLeft    int       `json:"days_left,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// CheckSSL проверяет SSL-сертификат хоста
func CheckSSL(ctx context.Context, host string, port int) SSLInfo {
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	// TLS конфигурация с таймаутом и пропуском проверки сертификата
	// (нам нужно проверить даже самоподписанные)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	// Создаем контекст с таймаутом для TLS handshake
	tlsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Подключаемся по TLS
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return SSLInfo{
			Valid: false,
			Error: err.Error(),
		}
	}
	defer conn.Close()

	// Проверяем, не отменён ли контекст
	select {
	case <-tlsCtx.Done():
		return SSLInfo{Valid: false, Error: "timeout"}
	default:
	}

	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return SSLInfo{Valid: false, Error: "no certificates"}
	}

	cert := state.PeerCertificates[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	// Определяем валидность
	valid := true
	if daysLeft < 0 {
		valid = false
	}

	// Собираем SANs (Subject Alternative Names)
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return SSLInfo{
		Valid:       valid,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DaysLeft:    daysLeft,
		SANs:        sans,
		Protocol:    tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0 ⚠️ INSECURE"
	case tls.VersionTLS11:
		return "TLS 1.1 ⚠️ INSECURE"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3 ✓"
	default:
		return "Unknown"
	}
}
