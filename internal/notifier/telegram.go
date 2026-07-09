package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TheOnlyBrightLord/port-auditor/internal/scanner"
)

type TelegramNotifier struct {
	botToken string
	chatID   string
	client   *http.Client
}

func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	// Увеличиваем таймаут до 30 секунд
	transport := &http.Transport{}

	// Поддержка прокси через переменные окружения
	if proxyURL := os.Getenv("HTTPS_PROXY"); proxyURL != "" {
		if proxy, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	} else if proxyURL := os.Getenv("HTTP_PROXY"); proxyURL != "" {
		if proxy, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}

	return &TelegramNotifier{
		botToken: botToken,
		chatID:   chatID,
		client: &http.Client{
			Timeout:   30 * time.Second, // Увеличили с 10 до 30 секунд
			Transport: transport,
		},
	}
}

func (t *TelegramNotifier) SendScanReport(target string, results []scanner.PortResult) error {
	if len(results) == 0 {
		return t.sendMessage(fmt.Sprintf("✅ <b>Сканирование %s</b>\n\nОткрытых портов не найдено", target))
	}

	var critical []scanner.PortResult
	var normal []scanner.PortResult

	for _, r := range results {
		if r.Risk != "" {
			critical = append(critical, r)
		} else {
			normal = append(normal, r)
		}
	}

	var msg strings.Builder

	if len(critical) > 0 {
		msg.WriteString(fmt.Sprintf("🚨 <b>Сканирование %s</b>\n\n", target))
		msg.WriteString(fmt.Sprintf("⚠️  <b>Найдено проблем: %d</b>\n\n", len(critical)))

		for _, r := range critical {
			msg.WriteString(fmt.Sprintf("<b>%s:%d</b> - %s\n", r.Host, r.Port, r.Service))
			if r.Version != "" {
				msg.WriteString(fmt.Sprintf("  Версия: %s\n", r.Version))
			}
			if r.SSL != nil {
				msg.WriteString(fmt.Sprintf("  SSL: %s (осталось %d дней)\n",
					r.SSL.Subject, r.SSL.DaysLeft))
			}
			msg.WriteString(fmt.Sprintf("  🚨 <code>%s</code>\n\n", r.Risk))
		}
	} else {
		msg.WriteString(fmt.Sprintf("✅ <b>Сканирование %s</b>\n\n", target))
		msg.WriteString("Проблем не обнаружено!\n\n")
	}

	msg.WriteString(fmt.Sprintf("<b>Открытые порты (%d):</b>\n", len(results)))
	for _, r := range normal {
		msg.WriteString(fmt.Sprintf("• %s:%d - %s", r.Host, r.Port, r.Service))
		if r.Version != "" && r.Version != "unknown" {
			msg.WriteString(" " + r.Version)
		}
		msg.WriteString("\n")
	}

	return t.sendMessage(msg.String())
}

// sendMessage с retry логикой (3 попытки)
func (t *TelegramNotifier) sendMessage(text string) error {
	const maxRetries = 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := t.sendMessageOnce(text)
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt < maxRetries {
			// Экспоненциальная задержка: 1с, 2с, 4с
			delay := time.Duration(1<<uint(attempt-1)) * time.Second
			fmt.Printf("⚠️  Попытка %d/%d не удалась: %v. Повтор через %v...\n",
				attempt, maxRetries, err, delay)
			time.Sleep(delay)
		}
	}

	return fmt.Errorf("все %d попытки не удались: %w", maxRetries, lastErr)
}

func (t *TelegramNotifier) sendMessageOnce(text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)

	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %w", err)
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("сетевая ошибка: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API вернул статус %d", resp.StatusCode)
	}

	return nil
}

func (t *TelegramNotifier) SendTestMessage() error {
	return t.sendMessage("🤖 <b>Port Auditor подключен!</b>\n\nТеперь вы будете получать уведомления о результатах сканирования.")
}
