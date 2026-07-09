package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TheBrightLord/port-auditor/internal/config"
	"github.com/TheBrightLord/port-auditor/internal/notifier"
	"github.com/TheBrightLord/port-auditor/internal/reporter"
	"github.com/TheBrightLord/port-auditor/internal/scanner"
)

func main() {
	cidr := flag.String("target", "", "CIDR (напр. 192.168.1.0/24)")
	workers := flag.Int("workers", 0, "Параллельных воркеров (0 = из конфига)")
	output := flag.String("out", "", "JSON-файл отчета")
	htmlOutput := flag.String("html-out", "", "HTML-файл отчета")
	configPath := flag.String("config", "", "Путь к YAML-конфигу (по умолчанию configs/default.yaml)")

	// Флаги для Telegram
	tgToken := flag.String("tg-token", "", "Telegram Bot Token")
	tgChatID := flag.String("tg-chat", "", "Telegram Chat ID")

	flag.Parse()

	if *cidr == "" {
		fmt.Println("Использование: scanner -target 192.168.1.0/24 [-config configs/default.yaml]")
		os.Exit(1)
	}

	// Загрузка конфигурации
	var cfg *config.Config
	var err error

	cfgFile := *configPath
	if cfgFile == "" {
		cfgFile = "configs/default.yaml"
	}

	if _, statErr := os.Stat(cfgFile); statErr == nil {
		cfg, err = config.Load(cfgFile)
		if err != nil {
			log.Fatalf("Ошибка загрузки конфига %s: %v", cfgFile, err)
		}
		fmt.Printf("📄 Конфиг загружен: %s\n", cfgFile)
	} else {
		cfg = config.Default()
		fmt.Println("📄 Используется конфигурация по умолчанию")
	}

	// Флаг -workers переопределяет значение из конфига
	numWorkers := cfg.Defaults.Workers
	if *workers > 0 {
		numWorkers = *workers
	}

	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		log.Fatalf("Неверный CIDR: %v", err)
	}

	hosts := generateHosts(prefix)
	totalJobs := len(hosts) * len(cfg.Ports)
	fmt.Printf("🎯 Цель: %s\n", *cidr)
	fmt.Printf("📊 Хостов: %d | Портов: %d | Всего: %d\n",
		len(hosts), len(cfg.Ports), totalJobs)
	fmt.Printf("⚙️  Воркеров: %d\n\n", numWorkers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠️  Остановка...")
		cancel()
	}()

	pool := scanner.NewPool(numWorkers, totalJobs)
	pool.Start(ctx)

	go func() {
	outer:
		for _, host := range hosts {
			for _, port := range cfg.Ports {
				select {
				case <-ctx.Done():
					break outer
				default:
					pool.Submit(host.String(), port)
				}
			}
		}
		pool.Close()
		pool.Wait()
	}()

	progressDone := make(chan struct{})
	go showProgress(ctx, pool, progressDone)

	var openPorts []scanner.PortResult
	for result := range pool.Results() {
		if result.Open {
			openPorts = append(openPorts, result)

			line := fmt.Sprintf("✅ [OPEN] %s:%d (%.2fms) - %s",
				result.Host, result.Port, result.Duration, result.Service)

			if result.Version != "" && result.Version != "unknown" {
				line += " " + result.Version
			}

			if result.SSL != nil {
				line += fmt.Sprintf(" | SSL: %s (%s)", result.SSL.Subject, result.SSL.Protocol)
				if result.SSL.DaysLeft > 0 {
					line += fmt.Sprintf(" [%d days left]", result.SSL.DaysLeft)
				}
			}

			if result.Risk != "" {
				line += "\n   🚨 " + result.Risk
			}
			fmt.Println(line)
		}
	}

	cancel()
	<-progressDone

	// JSON-отчёт
	writeReport(*output, openPorts)

	// HTML-отчёт
	if *htmlOutput != "" {
		fmt.Println("\n🎨 Генерация HTML-отчета...")
		if err := reporter.GenerateHTMLReport(*htmlOutput, *cidr, openPorts); err != nil {
			fmt.Printf("⚠️  Ошибка создания HTML: %v\n", err)
		} else {
			fmt.Printf("✅ HTML-отчет сохранен: %s\n", *htmlOutput)
		}
	}

	// ОТПРАВКА В TELEGRAM
	if *tgToken != "" && *tgChatID != "" {
		fmt.Println("\n📱 Отправка уведомления в Telegram...")
		tg := notifier.NewTelegramNotifier(*tgToken, *tgChatID)

		if err := tg.SendTestMessage(); err != nil {
			fmt.Printf("⚠️  Ошибка Telegram: %v\n", err)
		} else {
			fmt.Println("✅ Тестовое сообщение отправлено!")
		}

		if err := tg.SendScanReport(*cidr, openPorts); err != nil {
			fmt.Printf("⚠️  Ошибка отправки отчета: %v\n", err)
		} else {
			fmt.Println("✅ Отчет отправлен в Telegram!")
		}
	}

	fmt.Println("✅ Сканирование завершено!")
}

func generateHosts(prefix netip.Prefix) []netip.Addr {
	var hosts []netip.Addr
	addr := prefix.Masked().Addr()
	for prefix.Contains(addr) {
		hosts = append(hosts, addr)
		addr = addr.Next()
	}
	return hosts
}

func showProgress(ctx context.Context, pool *scanner.Pool, done chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return
		case <-ticker.C:
			fmt.Printf("\r⏳ Прогресс: %.1f%%", pool.Progress()*100)
		}
	}
}

func writeReport(output string, results []scanner.PortResult) {
	if output == "" {
		return
	}
	data, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(output, data, 0644); err != nil {
		log.Fatalf("Ошибка записи JSON: %v", err)
	}
	fmt.Printf("💾 JSON-отчет сохранен: %s\n", output)
}
