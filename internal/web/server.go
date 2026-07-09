package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/TheOnlyBrightLord/port-auditor/internal/config"
	"github.com/TheOnlyBrightLord/port-auditor/internal/scanner"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed static/*
var staticFiles embed.FS

type ScanRequest struct {
	Target  string `json:"target"`
	Workers int    `json:"workers"`
}

type ScanEvent struct {
	Type     string              `json:"type"` // "progress", "result", "done", "error"
	Progress float64             `json:"progress,omitempty"`
	Result   *scanner.PortResult `json:"result,omitempty"`
	Message  string              `json:"message,omitempty"`
}

type ScanHistoryItem struct {
	ID        string               `json:"id"`
	Target    string               `json:"target"`
	Timestamp time.Time            `json:"timestamp"`
	Status    string               `json:"status"` // "running", "completed", "failed"
	Results   []scanner.PortResult `json:"results,omitempty"`
}

type Server struct {
	cfg      *config.Config
	router   chi.Router
	events   map[string]chan ScanEvent
	history  map[string]*ScanHistoryItem
	mu       sync.RWMutex
	scanning bool
}

func NewServer(cfg *config.Config) *Server {
	s := &Server{
		cfg:     cfg,
		events:  make(map[string]chan ScanEvent),
		history: make(map[string]*ScanHistoryItem),
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// API routes
	r.Post("/api/scan", s.handleStartScan)
	r.Get("/api/events/{id}", s.handleSSE)
	r.Get("/api/status", s.handleStatus)
	r.Get("/api/history", s.handleGetHistory)
	r.Get("/api/reports/{id}/download", s.handleDownloadReport)

	// Static files (embedded)
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	r.Handle("/*", fileServer)

	s.router = r
	return s
}

func (s *Server) Start(addr string) error {
	fmt.Printf("🌐 Web UI доступен по адресу: http://%s\n", addr)
	return http.ListenAndServe(addr, s.router)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"scanning": s.scanning})
}

func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []*ScanHistoryItem
	for _, item := range s.history {
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	s.mu.RLock()
	item, ok := s.history[id]
	s.mu.RUnlock()

	if !ok || item.Status != "completed" {
		http.Error(w, "Report not found or not ready", http.StatusNotFound)
		return
	}

	// Генерируем HTML отчет на лету
	filename := fmt.Sprintf("report-%s.html", id)

	// Создаем временный буфер для HTML
	// В реальном проекте лучше сохранять на диск, но для простоты генерируем в память
	// Используем reporter.GenerateHTMLReport, но он пишет в файл.
	// Для упрощения просто отдадим JSON или создадим простой HTML вручную.

	// Вариант 1: Отдать JSON
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item.Results)

	// Вариант 2 (сложнее): Сгенерировать HTML в буфер bytes.Buffer и отдать его.
	// Пока оставим JSON, так как reporter требует путь к файлу.
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if s.scanning {
		http.Error(w, "Сканирование уже запущено", http.StatusConflict)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		http.Error(w, "Target обязателен", http.StatusBadRequest)
		return
	}

	workers := req.Workers
	if workers <= 0 {
		workers = s.cfg.Defaults.Workers
	}

	eventID := fmt.Sprintf("scan-%d", time.Now().UnixNano())
	eventCh := make(chan ScanEvent, 100)

	// Создаем запись в истории
	historyItem := &ScanHistoryItem{
		ID:        eventID,
		Target:    req.Target,
		Timestamp: time.Now(),
		Status:    "running",
	}

	s.mu.Lock()
	s.events[eventID] = eventCh
	s.history[eventID] = historyItem
	s.scanning = true
	s.mu.Unlock()

	go s.runScan(req.Target, workers, eventCh, historyItem)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":     eventID,
		"status": "started",
	})
}

func (s *Server) runScan(target string, workers int, eventCh chan<- ScanEvent, historyItem *ScanHistoryItem) {
	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
		eventCh <- ScanEvent{Type: "done", Message: "Сканирование завершено"}
		close(eventCh)
	}()

	cfg := s.cfg
	prefix, err := parsePrefix(target)
	if err != nil {
		eventCh <- ScanEvent{Type: "error", Message: err.Error()}
		historyItem.Status = "failed"
		return
	}

	hosts := generateHosts(prefix)
	totalJobs := len(hosts) * len(cfg.Ports)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := scanner.NewPool(workers, totalJobs)
	pool.Start(ctx)

	go func() {
		for _, host := range hosts {
			for _, port := range cfg.Ports {
				select {
				case <-ctx.Done():
					break
				default:
					pool.Submit(host, port)
				}
			}
		}
		pool.Close()
		pool.Wait()
	}()

	// Отправляем прогресс
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				eventCh <- ScanEvent{
					Type:     "progress",
					Progress: pool.Progress(),
				}
			}
		}
	}()

	// Собираем результаты
	var results []scanner.PortResult
	for result := range pool.Results() {
		if result.Open {
			results = append(results, result)
			eventCh <- ScanEvent{
				Type:   "result",
				Result: &result,
			}
		}
	}

	cancel()

	// Сохраняем результаты в историю
	s.mu.Lock()
	historyItem.Status = "completed"
	historyItem.Results = results
	s.mu.Unlock()
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	s.mu.RLock()
	eventCh, ok := s.events[id]
	s.mu.RUnlock()

	if !ok {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for event := range eventCh {
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		if event.Type == "done" || event.Type == "error" {
			return
		}
	}
}

// Вспомогательные функции
func parsePrefix(cidr string) (netip.Prefix, error) {
	return netip.ParsePrefix(cidr)
}

func generateHosts(prefix netip.Prefix) []string {
	var hosts []string
	addr := prefix.Masked().Addr()
	for prefix.Contains(addr) {
		hosts = append(hosts, addr.String())
		addr = addr.Next()
	}
	return hosts
}
