package reporter

import (
	"html/template"
	"os"
	"time"

	"github.com/TheBrightLord/port-auditor/internal/scanner"
)

// Stats агрегированная статистика
type Stats struct {
	TotalPorts   int
	OpenPorts    int
	CriticalRisk int
	MediumRisk   int
	InfoRisk     int
	Services     map[string]int
}

// HTMLReport данные для шаблона
type HTMLReport struct {
	Target    string
	Timestamp time.Time
	Stats     Stats
	Results   []scanner.PortResult
}

// GenerateHTMLReport создаёт HTML-отчет
func GenerateHTMLReport(filename, target string, results []scanner.PortResult) error {
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	// Считаем статистику
	stats := Stats{
		TotalPorts: len(results),
		OpenPorts:  len(results),
		Services:   make(map[string]int),
	}

	for _, r := range results {
		stats.Services[r.Service]++
		if r.Risk != "" {
			stats.CriticalRisk++
		}
	}

	report := HTMLReport{
		Target:    target,
		Timestamp: time.Now(),
		Stats:     stats,
		Results:   results,
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, report)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Port Auditor Report - {{.Target}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f5f5; color: #333; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px;
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 0.9em; }
        .stats {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px; margin-bottom: 20px;
        }
        .stat-card {
            background: white; padding: 20px; border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { color: #666; font-size: 0.9em; }
        .stat-card.critical .number { color: #e74c3c; }
        .stat-card.info .number { color: #3498db; }
        .stat-card.success .number { color: #27ae60; }
        .card {
            background: white; padding: 25px; border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;
        }
        .card h2 { margin-bottom: 20px; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #555; }
        tr:hover { background: #f8f9fa; }
        .badge {
            display: inline-block; padding: 4px 10px; border-radius: 12px;
            font-size: 0.85em; font-weight: 500;
        }
        .badge.critical { background: #fee; color: #c33; border: 1px solid #fcc; }
        .badge.warning { background: #fff8e1; color: #d68910; border: 1px solid #ffe0b2; }
        .badge.info { background: #e3f2fd; color: #1976d2; border: 1px solid #bbdefb; }
        .badge.success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .service-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .service-tag {
            background: #ecf0f1; padding: 6px 12px; border-radius: 15px;
            font-size: 0.9em;
        }
        .risk-message {
            font-family: "Courier New", monospace; font-size: 0.9em;
            color: #c0392b; margin-top: 5px;
        }
        .no-issues {
            text-align: center; padding: 40px; color: #27ae60;
        }
        .no-issues::before { content: "✓ "; font-size: 1.5em; }
        .footer { text-align: center; padding: 20px; color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Auditor Report</h1>
            <div class="meta">
                Цель: <strong>{{.Target}}</strong> | 
                Дата: {{.Timestamp.Format "02.01.2006 15:04"}}
            </div>
        </div>

        <div class="stats">
            <div class="stat-card info">
                <div class="number">{{.Stats.OpenPorts}}</div>
                <div class="label">Открытых портов</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{{.Stats.CriticalRisk}}</div>
                <div class="label">Критических проблем</div>
            </div>
            <div class="stat-card success">
                <div class="number">{{len .Stats.Services}}</div>
                <div class="label">Разных сервисов</div>
            </div>
        </div>

        {{if .Stats.CriticalRisk}}
        <div class="card">
            <h2>🚨 Критические проблемы</h2>
            <table>
                <thead>
                    <tr>
                        <th>Хост:Порт</th>
                        <th>Сервис</th>
                        <th>Проблема</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Results}}
                    {{if .Risk}}
                    <tr>
                        <td><strong>{{.Host}}:{{.Port}}</strong></td>
                        <td>{{.Service}}{{if .Version}} <small>({{.Version}})</small>{{end}}</td>
                        <td><span class="badge critical">{{.Risk}}</span></td>
                    </tr>
                    {{end}}
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        <div class="card">
            <h2>📊 Обнаруженные сервисы</h2>
            <div class="service-list">
                {{range $service, $count := .Stats.Services}}
                <div class="service-tag">
                    <strong>{{$service}}</strong>: {{$count}} шт.
                </div>
                {{end}}
            </div>
        </div>

        <div class="card">
            <h2>📋 Все открытые порты</h2>
            <table>
                <thead>
                    <tr>
                        <th>Хост</th>
                        <th>Порт</th>
                        <th>Сервис</th>
                        <th>Версия</th>
                        <th>Время отклика</th>
                        <th>Статус</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Results}}
                    <tr>
                        <td>{{.Host}}</td>
                        <td><strong>{{.Port}}</strong></td>
                        <td>{{.Service}}</td>
                        <td>{{if .Version}}{{.Version}}{{else}}—{{end}}</td>
                        <td>{{printf "%.2f" .Duration}} мс</td>
                        <td>
                            {{if .Risk}}
                                <span class="badge critical">Проблема</span>
                            {{else if .SSL}}
                                <span class="badge success">SSL OK</span>
                            {{else}}
                                <span class="badge info">OK</span>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Сгенерировано Port Auditor — инструментом аудита сети на Go
        </div>
    </div>
</body>
</html>`
