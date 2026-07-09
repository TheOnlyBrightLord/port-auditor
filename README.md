# 🔍 Port Auditor
![CI](https://github.com/TheOnlyBrightLord/port-auditor/actions/workflows/ci.yml/badge.svg)

Сетевой сканер и аудитор безопасности, написанный на Go. Автоматически обнаруживает открытые порты, определяет сервисы, проверяет SSL-сертификаты и генерирует красивые отчёты.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Возможности

- 🔎 **TCP-сканирование портов** с Worker Pool (до 1000 параллельных подключений)
- 🎯 **Banner Grabbing** — автоматическое определение сервисов (MySQL, Redis, SSH, HTTP и др.)
- 🔒 **SSL/TLS аудит** — проверка сертификатов, протоколов и сроков действия
- 🚨 **Security scoring** — автоматическое выявление критических проблем
- 📊 **HTML-отчёты** — красивые отчёты для presentations
- 📱 **Telegram-уведомления** — отправка алертов в мессенджер
- 🐳 **Docker support** — запуск в контейнере
- ⚡ **Высокая производительность** — использует горутины и конкурентность Go
- 🌐 **Web UI** — веб-интерфейс с real-time обновлениями через SSE
- 📜 **История сканирований** — сохранение и просмотр прошлых запусков
- 💾 **Экспорт отчётов** — скачивание результатов в JSON из браузера
- 📦 **Embed-конфигурация** — самодостаточный бинарник без внешних файлов

## 🌐 Web UI

Запустите веб-интерфейс одной командой:

```bash
port-auditor -web

## 🚀 Быстрый старт

### Установка из исходников

```bash
git clone https://github.com/TheOnlyBrightLord/port-auditor.git
cd port-auditor
make build
./build/port-auditor -target 192.168.1.0/24
