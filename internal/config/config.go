package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Ports    []int         `yaml:"ports"`
	Timeouts TimeoutConfig `yaml:"timeouts"`
	Defaults DefaultConfig `yaml:"defaults"`
}

type TimeoutConfig struct {
	Dial  time.Duration `yaml:"dial"`
	Read  time.Duration `yaml:"read"`
	Total time.Duration `yaml:"total"`
}

type DefaultConfig struct {
	Workers int `yaml:"workers"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// DefaultFromBytes парсит конфиг из байтов (для embed)
func DefaultFromBytes(data []byte) *Config {
	if len(data) == 0 {
		return HardcodedDefault()
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return HardcodedDefault()
	}
	return cfg
}

// HardcodedDefault используется как fallback
func HardcodedDefault() *Config {
	return &Config{
		Ports: []int{22, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 11211},
		Timeouts: TimeoutConfig{
			Dial:  2 * time.Second,
			Read:  3 * time.Second,
			Total: 5 * time.Second,
		},
		Defaults: DefaultConfig{
			Workers: 100,
		},
	}
}
