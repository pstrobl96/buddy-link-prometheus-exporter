package config

import (
	"os"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// Config struct for the configuration file prusa.yml
type Config struct {
	Exporter struct {
		ScrapeTimeout int    `yaml:"scrape_timeout"`
		LogLevel      string `yaml:"log_level"`
		RemoteWrite   struct {
			Enabled  bool   `yaml:"enabled"`
			Format   string `yaml:"format"`
			Endpoint string `yaml:"endpoint"`
		} `yaml:"remote_write"`
		Prusalink struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"prusalink"`
		Syslog struct {
			Metrics struct {
				Enabled       bool   `yaml:"enabled"`
				ListenAddress string `yaml:"listen_address"`
			} `yaml:"metrics"`
			Logs struct {
				Enabled       bool   `yaml:"enabled"`
				ListenAddress string `yaml:"listen_address"`
				Directory     string `yaml:"directory"`
				Filename      string `yaml:"filename"`
				MaxSize       int    `yaml:"max_size"`
				MaxAge        int    `yaml:"max_age"`
				MaxBackups    int    `yaml:"max_backups"`
			} `yaml:"logs"`
		} `yaml:"syslog"`
	} `yaml:"exporter"`
	Printers []Printers `yaml:"printers"`
}

// Printers struct containing the printer configuration
type Printers struct {
	Address   string `yaml:"address"`
	Username  string `yaml:"username,omitempty"`
	Password  string `yaml:"password,omitempty"`
	Apikey    string `yaml:"apikey,omitempty"`
	Name      string `yaml:"name,omitempty"`
	Type      string `yaml:"type,omitempty"`
	Reachable bool
}

// LoadConfig function to load and parse the configuration file
func LoadConfig(path string) (Config, error) {
	var config Config
	file, err := os.ReadFile(path)

	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal(file, &config); err != nil {
		return config, err
	}

	return config, err
}

// GetLogLevel function to parse the log level for zerolog
func GetLogLevel(level string) zerolog.Level {
	switch level {
	case "info":
		return zerolog.InfoLevel
	case "debug":
		return zerolog.DebugLevel
	case "trace":
		return zerolog.TraceLevel
	case "error":
		return zerolog.ErrorLevel
	case "panic":
		return zerolog.PanicLevel
	case "fatal":
		return zerolog.FatalLevel
	default:
		return zerolog.InfoLevel
	}
}
