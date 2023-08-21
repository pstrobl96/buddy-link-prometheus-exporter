package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

var config configuration

type configuration struct {
	Printers struct {
		Buddy []struct {
			Address   string `yaml:"address"`
			Name      string `yaml:"name"`
			Type      string `yaml:"type"`
			Username  string `yaml:"username,omitempty"`
			Pass      string `yaml:"pass,omitempty"`
			Apikey    string `yaml:"apikey,omitempty"`
			Reachable bool
		} `yaml:"buddy"`
		Einsy []struct {
			Address   string `yaml:"address"`
			Apikey    string `yaml:"apikey"`
			Name      string `yaml:"name"`
			Type      string `yaml:"type"`
			Reachable bool
		} `yaml:"einsy"`
	} `yaml:"printers"`
	Exporter struct {
		MetricsPort   int    `yaml:"metrics_port"`
		ScrapeTimeout int    `yaml:"scrape_timeout"`
		ReloadInteval int    `yaml:"reload_inteval"`
		LogLevel      string `yaml:"log_level"`
	} `yaml:"exporter"`
}

func setLogLevel(level string) string {
	if level == "" {
		level = "info"
	}

	level = strings.ToLower(level)
	var zeroLogLevel zerolog.Level

	switch level {
	case "info":
		zeroLogLevel = zerolog.InfoLevel
	case "debug":
		zeroLogLevel = zerolog.DebugLevel
	case "trace":
		zeroLogLevel = zerolog.TraceLevel
	case "error":
		zeroLogLevel = zerolog.ErrorLevel		
	case "panic":
		zeroLogLevel = zerolog.PanicLevel
	case "fatal":
		zeroLogLevel = zerolog.FatalLevel
	default:
		zeroLogLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zeroLogLevel)

	return level
}

func loadConfigFile() {
	config = probeConfigFile(parseConfig(getConfigPath()))	
}

func getConfigPath() string {
	cfgFile := os.Getenv("BUDDY_EXPORTER_CONFIG")
	if cfgFile == "" {
		pwd, e := os.Getwd()
		if e != nil {
			fmt.Println(e)
			os.Exit(1)
		}
		cfgFile = pwd + "/buddy.yaml"
	}

	return cfgFile
}

func parseConfig(path string) configuration {
	f, e := os.ReadFile(path)
	if e != nil {
		log.Error().Msg(e.Error())
	}
	var p configuration
	if e := yaml.Unmarshal(f, &p); e != nil {
		log.Error().Msg(e.Error())
	}
	return p
}

func probeConfigFile(parsedConfig configuration) configuration {
	for _, s := range parsedConfig.Printers.Buddy {
		if head(s.Address) {
			s.Reachable = true
		} else {
			s.Reachable = false
			log.Error().Msg(s.Address + " is not reachable")
		}
	}
	return parsedConfig
}

// func testConnection(s string) (bool, error) {
// 	r, e := http.Head(s)
// 	return r.StatusCode == 200, e
// }

func configReloader() {
    ticker := time.NewTicker(1 * time.Second)

	for t := range ticker.C {
		log.Info().Msg(fmt.Sprintf("Tick at: %v\n", t.UTC()))
		loadConfigFile()
	}
	//defer t.Stop()
	//for {
	//	select {
	//	case <-t.C: // Activate periodically
	//		loadConfigFile()
	//		log.Debug().Msg("Config reloaded")
	//	}
	//}
}
