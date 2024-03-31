package cmd

import (
	"net/http"
	"os"
	"strconv"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pstrobl96/prusa_exporter/config"
	"github.com/pstrobl96/prusa_exporter/prusalink"
	"github.com/pstrobl96/prusa_exporter/syslog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configFile  = kingpin.Flag("config.file", "Configuration file for prusa_exporter.").Default("./prusa.yml").ExistingFile()
	metricsPath = kingpin.Flag("exporter.metrics-path", "Path where to expose metrics.").Default("/metrics").String()
	metricsPort = kingpin.Flag("exporter.metrics-port", "Port where to expose metrics.").Default("10009").Int()
	syslogTTL   = kingpin.Flag("syslog.ttl", "TTL for syslog metrics in seconds.").Default("60").Int()
)

// Run function to start the exporter
func Run() {
	kingpin.Parse()
	log.Info().Msg("Prusa exporter starting")
	log.Info().Msg("Loading configuration file: " + *configFile)

	config, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Error().Msg("Error loading configuration file " + err.Error())
		os.Exit(1)
	}

	logLevel, err := zerolog.ParseLevel(config.Exporter.LogLevel)

	if err != nil {
		logLevel = zerolog.InfoLevel // default log level
	}
	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixNano

	config, err = probeConfigFile(config)

	if err != nil {
		log.Error().Msg("Error probing configuration file " + err.Error())
		os.Exit(1)
	}
	var collectors []prometheus.Collector

	if config.Exporter.Prusalink.Enabled {
		log.Info().Msg("PrusaLink metrics enabled!")
		collectors = append(collectors, prusalink.NewCollector(config))
	}

	if config.Exporter.Syslog.Metrics.Enabled {
		log.Info().Msg("Syslog metrics enabled!")
		log.Info().Msg("Syslog metrics server starting at: " + config.Exporter.Syslog.Metrics.ListenAddress)
		go syslog.HandleMetrics(config.Exporter.Syslog.Metrics.ListenAddress)
		collectors = append(collectors, syslog.NewCollector(*syslogTTL, config.Exporter.RemoteWrite.Format, config.Exporter.RemoteWrite.Endpoint))
	}

	if config.Exporter.Syslog.Logs.Enabled {
		log.Info().Msg("Syslog logs enabled!")
		log.Info().Msg("Syslog logs server starting at: " + config.Exporter.Syslog.Logs.ListenAddress)
		go syslog.HandleLogs(config.Exporter.Syslog.Logs.ListenAddress,
			config.Exporter.Syslog.Logs.Directory,
			config.Exporter.Syslog.Logs.Filename,
			config.Exporter.Syslog.Logs.MaxSize,
			config.Exporter.Syslog.Logs.MaxBackups,
			config.Exporter.Syslog.Logs.MaxAge)
	}

	if len(collectors) == 0 && !config.Exporter.Syslog.Logs.Enabled {
		log.Error().Msg("No collectors or logs registered")
		os.Exit(1)
	}

	prometheus.MustRegister(collectors...)
	log.Info().Msg("Metrics registered")
	http.Handle(*metricsPath, promhttp.Handler())
	log.Info().Msg("Listening at port: " + strconv.Itoa(*metricsPort))
	log.Fatal().Msg(http.ListenAndServe(":"+strconv.Itoa(*metricsPort), nil).Error())

}

func probeConfigFile(config config.Config) (config.Config, error) {
	for i, printer := range config.Printers {
		status, err := prusalink.ProbePrinter(printer)
		if err != nil {
			log.Error().Msg(err.Error())
		} else if status {

			printerType, err := prusalink.GetPrinterType(printer)

			if err != nil {
				log.Error().Msg(err.Error())
			}

			config.Printers[i].Type = printerType
		}
	}
	return config, nil
}
